//! Best-effort user-mode stackwalk for dump sessions.
//!
//! Prefer frame-pointer chains (RBP/EBP) when available; fall back to a
//! conservative RSP scan of return-address candidates that land in modules.
//! Frames report `module+offset` and a confidence/reason for incomplete walks.

use serde::Serialize;

use super::{DumpModule, DumpThread, LoadedDump, ReadStatus};

const MAX_FRAMES_HARD: usize = 256;
const MAX_SCAN_SLOTS: usize = 4096;

#[derive(Clone, Debug, Serialize)]
pub struct StackFrame {
    pub index: usize,
    pub ip: String,
    pub sp: Option<String>,
    pub module: Option<String>,
    pub module_base: Option<String>,
    pub offset: Option<String>,
    /// `fp_chain` | `sp_scan` | `thread_context`
    pub method: String,
    pub confidence: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ThreadStack {
    pub thread_id: u32,
    pub frames: Vec<StackFrame>,
    /// Why the walk stopped: `depth_cap` | `broken_fp` | `missing_memory` | `no_context` | `done`
    pub died: String,
    pub is_exception_thread: bool,
}

impl LoadedDump {
    /// Walk `thread_id` (or the exception thread, or first with IP).
    pub fn walk_thread_stack(
        &self,
        thread_id: Option<u32>,
        max_frames: usize,
    ) -> ThreadStack {
        let max_frames = max_frames.clamp(1, MAX_FRAMES_HARD);
        let thread = select_thread(self, thread_id);
        let Some(thread) = thread else {
            return ThreadStack {
                thread_id: thread_id.unwrap_or(0),
                frames: Vec::new(),
                died: "no_context".into(),
                is_exception_thread: false,
            };
        };

        let mut frames = Vec::new();

        // Frame 0: thread context IP.
        if let Some(ip) = thread.instruction_pointer {
            frames.push(frame_for_ip(self, 0, ip, thread.stack_pointer, "thread_context", "high"));
        } else {
            return ThreadStack {
                thread_id: thread.thread_id,
                frames,
                died: "no_context".into(),
                is_exception_thread: thread.is_exception_thread,
            };
        }

        // Prefer FP chain when RBP looks sane.
        if let (Some(fp), Some(sp)) = (thread.frame_pointer, thread.stack_pointer) {
            if fp >= sp && looks_like_stack_ptr(self, fp) {
                let (more, reason) = walk_fp_chain(self, fp, max_frames.saturating_sub(1));
                for (i, f) in more.into_iter().enumerate() {
                    frames.push(StackFrame {
                        index: i + 1,
                        ..f
                    });
                }
                return ThreadStack {
                    thread_id: thread.thread_id,
                    frames,
                    died: reason,
                    is_exception_thread: thread.is_exception_thread,
                };
            }
        }

        // RSP scan fallback.
        let died = if let Some(sp) = thread.stack_pointer {
            let (more, reason) = walk_sp_scan(self, sp, max_frames.saturating_sub(1));
            for (i, f) in more.into_iter().enumerate() {
                frames.push(StackFrame {
                    index: i + 1,
                    ..f
                });
            }
            reason
        } else {
            "missing_memory".into()
        };

        ThreadStack {
            thread_id: thread.thread_id,
            frames,
            died,
            is_exception_thread: thread.is_exception_thread,
        }
    }
}

fn select_thread(dump: &LoadedDump, thread_id: Option<u32>) -> Option<&DumpThread> {
    if let Some(tid) = thread_id {
        return dump.threads.iter().find(|t| t.thread_id == tid);
    }
    if let Some(exc) = &dump.exception {
        if let Some(t) = dump.threads.iter().find(|t| t.thread_id == exc.thread_id) {
            return Some(t);
        }
    }
    dump.threads
        .iter()
        .find(|t| t.is_exception_thread)
        .or_else(|| dump.threads.iter().find(|t| t.instruction_pointer.is_some()))
        .or_else(|| dump.threads.first())
}

fn walk_fp_chain(
    dump: &LoadedDump,
    mut fp: u64,
    max_more: usize,
) -> (Vec<StackFrame>, String) {
    let mut frames = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let ptr_size = if dump.system.bitness == 32 { 4usize } else { 8usize };

    for _ in 0..max_more {
        if !seen.insert(fp) {
            return (frames, "broken_fp".into());
        }
        // [fp] = saved_fp, [fp+ptr] = return address
        let Some(saved_fp) = read_ptr(dump, fp, ptr_size) else {
            return (frames, "missing_memory".into());
        };
        let Some(ret) = read_ptr(dump, fp.saturating_add(ptr_size as u64), ptr_size) else {
            return (frames, "missing_memory".into());
        };
        if ret == 0 {
            return (frames, "done".into());
        }
        // Return address points at instruction after call; keep as-is for module resolve.
        frames.push(frame_for_ip(
            dump,
            frames.len(),
            ret,
            Some(fp.saturating_add((ptr_size * 2) as u64)),
            "fp_chain",
            if dump.module_at(ret).is_some() {
                "high"
            } else {
                "medium"
            },
        ));
        if saved_fp <= fp || !looks_like_stack_ptr(dump, saved_fp) {
            return (frames, "broken_fp".into());
        }
        fp = saved_fp;
    }
    (frames, "depth_cap".into())
}

fn walk_sp_scan(
    dump: &LoadedDump,
    sp: u64,
    max_more: usize,
) -> (Vec<StackFrame>, String) {
    let mut frames = Vec::new();
    let ptr_size = if dump.system.bitness == 32 { 4usize } else { 8usize };
    let mut slots = 0usize;
    let mut addr = sp;

    while frames.len() < max_more && slots < MAX_SCAN_SLOTS {
        slots += 1;
        let Some(val) = read_ptr(dump, addr, ptr_size) else {
            // Skip unmapped holes up to a point.
            addr = addr.saturating_add(ptr_size as u64);
            continue;
        };
        addr = addr.saturating_add(ptr_size as u64);
        if val < 0x10000 {
            continue;
        }
        if dump.module_at(val).is_none() {
            continue;
        }
        // Dedup consecutive identical candidates.
        let ip_s = format!("{val:#x}");
        if frames.last().is_some_and(|f: &StackFrame| f.ip == ip_s) {
            continue;
        }
        frames.push(frame_for_ip(
            dump,
            frames.len(),
            val,
            Some(addr),
            "sp_scan",
            "low",
        ));
    }

    let died = if frames.len() >= max_more {
        "depth_cap"
    } else {
        "done"
    };
    (frames, died.into())
}

fn read_ptr(dump: &LoadedDump, va: u64, ptr_size: usize) -> Option<u64> {
    match dump.read_at(va, ptr_size) {
        ReadStatus::Ok(b) | ReadStatus::Partial(b) if b.len() >= ptr_size => {
            let mut buf = [0u8; 8];
            buf[..ptr_size].copy_from_slice(&b[..ptr_size]);
            Some(if ptr_size == 4 {
                u32::from_le_bytes(buf[..4].try_into().ok()?) as u64
            } else {
                u64::from_le_bytes(buf)
            })
        }
        _ => None,
    }
}

fn looks_like_stack_ptr(dump: &LoadedDump, va: u64) -> bool {
    // Stack pointers should be readable and typically in high user space on x64.
    matches!(dump.read_at(va, 8), ReadStatus::Ok(_) | ReadStatus::Partial(_))
}

fn frame_for_ip(
    dump: &LoadedDump,
    index: usize,
    ip: u64,
    sp: Option<u64>,
    method: &str,
    confidence: &str,
) -> StackFrame {
    let module = dump.module_at(ip);
    StackFrame {
        index,
        ip: format!("{ip:#x}"),
        sp: sp.map(|v| format!("{v:#x}")),
        module: module.map(|m: &DumpModule| m.name.clone()),
        module_base: module.map(|m| format!("{:#x}", m.base)),
        offset: module.map(|m| format!("{:#x}", ip.saturating_sub(m.base))),
        method: method.into(),
        confidence: confidence.into(),
    }
}
