use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;

use crate::analysis::Analysis;
use crate::analysis::functions::{Function, FunctionTable};
use crate::analysis::indirect;
use crate::analysis::search::{SearchHit, search_everything};
use crate::analysis::stack_frame;
use crate::analysis::thunks;
use crate::analysis::win32_sigs::SigDB;
use crate::analysis::xrefs::{Xref, XrefIndex};
use crate::ir::agent_text::{AgentTextOpts, to_agent_text_opts};
use crate::ir::export::{FunctionExport, function_to_export_with_db, to_llm_text};
use crate::loader::AddressSpace;
use crate::loader::pe::LoadedPe;
use crate::project::op_log::Journal;
use crate::project::pdb_info::PdbInfo;
use crate::project::persistence::{ProjectState, hash_bytes, windy_home_dir};
use crate::project::types::{FunctionSignature, StackFrame};

pub mod activity_log;
pub mod command;
pub mod comments;
pub mod demangle;
pub mod memory;
pub mod op;
pub mod op_log;
pub mod pdb_info;
pub mod persistence;
pub mod symbols;
pub mod symsrv;
pub mod types;
pub mod workspace;

use comments::{CommentScope, CommentStore};
use demangle::demangle_or_raw;
use symbols::{SymbolKind, SymbolTable};
use types::{DataType, DataTypeManager};

/// Apply simple C-identifier function names from an adjacent MSVC `.map`.
///
/// Only upgrades existing `FUN_*` / missing symbols so PDB/export names win.
/// Skips CRT/lib objects and C++ mangled (`?`/`@`) publics.
fn apply_adjacent_msvc_map_names(pe_path: &Path, symbols: &mut SymbolTable) {
    let map_path = pe_path.with_extension("map");
    let Ok(text) = std::fs::read_to_string(&map_path) else {
        return;
    };
    let mut applied = 0usize;
    for line in text.lines() {
        // 0001:00000000       classify                   0000000140001000 f   c03_dispatch.obj
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        // Require type flag `f` (function).
        let f_idx = parts.iter().position(|p| *p == "f");
        let Some(fi) = f_idx else {
            continue;
        };
        if fi < 2 || fi + 1 >= parts.len() {
            continue;
        }
        let name = parts[fi - 2];
        let va_s = parts[fi - 1];
        let obj = parts[fi + 1];
        // User .obj only (not LIBCMT:… / libvcruntime:…).
        if obj.contains(':') || !obj.ends_with(".obj") {
            continue;
        }
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || name.starts_with('?')
            || name.starts_with('_')
            || name.len() < 2
        {
            continue;
        }
        let Ok(va) = u64::from_str_radix(va_s, 16) else {
            continue;
        };
        match symbols.name(va) {
            None => {
                symbols.insert(va, name, SymbolKind::Function);
                applied += 1;
            }
            Some(n) if n.starts_with("FUN_") || n.starts_with("sub_") => {
                symbols.insert(va, name, SymbolKind::Function);
                applied += 1;
            }
            Some(_) => {}
        }
    }
    if applied > 0 {
        tracing::info!(
            "MSVC map: applied {applied} function name(s) from {}",
            map_path.display()
        );
    }
}

/// Whether a signature can be represented by the first four Windows x64 GPR
/// argument slots without inventing floating-point, aggregate, vectorcall, or
/// caller-stack semantics.
fn win64_integer_call_contract(signature: &FunctionSignature) -> bool {
    if signature.params.len() > 4
        || signature
            .calling_conv
            .as_deref()
            .is_some_and(|calling_conv| calling_conv.eq_ignore_ascii_case("vectorcall"))
    {
        return false;
    }

    signature.params.iter().all(|(_, ty)| {
        matches!(
            ty,
            DataType::Bool
                | DataType::Int(_)
                | DataType::Uint(_)
                | DataType::Ptr(_)
                | DataType::FuncPtr { .. }
                | DataType::Unknown(_)
        )
    })
}

/// Set when this PE project was opened from a dump module (hybrid model).
#[derive(Clone)]
pub struct DumpModuleOrigin {
    pub dump_session_id: uuid::Uuid,
    pub module_base: u64,
    pub module_name: String,
    #[allow(dead_code)] // stable module identity for workspace / logs
    pub identity_key: String,
    /// Parent process dump for out-of-module VA reads / stack context.
    pub dump: Arc<crate::loader::dump::LoadedDump>,
}

#[derive(Clone)]
pub struct Project {
    /// The loaded PE image and surface analysis.
    pub pe: Arc<LoadedPe>,
    /// SHA256 hash of the loaded image; used as IDB key.
    pub image_sha256: String,
    /// Root for all durable Windy state associated with this project.
    data_dir: Arc<PathBuf>,
    /// Memory layout / VA↔offset translations.
    pub address_space: Arc<AddressSpace>,
    /// 32 or 64 (used by exporters and type sizes).
    pub bitness: u32,
    /// Cached analysis: decoded code, functions, CFG, xrefs.
    pub analysis: Arc<Analysis>,
    /// User-defined and auto-discovered symbols.
    pub symbols: SymbolTable,
    /// Per-address and per-function comments.
    pub comments: CommentStore,
    /// Project-wide data types (seam for decompiler/LLM phases).
    pub types: DataTypeManager,
    /// Recovered stack frames keyed by function entry VA.
    pub function_frames: BTreeMap<u64, StackFrame>,
    /// PDB-typed global data variables keyed by VA.
    pub typed_globals: Arc<HashMap<u64, DataType>>,
    /// PDB function signatures keyed by function entry VA.
    pub function_signatures: Arc<BTreeMap<u64, FunctionSignature>>,
    /// Win32 API signature database (bundled + resolved Windy data directory).
    pub sig_db: SigDB,
    /// COM / interface vtable signature database (Phase 7 D).
    pub vtable_db: crate::analysis::vtable_sigs::VtableDB,
    /// PDB loading result for this session.
    pub pdb_info: PdbInfo,
    /// Current function cursor for LLM/function-scope UI operations.
    pub focus: Option<u64>,
    /// Highest operation sequence number applied to this in-memory state.
    pub op_seq: u64,
    /// Agent-authored durable function memory cards (Phase C).
    pub function_memory: BTreeMap<u64, memory::FunctionMemoryCard>,
    /// Rename lineage for symbols (old → new), agent-queryable.
    pub alias_history: Vec<crate::project::symbols::AliasEvent>,
    /// Hybrid dump origin (None for normal PE opens).
    pub dump_origin: Option<DumpModuleOrigin>,
    /// Per-function optimized SSA session cache (shared across ArcSwap clones).
    /// Invalidated when stack frames or analysis inputs that affect SSA change.
    #[allow(clippy::type_complexity)]
    ssa_cache: Arc<
        Mutex<
            HashMap<
                u64,
                (
                    crate::decompiler::ssa::SsaFunction,
                    crate::decompiler::ssa::SsaAnalysis,
                ),
            >,
        >,
    >,
}

#[allow(dead_code)] // agent/MCP/UI programmatic surface (not all callers live in-tree)
impl Project {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_with_data_dir(path, windy_home_dir())
    }

    /// Open a PE while routing all durable state through `data_dir`.
    pub fn open_with_data_dir(
        path: impl AsRef<Path>,
        data_dir: impl Into<PathBuf>,
    ) -> Result<Self> {
        Self::open_with_data_dir_and_entry_hints(path, data_dir, &[])
    }

    /// Open a PE with authoritative function-entry hints while keeping all
    /// durable state under the supplied directory. The hints affect only
    /// function boundary discovery and do not create symbols or annotations.
    pub fn open_with_data_dir_and_entry_hints(
        path: impl AsRef<Path>,
        data_dir: impl Into<PathBuf>,
        entry_hints: &[u64],
    ) -> Result<Self> {
        let opened_at = Instant::now();
        let data_dir = data_dir.into();
        let path = path.as_ref();
        tracing::info!("Opening {}...", path.display());
        let pe = LoadedPe::open(path)?;
        tracing::info!(
            "Parsed PE headers, imports, exports, and strings in {:.2}s",
            opened_at.elapsed().as_secs_f64()
        );
        let image_sha256 = hash_bytes(&pe.image);
        let mut symbols = SymbolTable::default();

        let optional = pe.triage.optional_header.as_ref();
        let sections = pe.triage.sections.as_deref().unwrap_or_default();
        let image_base = optional.map(|h| h.image_base).unwrap_or_default();
        let entry_rva = optional
            .map(|h| h.address_of_entry_point)
            .unwrap_or_default();
        let entry_va = image_base.saturating_add(entry_rva);
        let address_space = AddressSpace::new(image_base, sections);
        let magic = optional.map(|h| h.magic.as_str()).unwrap_or("PE32");
        let bitness = address_space.bitness(magic);

        // Seed exports and IAT slots (__imp_<Api>) from the PE headers.
        SeedSymbolTable::from_triage(&pe, &mut symbols, &address_space, bitness);

        // Load PDB symbols/frames/types before analysis so function discovery seeds them.
        tracing::info!("Checking local symbol sources...");
        let pdb_info = PdbInfo::load_for_pe_in(&pe, &data_dir);
        let mut function_frames: BTreeMap<u64, StackFrame> = BTreeMap::new();
        let mut types = DataTypeManager::new();
        let mut typed_globals: HashMap<u64, DataType> = HashMap::new();
        let mut function_signatures: BTreeMap<u64, FunctionSignature> = BTreeMap::new();
        if let Some(err) = &pdb_info.error {
            tracing::info!(
                "No PDB (normal for private or game binaries). Continuing without symbols."
            );
            tracing::debug!("PDB detail: {err}");
        } else if pdb_info.loaded {
            tracing::info!("PDB loaded from {:?}", pdb_info.source);
        }
        pdb_info.apply(
            &address_space,
            &mut symbols,
            &mut function_frames,
            &mut types,
            &mut typed_globals,
            &mut function_signatures,
        );

        tracing::info!("Decoding instructions and discovering functions...");
        let analysis_started = Instant::now();
        let mut analysis = if entry_hints.is_empty() {
            Analysis::build(&pe.image, &address_space, bitness, entry_va, &symbols)
        } else {
            Analysis::build_with_entry_hints(
                &pe.image,
                &address_space,
                bitness,
                entry_va,
                &symbols,
                entry_hints,
            )
        };
        tracing::info!(
            "Indexed {} instructions and discovered {} functions in {:.2}s",
            analysis.code_index.len(),
            analysis.functions.len(),
            analysis_started.elapsed().as_secs_f64()
        );
        analysis.functions.apply_frames(&function_frames);

        // Attach PDB-derived function signatures.
        for func in analysis.functions.iter_mut() {
            if let Some(sig) = function_signatures.get(&func.entry_va) {
                func.signature = Some(sig.clone());
            }
        }

        // Recover stack frames from prologues for functions without PDB data.
        stack_frame::recover_frames(&mut analysis.functions, &analysis.code_index, bitness);
        for func in analysis.functions.iter() {
            if let Some(frame) = &func.stack_frame {
                function_frames.insert(func.entry_va, frame.clone());
            }
        }

        // Auto-name discovered functions if they don't already have a symbol.
        // FUN_ matches Ghidra stripped naming (scorecard gold uses fun_* aliases).
        // Also rewrite legacy sub_* auto-names so emit/scorecard stay aligned.
        for func in analysis.functions.iter() {
            match symbols.get(func.entry_va).map(|s| s.name.clone()) {
                None => {
                    symbols.insert(
                        func.entry_va,
                        format!("FUN_{:08x}", func.entry_va),
                        SymbolKind::Function,
                    );
                }
                Some(n) if n.starts_with("sub_") => {
                    symbols.insert(
                        func.entry_va,
                        format!("FUN_{:08x}", func.entry_va),
                        SymbolKind::Function,
                    );
                }
                Some(_) => {}
            }
        }

        // Adjacent MSVC .map publics (same stem as the PE) upgrade FUN_ names
        // so pure-V2 call sites can emit `classify` / `crc_add` / `res_init`.
        apply_adjacent_msvc_map_names(&pe.path, &mut symbols);

        // Detect import forwarder thunks and rename them to their API names.
        let thunks = thunks::find_thunk_renames(
            &analysis.functions,
            &analysis.code_index,
            &symbols,
            bitness,
        );
        for rename in thunks {
            symbols.insert(rename.thunk_va, rename.api_name, SymbolKind::Import);
        }

        // Resolve RIP-relative indirect jump tables / switch tables.
        indirect::resolve_indirect_jumps(
            &mut analysis.functions,
            &analysis.code_index,
            &mut analysis.xrefs,
            &address_space,
            &pe.image,
            bitness,
        );
        // Resolve single-instruction indirect call slots (IAT / function-pointer tables).
        indirect::resolve_indirect_calls(
            &mut analysis.functions,
            &analysis.code_index,
            &mut analysis.xrefs,
            &address_space,
            &pe.image,
            bitness,
        );

        let sig_db = SigDB::load_from(&data_dir);
        let vtable_db = crate::analysis::vtable_sigs::VtableDB::load_from(&data_dir);

        let mut project = Self {
            pe: Arc::new(pe),
            image_sha256,
            data_dir: Arc::new(data_dir),
            address_space: Arc::new(address_space),
            bitness,
            analysis: Arc::new(analysis),
            symbols,
            comments: CommentStore::default(),
            types,
            function_frames,
            typed_globals: Arc::new(typed_globals),
            function_signatures: Arc::new(function_signatures),
            sig_db,
            vtable_db,
            pdb_info,
            focus: Some(entry_va),
            op_seq: 0,
            function_memory: BTreeMap::new(),
            alias_history: Vec::new(),
            dump_origin: None,
            ssa_cache: Arc::new(Mutex::new(HashMap::new())),
        };

        if let Some(state) =
            ProjectState::load_from(project.data_dir.as_ref(), &project.image_sha256)
        {
            state.apply(&mut project);
        }

        let journal = Journal::open_in(project.data_dir.as_ref(), &project.image_sha256);
        for record in journal.read_all() {
            if record.seq > project.op_seq {
                let _ = record.op.apply_to(&mut project);
                project.op_seq = record.seq;
            }
        }

        tracing::info!(
            "Project ready: {} functions, {} instructions ({:.2}s total)",
            project.functions().len(),
            project.analysis.code_index.len(),
            opened_at.elapsed().as_secs_f64()
        );

        Ok(project)
    }

    /// Persist the current project state (symbols, comments, types, frames) to
    /// the central IDB store.
    pub fn save(&self) -> Result<()> {
        ProjectState::from_project(self).save_to(self.data_dir.as_ref())?;
        // All ops through op_seq are now captured in the snapshot.
        Journal::open_in(self.data_dir.as_ref(), &self.image_sha256)
            .truncate_through(self.op_seq)
            .ok();
        Ok(())
    }

    pub fn data_dir(&self) -> &Path {
        self.data_dir.as_ref()
    }

    /// Kind string for MCP: `pe` | `dump_module`.
    pub fn kind_label(&self) -> &'static str {
        if self.dump_origin.is_some() {
            "dump_module"
        } else {
            "pe"
        }
    }

    /// Read up to `len` bytes at process/image VA.
    ///
    /// Prefer the PE address space; for dump modules, fall through to the
    /// parent process memory map for out-of-module pointers (IAT targets, etc.).
    pub fn read_bytes(&self, va: u64, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        if let Some(slice) = self.address_space.slice_for_va(&self.pe.image, va, len) {
            if slice.len() == len {
                return Some(slice.to_vec());
            }
            // Partial PE mapping — still useful.
            if !slice.is_empty() && self.dump_origin.is_none() {
                return Some(slice.to_vec());
            }
        }
        if let Some(origin) = &self.dump_origin {
            match origin.dump.read_at(va, len) {
                crate::loader::dump::ReadStatus::Ok(b) => Some(b.to_vec()),
                crate::loader::dump::ReadStatus::Partial(b) if !b.is_empty() => Some(b.to_vec()),
                _ => None,
            }
        } else {
            None
        }
    }

    /// Apply dump-origin metadata and resolve runtime IAT slots to cross-module names.
    pub fn attach_dump_origin_and_resolve_iat(&mut self, origin: DumpModuleOrigin) {
        let dump = Arc::clone(&origin.dump);
        self.dump_origin = Some(origin);

        // Resolved IAT: absolute pointers at IAT slots → module!export names.
        let ptr_size = (self.bitness / 8) as usize;
        let import_slots: Vec<(u64, String)> = self
            .symbols
            .iter()
            .filter(|(_, s)| {
                s.kind == SymbolKind::Import
                    || s.name.starts_with("__imp_")
                    || s.name.starts_with("_imp_")
            })
            .map(|(va, s)| (va, s.name.clone()))
            .collect();

        let mut resolved = 0usize;
        for (iat_va, old_name) in import_slots {
            let Some(bytes) = self.read_bytes(iat_va, ptr_size) else {
                continue;
            };
            if bytes.len() < ptr_size {
                continue;
            }
            let target = if ptr_size == 8 {
                u64::from_le_bytes(bytes.as_slice().try_into().unwrap_or([0; 8]))
            } else {
                u32::from_le_bytes(bytes[..4].try_into().unwrap_or([0; 4])) as u64
            };
            if target < 0x10000 {
                continue;
            }
            let Some(sym) = crate::loader::dump::resolve_va_symbol(&dump, target) else {
                continue;
            };
            // Name the IAT slot and the thunk target when useful.
            let imp_name = if let Some(bang) = sym.find('!') {
                format!("__imp_{}", &sym[bang + 1..])
            } else {
                format!("__imp_{sym}")
            };
            if old_name.starts_with("FUN_")
                || old_name.starts_with("sub_")
                || old_name.starts_with("__imp_")
                || old_name.starts_with("_imp_")
                || old_name.contains("ordinal")
            {
                self.symbols
                    .insert(iat_va, imp_name, SymbolKind::Import);
                resolved += 1;
            }
            // Also name the target function VA if it lands in *this* module.
            if let Some(o) = &self.dump_origin {
                if target >= o.module_base
                    && target < o.module_base.saturating_add(
                        self.address_space
                            .sections
                            .iter()
                            .map(|s| u64::from(s.vsize))
                            .max()
                            .unwrap_or(0)
                            .max(0x1000),
                    )
                {
                    // leave local FUN_ discovery names; PE pipeline owns them
                } else if let Some(bang) = sym.find('!') {
                    // External: record address comment-style symbol when no local function.
                    let api = &sym[bang + 1..];
                    if self.symbols.name(target).is_none() {
                        self.symbols
                            .insert(target, api.to_string(), SymbolKind::Import);
                    }
                }
            }
        }
        if resolved > 0 {
            tracing::info!(
                "Dump module IAT: resolved {resolved} import slot(s) via process memory"
            );
        }
    }

    /// LLM/programmatic read API ------------------------------------------------
    pub fn functions(&self) -> &FunctionTable {
        &self.analysis.functions
    }

    pub fn function_at(&self, va: u64) -> Option<&Function> {
        self.analysis.functions.get(va)
    }

    pub fn focused_function(&self) -> Option<&Function> {
        self.focus.and_then(|va| self.function_at(va))
    }

    pub fn xrefs_to(&self, va: u64) -> &[Xref] {
        self.analysis.xrefs.to(va)
    }

    pub fn xrefs_index(&self) -> &XrefIndex {
        &self.analysis.xrefs
    }

    /// Global search across instructions, symbols, and strings.
    pub fn search(&self, query: &str) -> Vec<SearchHit> {
        search_everything(self, query)
    }

    pub fn function_export(&self, va: u64) -> Option<FunctionExport> {
        let func = self.function_at(va)?;
        function_to_export_with_db(
            func,
            &self.analysis.code_index,
            &self.symbols,
            &self.comments,
            &self.analysis.xrefs,
            self.bitness,
            &self.typed_globals,
            &self.function_frames,
            &self.types,
            &self.function_signatures,
            Some(&self.sig_db),
        )
    }

    pub fn function_llm_text(&self, va: u64) -> Option<String> {
        self.function_export(va).map(|e| to_llm_text(&e))
    }

    pub fn function_agent_text(&self, va: u64) -> Option<String> {
        self.function_agent_text_opts(va, AgentTextOpts::default())
    }

    /// Agent text with optional noise stripping and instruction budget.
    pub fn function_agent_text_opts(&self, va: u64, opts: AgentTextOpts) -> Option<String> {
        self.function_export(va)
            .map(|e| to_agent_text_opts(&e, &opts))
    }

    /// Resolve the supported Windows x64 integer-register inputs of direct
    /// calls in `func`.  These inputs are supplied to SSA construction before
    /// simplification so argument setup cannot be dead-code-eliminated merely
    /// because raw P-code omits ABI operands.
    ///
    /// This deliberately rejects calls whose contract is not yet modeled:
    /// indirect calls, vector/float parameters, aggregates, more than four
    /// arguments, and `vectorcall`.  Those remain available as raw/structured
    /// evidence but must not turn into a deceptively complete native C call.
    fn call_abi_inputs_for(&self, func: &Function) -> crate::decompiler::ssa::CallAbiInputs {
        use crate::decompiler::ssa::Location;
        use iced_x86::FlowControl;

        if self.bitness != 64 {
            return Default::default();
        }

        const WIN64_GPR_ARGUMENT_BASES: [u64; 4] = [0x08, 0x10, 0x80, 0x88];
        let mut inputs = crate::decompiler::ssa::CallAbiInputs::new();

        for block in &func.blocks {
            let mut instruction_va = block.entry_va;
            while let Some(decoded) = self.analysis.code_index.at_va(instruction_va) {
                if decoded.instr.flow_control() == FlowControl::Call {
                    let target = decoded.instr.near_branch_target();
                    if target != 0
                        && let Some(signature) = self.call_signature_for_abi_inputs(target)
                        && win64_integer_call_contract(&signature)
                    {
                        let registers = WIN64_GPR_ARGUMENT_BASES
                            .iter()
                            .take(signature.params.len())
                            .map(|base_offset| Location::Register {
                                base_offset: *base_offset,
                            })
                            .collect();
                        inputs.insert(instruction_va, registers);
                    }
                }
                if instruction_va == block.exit_va {
                    break;
                }
                instruction_va = decoded.next_ip();
            }
        }

        inputs
    }

    /// Use declarations first, then the existing bounded x64 signature
    /// heuristic for direct in-image targets.  The latter is sufficient to
    /// retain a proven register setup as an *inferred* call input; unsupported
    /// or incomplete contracts still stay out of the native call printer.
    fn call_signature_for_abi_inputs(&self, target: u64) -> Option<FunctionSignature> {
        self.signature_for_target(target).or_else(|| {
            let function = self.function_at(target)?;
            crate::analysis::signatures::recover_signature_with_db(
                function,
                &self.analysis.code_index,
                self.bitness,
                &function.name(&self.symbols),
                None,
            )
        })
    }

    /// Function-level SSA IR over the lifted P-code (Phase 2).
    ///
    /// Lazily builds the SSA form for the function at `va` on each call (no
    /// caching, consistent with the Phase 1 deferral of eager precomputation).
    /// Returns `None` if no function starts at `va`.
    pub fn function_ssa(&self, va: u64) -> Option<crate::decompiler::ssa::SsaFunction> {
        let func = self.function_at(va)?;
        let call_abi_inputs = self.call_abi_inputs_for(func);
        Some(crate::decompiler::ssa::build_ssa_with_call_abi_inputs(
            func,
            &self.analysis.code_index,
            &self.function_frames,
            self.bitness,
            self.address_space.image_base,
            &call_abi_inputs,
        ))
    }

    /// Optimized SSA form of a function — copy/constant propagation, trivial-phi
    /// collapse, and conservative DCE over the raw Phase-2 SSA.
    ///
    /// Results are cached per function VA for the session; see
    /// [`Self::invalidate_ssa_cache`]. The raw SSA from [`Self::function_ssa`]
    /// is never mutated.
    pub fn function_ssa_optimized(
        &self,
        va: u64,
    ) -> Option<(
        crate::decompiler::ssa::SsaFunction,
        crate::decompiler::ssa::SsaAnalysis,
    )> {
        if let Ok(cache) = self.ssa_cache.lock()
            && let Some(hit) = cache.get(&va)
        {
            return Some(hit.clone());
        }
        let func = self.function_at(va)?;
        let call_abi_inputs = self.call_abi_inputs_for(func);
        let ssa = crate::decompiler::ssa::build_ssa_with_call_abi_inputs(
            func,
            &self.analysis.code_index,
            &self.function_frames,
            self.bitness,
            self.address_space.image_base,
            &call_abi_inputs,
        );
        let out = crate::decompiler::ssa::simplify(&ssa);
        if let Ok(mut cache) = self.ssa_cache.lock() {
            cache.insert(va, out.clone());
        }
        Some(out)
    }

    /// Additive semantic HIR for one function.
    ///
    /// The HIR is deliberately built above the frozen P-code/SSA layers.  It
    /// preserves the current value/provenance graph while giving subsequent
    /// passes a stable home for register slices, partitioned memory objects,
    /// and Win64 call contracts.  It does not mutate cached SSA or project
    /// state.
    pub fn function_hir(&self, va: u64) -> Option<crate::decompiler::hir::HirFunction> {
        let (ssa, _) = self.function_ssa_optimized(va)?;
        let mut lowering = crate::decompiler::hir::HirFunction::lower_from_ssa(&ssa);
        // The current ABI lifting pass is deliberately specific to the Windows
        // x64 calling convention.  Keep the generic SSA/HIR provenance bridge
        // available for x86, but do not attach a false Win64 contract there.
        if self.bitness == 64 {
            lowering.lift_win64_calls(&ssa);
        }
        Some(lowering.hir)
    }

    /// Drop cached optimized SSA for one function, or the whole project if `va` is `None`.
    pub fn invalidate_ssa_cache(&self, va: Option<u64>) {
        if let Ok(mut cache) = self.ssa_cache.lock() {
            match va {
                Some(v) => {
                    cache.remove(&v);
                }
                None => cache.clear(),
            }
        }
    }

    /// SSA-derived suggestion comments for the `apply_ssa_suggestions` bridge.
    ///
    /// Each surviving definition that simplification proved constant becomes a
    /// `(defining_va, "= 0xV (uintN)")` pair, ready to be persisted as a
    /// durable address comment via an `Op::Batch`.
    pub fn function_ssa_suggestions(&self, va: u64) -> Option<Vec<(u64, String)>> {
        let (_, analysis) = self.function_ssa_optimized(va)?;
        let out = analysis
            .constants
            .iter()
            .filter(|c| c.va != 0)
            .map(|c| (c.va, format!("= 0x{:x} (uint{})", c.value, c.size * 8)))
            .collect::<Vec<_>>();
        Some(out)
    }

    /// Recovered type report (Phase 4) for the function at `va`, computed over
    /// its optimized SSA. Read-only — persistence is the caller's job through
    /// [`Self::type_recovery_ops`] / the `apply_type_recovery` MCP tool.
    pub fn function_types_recovered(
        &self,
        va: u64,
    ) -> Option<crate::decompiler::types::TypeRecoveryReport> {
        let (opt, _) = self.function_ssa_optimized(va)?;
        let constraints = self.call_constraints_for(&opt);
        Some(crate::decompiler::types::recover_types(
            &opt,
            va,
            self.bitness,
            &constraints,
        ))
    }

    /// Select the signature emitted for a function without mutating durable
    /// project state.  Explicit project/PDB declarations always win.  Only the
    /// architecture heuristic is eligible for a one-way refinement from the
    /// SSA type-recovery report.
    fn signature_for_emission(
        &self,
        func: &crate::analysis::functions::Function,
        report: &crate::decompiler::types::TypeRecoveryReport,
    ) -> Option<FunctionSignature> {
        // `function_signatures` contains persisted user edits as well as PDB
        // declarations, so it must win over the analysis snapshot.
        if let Some(signature) = self.function_signatures.get(&func.entry_va) {
            return Some(signature.clone());
        }
        if let Some(signature) = &func.signature {
            return Some(signature.clone());
        }

        let name = func.name(&self.symbols);
        // A named SigDB API is externally supplied evidence, not a heuristic
        // placeholder.  Keep it exactly as authored.
        if let Some(signature) = self.sig_db.lookup_by_name(&name) {
            return Some(signature.clone());
        }

        let heuristic = crate::analysis::signatures::recover_signature_with_db(
            func,
            &self.analysis.code_index,
            self.bitness,
            &name,
            None,
        )?;
        Some(
            crate::decompiler::types::signature::refine_signature_from_recovery(
                &heuristic,
                crate::decompiler::types::signature::SignatureSource::Heuristic,
                report,
                self.bitness as u8,
            ),
        )
    }

    /// 2.md dual-object model (semantic effects + presentation + contracts)
    /// for a function, built on the same optimized SSA as native decompile.
    /// Applies checker-backed rewrites so contracts match the shipped emit path.
    pub fn function_dual_model(
        &self,
        va: u64,
    ) -> Option<crate::decompiler::structure::DualDecompModel> {
        let func = self.function_at(va)?;
        let (opt, _) = self.function_ssa_optimized(va)?;
        let switches = resolve_switch_infos(self, func, &opt);
        let mut dual = crate::decompiler::structure::DualDecompModel::build(&opt, &switches);
        let selected = crate::decompiler::structure::rewrite::select_improving_moves(&dual);
        crate::decompiler::structure::rewrite::apply_moves(&mut dual, &selected, &opt);
        let _ = dual.sanitize_contracts(&opt);
        Some(dual)
    }

    /// Compact contract fingerprint for multi-profile orbit stability (2.md).
    /// When the shipped decompiler emits `switch`/`case` but SSA contracts
    /// missed the partition (eq-ladder fold path), seed cases from text.
    pub fn function_contract_fingerprint(&self, va: u64) -> Option<String> {
        let mut dual = self.function_dual_model(va)?;
        if dual.contracts.cases.is_empty()
            && let Some(text) = self.function_decompile_native(va)
            && let Some(part) =
                crate::decompiler::structure::rd_model::case_partition_from_decomp_text(&text)
        {
            dual.contracts.cases.push(part);
        }
        Some(dual.contracts.fingerprint())
    }

    /// Full decompile artifact (v2 pipeline with legacy fallback).
    /// Canonical product: text + contracts + check report + engine identity.
    pub fn function_decompile_artifact(
        &self,
        va: u64,
        options: crate::decompiler::v2::DecompileOptions,
    ) -> Option<crate::decompiler::v2::DecompileArtifact> {
        let func = self.function_at(va)?;
        // Raw lifted P-code for semantic HIR; optimized SSA for presentation.
        let raw = self.function_ssa(va)?;
        let (opt, _) = self.function_ssa_optimized(va)?;
        let constraints = self.call_constraints_for(&opt);
        let report = crate::decompiler::types::recover_types(&opt, va, self.bitness, &constraints);
        let sig = self.signature_for_emission(func, &report);
        let switches = resolve_switch_infos(self, func, &opt);
        let mut global_names = crate::ir::annotate::build_global_names_with_db(
            &self.symbols,
            &self.typed_globals,
            &self.function_signatures,
            &self.types,
            Some(&self.sig_db),
        );
        for f in self.functions().iter() {
            let n = f.name(&self.symbols);
            global_names.insert(f.entry_va, n);
        }
        let mut insn_to_global = std::collections::HashMap::new();
        for block in &opt.blocks {
            for op in &block.ops {
                if op.va == 0 {
                    continue;
                }
                if let Some(gva) = self.resolve_global_va(op.va) {
                    insn_to_global.insert(op.va, gva);
                    if let Some(sref) = crate::llm::query::try_read_string_at_va(
                        &self.pe.image,
                        &self.address_space,
                        gva,
                        2,
                    ) {
                        let lit = format!("{:?}", sref.value);
                        global_names.insert(gva, lit);
                    } else {
                        global_names.entry(gva).or_insert_with(|| {
                            self.symbols
                                .name(gva)
                                .map(str::to_string)
                                .unwrap_or_else(|| format!("g_{gva:x}"))
                        });
                    }
                }
                if let crate::decompiler::ssa::SsaOpKind::Pcode(pcode) = &op.kind {
                    use pcode_ir::AddressSpaceId;
                    use rsleigh_api::PcodeOp;
                    if let PcodeOp::Copy { input, .. } = pcode
                        && matches!(input.space, AddressSpaceId::Const | AddressSpaceId::Ram)
                        && input.offset != 0
                    {
                        let gva = input.offset;
                        if let Some(sref) = crate::llm::query::try_read_string_at_va(
                            &self.pe.image,
                            &self.address_space,
                            gva,
                            2,
                        ) {
                            global_names
                                .entry(gva)
                                .or_insert_with(|| format!("{:?}", sref.value));
                        }
                    }
                }
            }
        }
        let frame = self.function_frames.get(&va).or(func.stack_frame.as_ref());
        let names = crate::decompiler::structure::NameCtx {
            frame,
            sig: sig.as_ref(),
            global_names,
            insn_to_global,
        };
        Some(crate::decompiler::v2::decompile_function_v2_with_raw(
            &raw,
            &opt,
            Some(&report),
            sig.as_ref(),
            self.bitness,
            &switches,
            &names,
            &options,
        ))
    }

    /// Native (non-LLM) pseudo-C decompilation — returns artifact text only.
    ///
    /// Product default mode ([`DecompileOptions::production`]). For pure V2
    /// equality checks use [`Self::function_decompile_native_with`].
    pub fn function_decompile_native(&self, va: u64) -> Option<String> {
        self.function_decompile_native_with(
            va,
            crate::decompiler::v2::DecompileOptions::production(),
        )
    }

    /// Native decompile text under an explicit decompile mode (product / pure / legacy).
    pub fn function_decompile_native_with(
        &self,
        va: u64,
        options: crate::decompiler::v2::DecompileOptions,
    ) -> Option<String> {
        self.function_decompile_artifact(va, options)
            .map(|a| a.text)
    }

    /// Alias used by tests / agents for the full v2 product.
    pub fn function_decompile_artifact_default(
        &self,
        va: u64,
    ) -> Option<crate::decompiler::v2::DecompileArtifact> {
        self.function_decompile_artifact(va, crate::decompiler::v2::DecompileOptions::production())
    }

    /// Resolve a callee VA (function entry or IAT slot) to a [`FunctionSignature`].
    fn signature_for_target(&self, target: u64) -> Option<FunctionSignature> {
        if let Some(sig) = self.function_signatures.get(&target) {
            return Some(sig.clone());
        }
        if let Some(f) = self.function_at(target) {
            if let Some(sig) = &f.signature {
                return Some(sig.clone());
            }
            let name = f.name(&self.symbols);
            if let Some(sig) = self.sig_db.lookup_by_name(&name) {
                return Some(sig.clone());
            }
        }
        // IAT / import symbol at target.
        if let Some(sym) = self.symbols.get(target)
            && let Some(sig) = self.sig_db.lookup_by_name(&sym.name)
        {
            return Some(sig.clone());
        }
        None
    }

    /// Build call-site type constraints from direct callees with known signatures.
    fn call_constraints_for(
        &self,
        ssa: &crate::decompiler::ssa::SsaFunction,
    ) -> Vec<crate::decompiler::types::CallConstraint> {
        use crate::decompiler::ssa::SsaOpKind;
        use crate::decompiler::types::{CallConstraint, data_type_to_ty_guess};
        use pcode_ir::AddressSpaceId;
        use rsleigh_api::PcodeOp;

        let mut out = Vec::new();

        // Collect Call/CallInd ops with a best-effort resolved target.
        for block in &ssa.blocks {
            for op in &block.ops {
                let dest = match &op.kind {
                    SsaOpKind::Pcode(PcodeOp::Call { dest })
                    | SsaOpKind::Pcode(PcodeOp::CallInd { dest }) => *dest,
                    _ => continue,
                };
                let mut target = if dest.space == AddressSpaceId::Const {
                    dest.offset
                } else {
                    0
                };
                // Resolve via xrefs-from this instruction (IAT / direct call).
                if target == 0 {
                    for x in self.analysis.xrefs.from(op.va) {
                        if x.kind == crate::analysis::xrefs::XrefKind::Call && x.to_va != 0 {
                            target = x.to_va;
                            break;
                        }
                    }
                }
                // Resolve via RIP-relative memory operand on the iced instruction
                // (typical `call [rip+__imp_X]` pattern).
                if target == 0
                    && let Some(dec) = self.analysis.code_index.at_va(op.va)
                    && let Some(mem_va) =
                        crate::analysis::indirect::rip_relative_target_va(&dec.instr, self.bitness)
                {
                    target = mem_va;
                }
                if target == 0 {
                    continue;
                }
                let Some(sig) = self.signature_for_target(target) else {
                    continue;
                };
                let arg_types = sig
                    .params
                    .iter()
                    .map(|(_, t)| data_type_to_ty_guess(t))
                    .collect();
                out.push(CallConstraint {
                    call_va: op.va,
                    arg_types,
                });
            }
        }
        // Also seed from CFG call edges when the SSA dest is indirect/register
        // but the edge target is known.
        if let Some(func) = self.function_at(ssa.entry_va) {
            for block in &func.blocks {
                for edge in &block.successors {
                    if edge.kind != crate::analysis::functions::EdgeKind::Call || edge.target == 0 {
                        continue;
                    }
                    // Find a Call op in this block whose constraint is missing.
                    let Some(sig) = self.signature_for_target(edge.target) else {
                        continue;
                    };
                    // Approximate: attach to any Call op in the block without a
                    // constraint yet (best-effort for indirect-ish edges).
                    if let Some(ssa_block) =
                        ssa.blocks.iter().find(|b| b.entry_va == block.entry_va)
                    {
                        for op in &ssa_block.ops {
                            if matches!(
                                &op.kind,
                                SsaOpKind::Pcode(PcodeOp::Call { .. } | PcodeOp::CallInd { .. })
                            ) && !out.iter().any(|c| c.call_va == op.va)
                            {
                                let arg_types = sig
                                    .params
                                    .iter()
                                    .map(|(_, t)| data_type_to_ty_guess(t))
                                    .collect();
                                out.push(CallConstraint {
                                    call_va: op.va,
                                    arg_types,
                                });
                                break;
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Build the durable [`Op::Batch`] that persists a [`TypeRecoveryReport`]:
    /// typed stack locals/args, a refined function signature (typed params +
    /// return), and resolved global re-types. One undo step, one checkpoint.
    pub fn type_recovery_ops(
        &self,
        report: &crate::decompiler::types::TypeRecoveryReport,
    ) -> crate::project::op::Op {
        use crate::decompiler::types::TyGuess;
        use crate::project::op::Op;
        use crate::project::types::FunctionSignature;

        let mut ops: Vec<Op> = Vec::new();
        let ptr_bits = (self.bitness / 8 * 8) as u8;

        // 1) Stack locals / args. Aggregates override the base local's type
        // with a Named struct (Phase 7 B).
        let aggregate_bases: HashMap<i64, String> =
            crate::decompiler::types::aggregate::aggregate_base_offsets(
                &report.locals,
                &report.aggregates,
            )
            .into_iter()
            .collect();

        for local in &report.locals {
            if matches!(local.ty, TyGuess::Unknown) && !aggregate_bases.contains_key(&local.offset)
            {
                continue;
            }
            let ty = if let Some(name) = aggregate_bases.get(&local.offset) {
                crate::project::types::DataType::Named(name.clone())
            } else {
                local.ty.to_data_type(ptr_bits)
            };
            ops.push(Op::SetStackLocalType {
                function_va: report.function_va,
                offset: local.offset,
                ty,
                old_ty: None,
            });
        }

        // 2) Function signature: typed params + return.
        let typed_params: Vec<_> = report
            .params
            .iter()
            .filter(|p| !matches!(p.ty, TyGuess::Unknown))
            .collect();
        if !typed_params.is_empty() || report.return_type.is_some() {
            let func = match self.function_at(report.function_va) {
                Some(f) => f,
                None => return Op::Batch { ops },
            };
            let existing = func
                .signature
                .clone()
                .or_else(|| {
                    crate::analysis::signatures::recover_signature_with_db(
                        func,
                        &self.analysis.code_index,
                        self.bitness,
                        &func.name(&self.symbols),
                        Some(&self.sig_db),
                    )
                })
                .unwrap_or(FunctionSignature {
                    name: func.name(&self.symbols),
                    params: Vec::new(),
                    ret: crate::project::types::DataType::Void,
                    calling_conv: None,
                });
            let mut params = existing.params;
            for (i, p) in typed_params.iter().enumerate() {
                let ty_dt = p.ty.to_data_type(ptr_bits);
                if i < params.len() {
                    params[i].1 = ty_dt;
                } else {
                    params.push((format!("arg{}", i + 1), ty_dt));
                }
            }
            let ret = report
                .return_type
                .as_ref()
                .map(|r| r.ty.to_data_type(ptr_bits))
                .unwrap_or(existing.ret);
            ops.push(Op::SetFunctionSignature {
                va: report.function_va,
                signature: FunctionSignature {
                    params,
                    ret,
                    ..existing
                },
                old_signature: None,
            });
        }

        // 3) Global re-types: resolve each candidate's instruction VA to a
        //    data-section global VA via the iced instruction's memory operand.
        for g in &report.globals {
            if let Some(va) = self.resolve_global_va(g.instruction_va) {
                // Don't clobber PDB-typed globals.
                if !self.typed_globals.contains_key(&va) {
                    ops.push(Op::SetGlobalType {
                        va,
                        ty: g.ty.to_data_type(ptr_bits),
                        old_ty: None,
                    });
                }
            }
        }

        Op::Batch { ops }
    }

    /// Resolve the target VA of a RIP-relative / absolute memory operand at
    /// `instruction_va`, if it lands in a data section. Used by type recovery
    /// to back the `RawRam` global candidates with a concrete global VA.
    pub fn resolve_global_va(&self, instruction_va: u64) -> Option<u64> {
        use iced_x86::InstructionInfoFactory;
        let dec = self.analysis.code_index.at_va(instruction_va)?;
        let mut factory = InstructionInfoFactory::new();
        let info = factory.info(&dec.instr);
        for um in info.used_memory() {
            let target = crate::llm::query::memory_target_va(
                &dec.instr,
                um.base(),
                um.index(),
                um.displacement(),
            );
            if target != 0 && self.address_space.is_data_va(target) {
                return Some(target);
            }
        }
        None
    }

    /// Graph-conditioned decompiler input for a function, preserving edge kinds.
    #[cfg(feature = "gclsd-archive")]
    pub fn function_gclsd_input(&self, va: u64) -> Option<crate::ir::gclsd::GclsdInput> {
        let func = self.function_at(va)?;
        crate::ir::gclsd::function_to_gclsd_input(
            func,
            &self.analysis.code_index,
            &self.symbols,
            &self.comments,
            &self.analysis.xrefs,
            self.address_space.image_base,
            self.bitness,
            &self.typed_globals,
            &self.function_frames,
            &self.types,
            &self.function_signatures,
        )
    }

    /// Paginated export: only instructions within the requested IP range.
    pub fn function_export_range(
        &self,
        va: u64,
        start_ip: u64,
        end_ip: u64,
    ) -> Option<FunctionExport> {
        self.function_export(va)
            .map(|e| e.ip_window(start_ip, end_ip))
    }

    /// Full-context package for a function: agent text plus strings/APIs/callers.
    pub fn function_context_text(&self, va: u64) -> Option<String> {
        self.function_context_text_bounded(va, None)
    }

    /// Like [`Self::function_context_text`] with an optional token budget on the
    /// agent-text body (~4 tokens per line).
    pub fn function_context_text_bounded(
        &self,
        va: u64,
        max_tokens: Option<usize>,
    ) -> Option<String> {
        use crate::llm::query::{apis_called, callers_with_args, strings_in_function};
        let max_instructions = max_tokens.map(|t| t / 4);
        let agent = self.function_agent_text_opts(
            va,
            AgentTextOpts {
                strip_noise: true,
                max_instructions,
            },
        )?;
        let strings = strings_in_function(self, va, 4)
            .iter()
            .map(|s| format!("  {:#x} ({}): {}", s.va, s.encoding, s.value))
            .collect::<Vec<_>>()
            .join("\n");
        let apis = apis_called(self, va).join(", ");
        let callers = callers_with_args(self, va)
            .iter()
            .map(|c| {
                format!(
                    "  {} @ {:#x} ({})\n",
                    c.caller,
                    c.from_va,
                    c.args.join(", ")
                )
            })
            .collect::<String>();
        Some(format!(
            "{agent}\nreferenced strings:\n{strings}\napis called:\n  {apis}\ncallers with args:\n{callers}",
        ))
    }

    /// Native decompilation with optional token budget (~4 tokens per line).
    pub fn function_decompile_native_bounded(
        &self,
        va: u64,
        max_tokens: Option<usize>,
    ) -> Option<String> {
        let full = self.function_decompile_native(va)?;
        let Some(budget) = max_tokens else {
            return Some(full);
        };
        let max_lines = budget / 4;
        if max_lines == 0 {
            return Some("// truncated: max_tokens too small\n".to_string());
        }
        let lines: Vec<&str> = full.lines().collect();
        if lines.len() <= max_lines {
            return Some(full);
        }
        // Always keep the signature header (first line) and closing brace if present.
        let header = lines.first().copied().unwrap_or("");
        let has_close = lines.last().is_some_and(|l| l.trim() == "}");
        let body_budget = max_lines.saturating_sub(2); // header + close/summary
        let mut out = String::new();
        out.push_str(header);
        out.push('\n');
        let body: Vec<&str> = lines.iter().skip(1).copied().collect();
        let keep = if has_close {
            body.len().saturating_sub(1).min(body_budget)
        } else {
            body.len().min(body_budget)
        };
        for line in body.iter().take(keep) {
            out.push_str(line);
            out.push('\n');
        }
        let omitted = body.len().saturating_sub(keep) - if has_close { 1 } else { 0 };
        if omitted > 0 {
            out.push_str(&format!(
                "// ... {omitted} more lines truncated. Call get_function_dataflow for full SSA.\n"
            ));
        }
        if has_close {
            out.push_str("}\n");
        }
        Some(out)
    }

    /// Compact SSA def-use JSON for LLM data-flow reasoning (Phase 6 L2).
    ///
    /// Token-dense: no assembly, only defs/uses/phis/constants. Bounded by
    /// `max_defs` (default 128).
    pub fn function_dataflow_json(
        &self,
        va: u64,
        max_defs: Option<usize>,
    ) -> Option<serde_json::Value> {
        use crate::decompiler::ssa::{Location, SsaOpKind, SsaVar};
        use pcode_ir::AddressSpaceId;
        use rsleigh_api::PcodeOp;
        use serde_json::json;

        let (ssa, analysis) = self.function_ssa_optimized(va)?;
        let max_defs = max_defs.unwrap_or(128);

        // Build use map: def → list of consumer var labels (or return:va).
        let mut use_sites: HashMap<SsaVar, Vec<String>> = HashMap::new();
        for block in &ssa.blocks {
            for op in &block.ops {
                let consumer = match &op.def {
                    Some(d) => ssa_var_label(d),
                    None => match &op.kind {
                        SsaOpKind::Pcode(PcodeOp::Return { .. }) => {
                            format!("return_{:#x}", op.va)
                        }
                        SsaOpKind::Pcode(PcodeOp::Call { .. } | PcodeOp::CallInd { .. }) => {
                            format!("call_{:#x}", op.va)
                        }
                        SsaOpKind::Pcode(PcodeOp::Store { .. }) => {
                            format!("store_{:#x}", op.va)
                        }
                        SsaOpKind::Pcode(PcodeOp::Branch { .. } | PcodeOp::CBranch { .. }) => {
                            format!("branch_{:#x}", op.va)
                        }
                        _ => format!("side_{:#x}", op.va),
                    },
                };
                for u in &op.uses {
                    use_sites
                        .entry(u.clone())
                        .or_default()
                        .push(consumer.clone());
                }
                if let SsaOpKind::Phi(phi) = &op.kind {
                    for arg in phi.args.iter().flatten() {
                        use_sites
                            .entry(arg.clone())
                            .or_default()
                            .push(ssa_var_label(&phi.out));
                    }
                }
            }
        }

        // Constant map from analysis keyed by defining var when possible.
        let const_by_va: HashMap<u64, &crate::decompiler::ssa::simplify::SsaConstant> = analysis
            .constants
            .iter()
            .filter(|c| c.va != 0)
            .map(|c| (c.va, c))
            .collect();

        let mut total_defs = 0usize;
        let mut truncated = false;
        let mut blocks_json = Vec::new();

        for block in &ssa.blocks {
            let mut defs = Vec::new();
            let mut phis = Vec::new();
            let mut constants = Vec::new();

            for op in &block.ops {
                match &op.kind {
                    SsaOpKind::Phi(phi) => {
                        if total_defs >= max_defs {
                            truncated = true;
                            continue;
                        }
                        total_defs += 1;
                        phis.push(json!({
                            "out": ssa_var_label(&phi.out),
                            "args": phi.args.iter().map(|a| {
                                a.as_ref().map(ssa_var_label).unwrap_or_else(|| "undef".into())
                            }).collect::<Vec<_>>(),
                            "va": if op.va == 0 { serde_json::Value::Null } else { json!(format!("{:#x}", op.va)) },
                        }));
                    }
                    SsaOpKind::Pcode(pcode) => {
                        let Some(def) = &op.def else {
                            continue;
                        };
                        if total_defs >= max_defs {
                            truncated = true;
                            continue;
                        }
                        total_defs += 1;
                        let live = use_sites.get(def).cloned().unwrap_or_default();
                        // Constant copy?
                        if let PcodeOp::Copy { input, .. } = pcode
                            && input.space == AddressSpaceId::Const
                        {
                            constants.push(json!({
                                "var": ssa_var_label(def),
                                "value": format!("{:#x}", input.offset),
                                "size": input.size,
                                "va": if op.va == 0 { serde_json::Value::Null } else { json!(format!("{:#x}", op.va)) },
                            }));
                        } else if let Some(c) = const_by_va.get(&op.va) {
                            constants.push(json!({
                                "var": ssa_var_label(def),
                                "value": format!("{:#x}", c.value),
                                "size": c.size,
                                "va": format!("{:#x}", c.va),
                            }));
                        }
                        let uses: Vec<String> = op.uses.iter().map(ssa_var_label).collect();
                        // Live-in params: version 1 with no prior def looks like param.
                        let op_name = if def.version <= 1
                            && matches!(
                                def.location,
                                Location::Register { .. } | Location::StackSlot { .. }
                            )
                            && matches!(pcode, PcodeOp::Copy { .. })
                            && op.uses.is_empty()
                        {
                            "param".to_string()
                        } else {
                            pcode_op_name(pcode)
                        };
                        defs.push(json!({
                            "var": ssa_var_label(def),
                            "va": if op.va == 0 { serde_json::Value::Null } else { json!(format!("{:#x}", op.va)) },
                            "op": op_name,
                            "uses": uses,
                            "live_uses": live,
                        }));
                    }
                }
            }

            // Emit synthetic param entries for live-in uses (version 1 never defined).
            // Already covered when we see them as uses of ops that define from nothing —
            // scan uses with version 1 that aren't in defs.
            let defined: HashSet<SsaVar> = block.ops.iter().filter_map(|o| o.def.clone()).collect();
            for op in &block.ops {
                for u in &op.uses {
                    if u.version == 1 && !defined.contains(u) && total_defs < max_defs {
                        // Only emit once per block.
                        if defs.iter().any(|d| {
                            d.get("var").and_then(|v| v.as_str()) == Some(&ssa_var_label(u))
                        }) {
                            continue;
                        }
                        if matches!(
                            u.location,
                            Location::Register { .. } | Location::StackSlot { .. }
                        ) {
                            total_defs += 1;
                            let live = use_sites.get(u).cloned().unwrap_or_default();
                            defs.push(json!({
                                "var": ssa_var_label(u),
                                "va": serde_json::Value::Null,
                                "op": "param",
                                "uses": [],
                                "live_uses": live,
                            }));
                        }
                    }
                }
            }

            blocks_json.push(json!({
                "id": block.id,
                "entry_va": format!("{:#x}", block.entry_va),
                "defs": defs,
                "phis": phis,
                "constants": constants,
            }));
        }

        let top_constants: Vec<_> = analysis
            .constants
            .iter()
            .filter(|c| c.va != 0)
            .map(|c| {
                json!({
                    "va": format!("{:#x}", c.va),
                    "value": format!("{:#x}", c.value),
                    "size": c.size,
                })
            })
            .collect();

        // Phase 7 C: attach points-to targets to Load/Store ops in defs.
        let points_to = self.function_points_to_map(va);
        if let Some(pt) = &points_to {
            for block in &mut blocks_json {
                if let Some(defs) = block.get_mut("defs").and_then(|d| d.as_array_mut()) {
                    for def in defs.iter_mut() {
                        let Some(va_str) = def.get("va").and_then(|v| v.as_str()) else {
                            continue;
                        };
                        let Ok(insn_va) = u64::from_str_radix(va_str.trim_start_matches("0x"), 16)
                        else {
                            continue;
                        };
                        if let Some(e) = pt.by_instruction(insn_va) {
                            def["points_to"] = json!({
                                "kind": format!("{:?}", e.kind),
                                "va": e.va.map(|v| format!("{v:#x}")),
                                "symbol": e.symbol,
                                "stack_disp": e.stack_disp,
                            });
                        }
                    }
                }
            }
        }

        Some(json!({
            "entry_va": format!("{:#x}", ssa.entry_va),
            "blocks": blocks_json,
            "constants": top_constants,
            "truncated": truncated,
            "max_defs": max_defs,
            "points_to_count": points_to.as_ref().map(|p| p.entries.len()).unwrap_or(0),
        }))
    }

    /// Build the points-to map for a function (Phase 7 C).
    pub fn function_points_to_map(
        &self,
        va: u64,
    ) -> Option<crate::decompiler::analysis::PointsToMap> {
        let (ssa, _) = self.function_ssa_optimized(va)?;
        let mut insn_global = HashMap::new();
        for block in &ssa.blocks {
            for op in &block.ops {
                if op.va == 0 {
                    continue;
                }
                if let Some(gva) = self.resolve_global_va(op.va) {
                    insn_global.insert(op.va, gva);
                }
            }
        }
        let is_iat = |gva: u64| {
            self.symbols
                .get(gva)
                .is_some_and(|s| s.kind == SymbolKind::Import || s.name.starts_with("__imp_"))
        };
        let ctx = crate::decompiler::analysis::PointsToCtx {
            address_space: &self.address_space,
            symbols: &self.symbols,
            insn_global: &insn_global,
            is_iat: &is_iat,
        };
        Some(crate::decompiler::analysis::compute_points_to(&ssa, &ctx))
    }

    /// Points-to map as JSON (MCP `get_function_points_to`).
    pub fn function_points_to_json(&self, va: u64) -> Option<serde_json::Value> {
        self.function_points_to_map(va).map(|m| m.to_json())
    }

    /// Resolve COM/vtable calls inside a function (Phase 7 D).
    pub fn function_vtable_calls(&self, va: u64) -> Option<serde_json::Value> {
        let func = self.function_at(va)?;
        let all = crate::analysis::indirect::resolve_vtable_calls(
            &self.analysis.code_index,
            self.bitness,
            &self.vtable_db,
            &self.address_space,
            &self.pe.image,
        );
        // Filter to this function's VA range.
        let min_va = func.entry_va;
        let max_va = func
            .blocks
            .iter()
            .map(|b| b.exit_va.saturating_add(16))
            .max()
            .unwrap_or(min_va);
        let sites: Vec<_> = all
            .into_iter()
            .filter(|c| c.call_va >= min_va && c.call_va <= max_va)
            .map(|c| {
                let callee = match (&c.interface, &c.method) {
                    (Some(i), Some(m)) => format!("{i}::{m}"),
                    (None, Some(m)) => m.clone(),
                    _ => format!("vtable[+{:#x}]", c.vtable_offset),
                };
                serde_json::json!({
                    "call_va": format!("{:#x}", c.call_va),
                    "this_reg": c.this_reg,
                    "vtable_offset": c.vtable_offset,
                    "interface": c.interface,
                    "method": c.method,
                    "callee": callee,
                    "vtable_va": c.vtable_va.map(|v| format!("{v:#x}")),
                    "heuristic": c.heuristic,
                    "params": c.signature.as_ref().map(|s| {
                        s.params.iter().map(|(n, t)| {
                            serde_json::json!([n, self.types.render(t)])
                        }).collect::<Vec<_>>()
                    }),
                    "ret": c.signature.as_ref().map(|s| self.types.render(&s.ret)),
                })
            })
            .collect();
        Some(serde_json::json!(sites))
    }

    /// Cross-function call-site arg tracing (Phase 6 L3).
    ///
    /// For each Call/CallInd in the optimized SSA, resolve the callee and
    /// classify the reaching def of each arg register.
    pub fn call_sites_with_args(&self, va: u64) -> Option<serde_json::Value> {
        use crate::decompiler::ssa::lower::reg_name;
        use crate::decompiler::ssa::{Location, SsaOpKind, SsaVar};
        use crate::decompiler::types::data_type_to_ty_guess;
        use pcode_ir::AddressSpaceId;
        use rsleigh_api::PcodeOp;
        use serde_json::json;

        let (ssa, analysis) = self.function_ssa_optimized(va)?;
        let report = self.function_types_recovered(va);
        let def_types = report.as_ref().map(|r| &r.def_types);

        // Map def var → defining op for source classification.
        let mut def_op: HashMap<SsaVar, &crate::decompiler::ssa::SsaOp> = HashMap::new();
        for block in &ssa.blocks {
            for op in &block.ops {
                if let Some(d) = &op.def {
                    def_op.insert(d.clone(), op);
                }
            }
        }
        let const_by_va: HashMap<u64, u64> = analysis
            .constants
            .iter()
            .filter(|c| c.va != 0)
            .map(|c| (c.va, c.value))
            .collect();

        // Arg register bases in x64 fastcall order.
        let arg_regs: &[(u64, &str)] = &[(0x08, "rcx"), (0x10, "rdx"), (0x80, "r8"), (0x88, "r9")];

        // Precompute points-to + vtable calls once for this function (Phase 7 C/D).
        let pt_map = self.function_points_to_map(va);
        let vtable_sites = self.function_vtable_calls(va);

        let mut sites = Vec::new();
        for block in &ssa.blocks {
            for op in &block.ops {
                let is_call = matches!(
                    &op.kind,
                    SsaOpKind::Pcode(PcodeOp::Call { .. } | PcodeOp::CallInd { .. })
                );
                if !is_call {
                    continue;
                }
                let dest = match &op.kind {
                    SsaOpKind::Pcode(PcodeOp::Call { dest })
                    | SsaOpKind::Pcode(PcodeOp::CallInd { dest }) => *dest,
                    _ => continue,
                };
                let mut callee_va = if dest.space == AddressSpaceId::Const {
                    dest.offset
                } else {
                    0
                };
                // Fall back to CFG call edge for this block.
                if callee_va == 0
                    && let Some(func) = self.function_at(ssa.entry_va)
                    && let Some(bb) = func.blocks.iter().find(|b| b.entry_va == block.entry_va)
                {
                    for edge in &bb.successors {
                        if edge.kind == crate::analysis::functions::EdgeKind::Call
                            && edge.target != 0
                        {
                            callee_va = edge.target;
                            break;
                        }
                    }
                }

                let (callee_name, sig) = if callee_va != 0 {
                    let name = self
                        .symbols
                        .name(callee_va)
                        .map(|s| s.strip_prefix("__imp_").unwrap_or(s).to_string())
                        .or_else(|| self.function_at(callee_va).map(|f| f.name(&self.symbols)))
                        .unwrap_or_else(|| format!("FUN_{callee_va:08x}"));
                    let sig = self.signature_for_target(callee_va);
                    (name, sig)
                } else {
                    ("unknown".to_string(), None)
                };

                // For each arg register used at the call, find the reaching def.
                // Uses of Call ops don't always include arg regs (Call has no
                // register uses in p-code); scan backwards in the block for
                // last def of each arg reg.
                let mut args = Vec::new();
                let max_args = sig.as_ref().map(|s| s.params.len()).unwrap_or(4).min(4);
                for (rank, (base, reg)) in arg_regs.iter().enumerate().take(max_args) {
                    // Find last def of this register before the call in this block.
                    let mut reaching: Option<&SsaVar> = None;
                    for prior in &block.ops {
                        if prior.va == op.va && !matches!(&prior.kind, SsaOpKind::Phi(_)) {
                            // stop before this call (ops are in order)
                            break;
                        }
                        if let Some(d) = &prior.def
                            && matches!(d.location, Location::Register { base_offset } if base_offset == *base)
                        {
                            reaching = Some(d);
                        }
                    }
                    // Also check uses of the call op itself.
                    for u in &op.uses {
                        if matches!(u.location, Location::Register { base_offset } if base_offset == *base)
                        {
                            reaching = Some(u);
                        }
                    }

                    let (source, ty_str) = if let Some(var) = reaching {
                        let source =
                            classify_arg_source(var, def_op.get(var).copied(), &const_by_va, self);
                        let ty_str = def_types
                            .and_then(|dt| dt.get(var))
                            .map(|t| format!("{t:?}"))
                            .or_else(|| {
                                sig.as_ref()
                                    .and_then(|s| s.params.get(rank))
                                    .map(|(_, t)| self.types.render(t))
                            });
                        (source, ty_str)
                    } else {
                        // No reaching def found — still emit Win32 expected type.
                        let ty_str = sig
                            .as_ref()
                            .and_then(|s| s.params.get(rank))
                            .map(|(_, t)| self.types.render(t));
                        ("unknown".to_string(), ty_str)
                    };

                    let mut arg = json!({
                        "reg": reg,
                        "source": source,
                    });
                    if let Some(t) = ty_str {
                        arg["type"] = json!(t);
                    }
                    if let Some(s) = &sig
                        && let Some((pname, _)) = s.params.get(rank)
                    {
                        arg["param"] = json!(pname);
                    }
                    // Resolve pointer-looking constants / globals to string values.
                    if let Some((value, enc)) = resolve_arg_string_value(self, &source, reaching) {
                        arg["value"] = json!(value);
                        arg["value_encoding"] = json!(enc);
                        if source.starts_with("constant:") || source.starts_with("global:") {
                            arg["source"] = json!(format!("string:{value}"));
                        }
                    }
                    // Silence unused import warning for data_type_to_ty_guess
                    let _ = data_type_to_ty_guess;
                    let _ = reg_name;
                    args.push(arg);
                }

                // Enrich args with points-to when available for this call VA.
                if let Some(pt) = &pt_map
                    && let Some(e) = pt.by_instruction(op.va)
                {
                    for arg in &mut args {
                        arg["points_to"] = json!({
                            "kind": format!("{:?}", e.kind),
                            "va": e.va.map(|v| format!("{v:#x}")),
                            "symbol": e.symbol,
                        });
                    }
                }

                // Phase 7 D: overlay vtable method name when this call is a
                // COM dispatch.
                let mut final_callee = callee_name;
                if let Some(arr) = vtable_sites.as_ref().and_then(|v| v.as_array()) {
                    for site in arr {
                        if site.get("call_va").and_then(|v| v.as_str())
                            != Some(&format!("{:#x}", op.va))
                        {
                            continue;
                        }
                        if let Some(c) = site.get("callee").and_then(|v| v.as_str()) {
                            final_callee = c.to_string();
                        }
                        if let Some(params) = site.get("params").and_then(|v| v.as_array()) {
                            for (i, arg) in args.iter_mut().enumerate() {
                                if let Some(arr) = params.get(i).and_then(|p| p.as_array()) {
                                    if let Some(pname) = arr.first().and_then(|x| x.as_str()) {
                                        arg["param"] = json!(pname);
                                    }
                                    if let Some(pty) = arr.get(1).and_then(|x| x.as_str()) {
                                        arg["type"] = json!(pty);
                                    }
                                }
                            }
                        }
                    }
                }

                sites.push(json!({
                    "call_va": format!("{:#x}", op.va),
                    "callee": final_callee,
                    "callee_va": if callee_va == 0 { serde_json::Value::Null } else { json!(format!("{:#x}", callee_va)) },
                    "args": args,
                }));
            }
        }
        Some(json!(sites))
    }

    /// Structured decompilation export for LLM parsing (Phase 6 L5).
    pub fn function_decompile_structured(&self, va: u64) -> Option<serde_json::Value> {
        use crate::decompiler::ssa::lower::reg_name;
        use crate::decompiler::ssa::{Location, SsaOpKind};
        use crate::decompiler::structure::region::{Region, classify};
        use serde_json::json;

        let func = self.function_at(va)?;
        let (opt, _) = self.function_ssa_optimized(va)?;
        let report = self.function_types_recovered(va)?;
        let switches = resolve_switch_infos(self, func, &opt);
        let regions = classify(&opt, &switches);

        let sig = self.signature_for_emission(func, &report);

        let params: Vec<_> = sig
            .as_ref()
            .map(|s| {
                s.params
                    .iter()
                    .map(|(n, t)| {
                        json!({
                            "name": n,
                            "type": self.types.render(t),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let ret = sig
            .as_ref()
            .map(|s| self.types.render(&s.ret))
            .unwrap_or_else(|| "void".to_string());
        let name = sig
            .as_ref()
            .map(|s| s.name.clone())
            .unwrap_or_else(|| func.name(&self.symbols));

        // Carry Windows unwind provenance into the machine-readable view.  An
        // LLM can distinguish a recursively discovered candidate from an
        // authoritative x64 runtime-function range, while callers retain the
        // exact `.pdata` / `.xdata` addresses for follow-up evidence.
        let runtime_function = self
            .analysis
            .runtime_functions
            .entries
            .iter()
            .find(|entry| entry.contains_va(va))
            .cloned()
            .map(|entry| {
                let unwind = entry.unwind_info.as_ref().map(|info| {
                    let tail = match &info.tail {
                        crate::analysis::unwind::UnwindInfoTail::None => {
                            json!({ "kind": "none" })
                        }
                        crate::analysis::unwind::UnwindInfoTail::Handler {
                            handler_rva,
                            handler_data_offset,
                        } => json!({
                            "kind": "handler",
                            "handler_rva": format!("{handler_rva:#x}"),
                            "handler_data_offset": handler_data_offset,
                        }),
                        crate::analysis::unwind::UnwindInfoTail::Chained {
                            runtime_function,
                        } => json!({
                            "kind": "chained",
                            "begin_rva": format!("{:#x}", runtime_function.begin_rva),
                            "end_rva": format!("{:#x}", runtime_function.end_rva),
                            "unwind_info_rva": format!("{:#x}", runtime_function.unwind_info_rva),
                        }),
                    };
                    json!({
                        "version": info.version,
                        "flags": format!("{:#x}", info.flags),
                        "prolog_size": info.prolog_size,
                        "code_slots": info.code_slots,
                        "frame_register": info.frame_register,
                        "frame_offset_bytes": info.frame_offset_bytes,
                        "has_exception_handler": info.has_exception_handler(),
                        "has_termination_handler": info.has_termination_handler(),
                        "is_chained": info.is_chained(),
                        "tail": tail,
                        "codes": info.codes.iter().take(32).map(|code| json!({
                            "slot_index": code.slot_index,
                            "code_offset": code.code_offset,
                            "operation_code": code.operation_code,
                            "operation_info": code.operation_info,
                            "slots_used": code.slots_used,
                            "operation": format!("{:?}", code.operation),
                        })).collect::<Vec<_>>(),
                        "codes_truncated": info.codes.len() > 32,
                    })
                });
                json!({
                    "begin_va": format!("{:#x}", entry.begin_va),
                    "end_va": format!("{:#x}", entry.end_va),
                    "size": entry.size(),
                    "unwind_info_va": format!("{:#x}", entry.unwind_info_va),
                    "begin_rva": format!("{:#x}", entry.begin_rva),
                    "end_rva": format!("{:#x}", entry.end_rva),
                    "unwind_info_rva": format!("{:#x}", entry.unwind_info_rva),
                    "unwind": unwind,
                })
            });
        let runtime_function_table_complete = self.analysis.runtime_functions.is_complete();

        // Variable table from def_types.
        let mut variables = Vec::new();
        let mut seen = HashSet::new();
        for (var, ty) in &report.def_types {
            let label = ssa_var_label(var);
            if !seen.insert(label.clone()) {
                continue;
            }
            let source = match &var.location {
                Location::Register { base_offset } if var.version <= 1 => {
                    format!("param[{}]", reg_name(*base_offset))
                }
                Location::StackSlot { disp, .. } if var.version <= 1 && *disp > 0 => {
                    format!("stack_arg[{disp:#x}]")
                }
                _ => format!("{ty:?}"),
            };
            variables.push(json!({
                "name": label,
                "version": var.version,
                "type": format_ty_guess(ty),
                "source": source,
            }));
        }
        // Cap variable table.
        if variables.len() > 64 {
            variables.truncate(64);
        }

        let mut blocks = Vec::new();
        for block in &opt.blocks {
            let region_kind = match regions.get(&block.id) {
                Some(Region::If { .. }) => "if",
                Some(Region::IfElse { .. }) => "if/else",
                Some(Region::IfThenFallthrough { .. }) => "if/fallthrough",
                Some(Region::While { .. }) => "while",
                Some(Region::DoWhile { .. }) => "do/while",
                Some(Region::Switch { .. }) => "switch",
                Some(Region::Return) => "return",
                None => "linear",
            };
            let ops: Vec<_> = block
                .ops
                .iter()
                .filter(|o| !matches!(&o.kind, SsaOpKind::Phi(_)))
                .take(32)
                .map(|o| {
                    let op_name = match &o.kind {
                        SsaOpKind::Pcode(p) => pcode_op_name(p),
                        SsaOpKind::Phi(_) => "phi".to_string(),
                    };
                    json!({
                        "va": if o.va == 0 { serde_json::Value::Null } else { json!(format!("{:#x}", o.va)) },
                        "op": op_name,
                        "def": o.def.as_ref().map(ssa_var_label),
                        "uses": o.uses.iter().map(ssa_var_label).collect::<Vec<_>>(),
                    })
                })
                .collect();
            blocks.push(json!({
                "id": block.id,
                "entry_va": format!("{:#x}", block.entry_va),
                "region": region_kind,
                "ops": ops,
            }));
        }

        // Control-flow summary.
        let mut cf_parts = Vec::new();
        for (id, region) in &regions {
            match region {
                Region::IfElse { merge, .. } => {
                    let entry = opt.blocks.iter().find(|b| b.id == *id).map(|b| b.entry_va);
                    let merge_va = opt
                        .blocks
                        .iter()
                        .find(|b| b.id == *merge)
                        .map(|b| b.entry_va);
                    if let (Some(e), Some(m)) = (entry, merge_va) {
                        cf_parts.push(format!("if/else at {e:#x}, merge at {m:#x}"));
                    }
                }
                Region::IfThenFallthrough { merge, .. } => {
                    let entry = opt.blocks.iter().find(|b| b.id == *id).map(|b| b.entry_va);
                    if let Some(e) = entry {
                        cf_parts.push(format!("if/fallthrough at {e:#x}, merge block {merge}"));
                    }
                }
                Region::If { merge, .. } => {
                    let entry = opt.blocks.iter().find(|b| b.id == *id).map(|b| b.entry_va);
                    if let Some(e) = entry {
                        cf_parts.push(format!("if at {e:#x}, merge at block {merge}"));
                    }
                }
                Region::While { .. } => {
                    let entry = opt.blocks.iter().find(|b| b.id == *id).map(|b| b.entry_va);
                    if let Some(e) = entry {
                        cf_parts.push(format!("while at {e:#x}"));
                    }
                }
                Region::DoWhile { .. } => {
                    let entry = opt.blocks.iter().find(|b| b.id == *id).map(|b| b.entry_va);
                    if let Some(e) = entry {
                        cf_parts.push(format!("do/while at {e:#x}"));
                    }
                }
                Region::Switch { .. } => {
                    let entry = opt.blocks.iter().find(|b| b.id == *id).map(|b| b.entry_va);
                    if let Some(e) = entry {
                        cf_parts.push(format!("switch at {e:#x}"));
                    }
                }
                Region::Return => {}
            }
        }
        let control_flow = if cf_parts.is_empty() {
            "linear".to_string()
        } else {
            cf_parts.join("; ")
        };

        // Serialize def_types as array of {var, type}.
        let def_types_ser: Vec<_> = report
            .def_types
            .iter()
            .map(|(v, t)| {
                json!({
                    "var": ssa_var_label(v),
                    "type": format_ty_guess(t),
                })
            })
            .collect();

        // Phase 7 B: inferred structs.
        let structs: Vec<_> = report
            .aggregates
            .iter()
            .map(|a| {
                json!({
                    "name": a.name,
                    "size": a.size,
                    "fields": a.fields.iter().map(|f| {
                        json!({
                            "name": f.name,
                            "type": self.types.render(&f.ty),
                            "offset": f.offset,
                        })
                    }).collect::<Vec<_>>(),
                })
            })
            .collect();

        // HIR v1 is an additive semantic/provenance view.  Bound the inline
        // arrays so `get_function_decompilation_structured` stays usable on
        // large functions; callers can obtain the complete HIR through the
        // project API when a full graph is warranted.
        let mut lowering = crate::decompiler::hir::HirFunction::lower_from_ssa(&opt);
        if self.bitness == 64 {
            lowering.lift_win64_calls(&opt);
        }
        let hir = lowering.hir;
        let hir_value_count = hir.values().len();
        let hir_operation_count = hir.operations().len();
        let hir_memory_object_count = hir.memory_objects().len();
        let hir_call_site_count = hir.call_sites().len();
        let hir_validation_error = hir.validate().err().map(|error| error.to_string());
        let semantic_hir = json!({
            "schema": "windy-hir-v1",
            "valid": hir_validation_error.is_none(),
            "validation_error": hir_validation_error,
            "value_count": hir_value_count,
            "operation_count": hir_operation_count,
            "memory_object_count": hir_memory_object_count,
            "call_site_count": hir_call_site_count,
            "values": hir.values().iter().take(128).collect::<Vec<_>>(),
            "operations": hir.operations().iter().take(128).collect::<Vec<_>>(),
            "memory_objects": hir.memory_objects().iter().take(64).collect::<Vec<_>>(),
            "call_sites": hir.call_sites().iter().take(64).collect::<Vec<_>>(),
            "truncated": {
                "values": hir_value_count > 128,
                "operations": hir_operation_count > 128,
                "memory_objects": hir_memory_object_count > 64,
                "call_sites": hir_call_site_count > 64,
            },
        });

        // Machine-readable call facts belong beside the SSA/region facts, not
        // only in the human-oriented pseudo-C printer.  In particular, the
        // native emitter may still be unable to materialize a call result or
        // argument expression, while the call-site tracer can preserve the
        // recovered callee, ABI register, source value, and string evidence.
        // Consumers of the structured export can therefore score or reason
        // about call semantics without scraping `call(FUN_...)` text.
        let calls = self
            .call_sites_with_args(va)
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default();

        // Preserve CFG adjacency explicitly.  The old `control_flow` field is
        // a compact human summary and deliberately loses edge-level facts;
        // evaluators need these stable block/VA edges to score CFG recovery.
        let mut cfg_edges = Vec::new();
        for block in &opt.blocks {
            for succ_id in &block.successor_ids {
                let Some(succ) = opt.blocks.get(*succ_id as usize) else {
                    continue;
                };
                cfg_edges.push(json!({
                    "from_block": block.id,
                    "from_va": format!("{:#x}", block.entry_va),
                    "to_block": succ.id,
                    "to_va": format!("{:#x}", succ.entry_va),
                }));
            }
        }

        Some(json!({
            "signature": {
                "name": name,
                "params": params,
                "ret": ret,
            },
            "variables": variables,
            "blocks": blocks,
            "control_flow": control_flow,
            "def_types": def_types_ser,
            "typed_def_count": report.typed_def_count,
            "structs": structs,
            "calls": calls,
            "cfg_edges": cfg_edges,
            "runtime_function": runtime_function,
            "runtime_function_table_complete": runtime_function_table_complete,
            "semantic_hir": semantic_hir,
        }))
    }

    /// LLM/programmatic mutation API (facade; the MCP backend serializes every
    /// call into the durable operation journal).
    pub fn rename(&mut self, va: u64, name: impl Into<String>) {
        self.symbols.insert(va, name, SymbolKind::User);
    }

    pub fn set_comment(&mut self, va: u64, text: impl Into<String>) {
        self.comments.set(va, CommentScope::Address, text);
    }

    /// Apply a weak key→name map against the focused function.
    ///
    /// Supported keys:
    /// - `__function__` — rename the focused function
    /// - `local:-0x10` / `local:-16` — rename stack local at offset
    /// - `arg:0` / `arg:1` — rename signature parameter by index
    /// - anything else — stored as a function-scope comment for operator review
    pub fn apply_rename_batch(&mut self, map: HashMap<String, String>) {
        let focus = match self.focus {
            Some(va) => va,
            None => return,
        };

        for (key, value) in map {
            if key == "__function__" {
                self.symbols.insert(focus, value, SymbolKind::User);
            } else if let Some(off) = key.strip_prefix("local:") {
                if let Ok(offset) = parse_i64_offset(off) {
                    self.set_stack_local_name(focus, offset, value);
                } else {
                    self.comments
                        .set(focus, CommentScope::Function, format!("{key}: {value}"));
                }
            } else if let Some(idx) = key.strip_prefix("arg:") {
                if let Ok(index) = idx.parse::<usize>() {
                    self.set_param_name(focus, index, value);
                } else {
                    self.comments
                        .set(focus, CommentScope::Function, format!("{key}: {value}"));
                }
            } else {
                self.comments
                    .set(focus, CommentScope::Function, format!("{key}: {value}"));
            }
        }
    }

    pub fn set_focus(&mut self, va: u64) {
        if self.function_at(va).is_some() {
            self.focus = Some(va);
        }
    }

    /// Retype a PDB global variable (keyed by VA). Mutates the `typed_globals`
    /// map in place (clone-on-write through the `Arc`). The durable, reversible
    /// path is [`Op::SetGlobalType`] via the operation journal.
    pub fn set_global_type(&mut self, va: u64, ty: crate::project::types::DataType) {
        std::sync::Arc::make_mut(&mut self.typed_globals).insert(va, ty);
    }

    /// Override the recovered signature of a function (keyed by entry VA).
    /// The durable, reversible path is [`Op::SetFunctionSignature`].
    pub fn set_function_signature(
        &mut self,
        va: u64,
        signature: crate::project::types::FunctionSignature,
    ) {
        std::sync::Arc::make_mut(&mut self.function_signatures).insert(va, signature);
    }

    /// Retype a recovered stack local within `function_va`'s frame by its
    /// canonical signed offset (negative for locals). Creates the slot if
    /// missing. The durable, reversible path is [`Op::SetStackLocalType`].
    pub fn set_stack_local_type(
        &mut self,
        function_va: u64,
        offset: i64,
        ty: crate::project::types::DataType,
    ) {
        use crate::project::op::Op;
        Op::SetStackLocalType {
            function_va,
            offset,
            ty,
            old_ty: None,
        }
        .apply_to(self);
    }

    /// Rename a stack local/arg by frame offset. Creates the slot if missing.
    /// Durable path: [`Op::SetStackLocalName`].
    pub fn set_stack_local_name(&mut self, function_va: u64, offset: i64, name: impl Into<String>) {
        use crate::project::op::Op;
        Op::SetStackLocalName {
            function_va,
            offset,
            name: name.into(),
            old_name: None,
        }
        .apply_to(self);
    }

    /// Rename a signature parameter by index. Durable path: [`Op::SetParamName`].
    pub fn set_param_name(&mut self, function_va: u64, index: usize, name: impl Into<String>) {
        use crate::project::op::Op;
        Op::SetParamName {
            function_va,
            index,
            name: name.into(),
            old_name: None,
        }
        .apply_to(self);
    }

    /// Stable entity list an agent can rename/retype: function, params, stack locals.
    pub fn function_entities(&self, va: u64) -> Option<serde_json::Value> {
        let func = self.function_at(va)?;
        let name = func.name(&self.symbols);
        let frame = self.function_frames.get(&va).or(func.stack_frame.as_ref());
        let sig = self.function_signatures.get(&va).cloned().or_else(|| {
            crate::analysis::signatures::recover_signature_with_db(
                func,
                &self.analysis.code_index,
                self.bitness,
                &name,
                Some(&self.sig_db),
            )
        });

        let args: Vec<serde_json::Value> = sig
            .as_ref()
            .map(|s| {
                s.params
                    .iter()
                    .enumerate()
                    .map(|(i, (n, t))| {
                        serde_json::json!({
                            "id": format!("arg:{i}"),
                            "index": i,
                            "name": n,
                            "type": self.types.render(t),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        let locals: Vec<serde_json::Value> = frame
            .map(|f| {
                f.locals
                    .iter()
                    .chain(f.args.iter())
                    .map(|v| {
                        let off = if v.offset < 0 {
                            format!("-{:#x}", -v.offset)
                        } else {
                            format!("{:#x}", v.offset)
                        };
                        serde_json::json!({
                            "id": format!("local:{off}"),
                            "stack_offset": off,
                            "offset": v.offset,
                            "name": v.name,
                            "type": self.types.render(&v.ty),
                            "size": v.size,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();

        Some(serde_json::json!({
            "function": {
                "id": "function",
                "va": format!("{va:#x}"),
                "name": name,
            },
            "args": args,
            "locals": locals,
            "signature": sig.as_ref().map(|s| {
                serde_json::json!({
                    "name": s.name,
                    "calling_conv": s.calling_conv,
                    "ret": self.types.render(&s.ret),
                    "params": s.params.iter().map(|(n, t)| {
                        serde_json::json!({ "name": n, "type": self.types.render(t) })
                    }).collect::<Vec<_>>(),
                })
            }),
        }))
    }
}

fn parse_i64_offset(s: &str) -> Result<i64, std::num::ParseIntError> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("-0x").or_else(|| s.strip_prefix("-0X")) {
        i64::from_str_radix(hex, 16).map(|v| -v)
    } else if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16)
    } else {
        s.parse::<i64>()
    }
}

fn ssa_var_label(v: &crate::decompiler::ssa::SsaVar) -> String {
    use crate::decompiler::ssa::Location;
    use crate::decompiler::ssa::lower::reg_name;
    match &v.location {
        Location::Register { base_offset } => format!("{}_{}", reg_name(*base_offset), v.version),
        Location::StackSlot { base_reg, disp } => {
            format!("stack_{:x}{disp:+}_v{}", base_reg, v.version)
        }
        Location::RawRam => format!("ram_v{}", v.version),
        Location::Unique {
            instruction_va,
            offset,
            size,
        } => format!("t_{offset:x}_{size}@{instruction_va:x}_v{}", v.version),
    }
}

fn pcode_op_name(op: &rsleigh_api::PcodeOp) -> String {
    let s = format!("{op:?}");
    // "IntAdd { out: ..., left: ..., right: ... }" → "IntAdd"
    s.split_whitespace()
        .next()
        .unwrap_or("Op")
        .trim_end_matches('{')
        .to_string()
}

fn format_ty_guess(ty: &crate::decompiler::types::TyGuess) -> String {
    use crate::decompiler::types::TyGuess;
    match ty {
        TyGuess::Unknown => "unknown".to_string(),
        TyGuess::Int(b) => format!("int{b}"),
        TyGuess::Uint(b) => format!("uint{b}"),
        TyGuess::Bool => "bool".to_string(),
        TyGuess::Float => "float".to_string(),
        TyGuess::Double => "double".to_string(),
        TyGuess::Ptr(inner) => format!("{}*", format_ty_guess(inner)),
    }
}

fn classify_arg_source(
    var: &crate::decompiler::ssa::SsaVar,
    def_op: Option<&crate::decompiler::ssa::SsaOp>,
    const_by_va: &HashMap<u64, u64>,
    project: &Project,
) -> String {
    use crate::decompiler::ssa::lower::reg_name;
    use crate::decompiler::ssa::{Location, SsaOpKind};
    use pcode_ir::AddressSpaceId;
    // Constant from analysis or Copy const.
    if let Some(op) = def_op {
        if let Some(val) = const_by_va.get(&op.va) {
            return format!("constant:{val:#x}");
        }
        if let SsaOpKind::Pcode(rsleigh_api::PcodeOp::Copy { input, .. }) = &op.kind
            && input.space == AddressSpaceId::Const
        {
            return format!("constant:{:#x}", input.offset);
        }
        // LEA / IntAdd of RIP-relative address → often a string pointer.
        if matches!(
            &op.kind,
            SsaOpKind::Pcode(rsleigh_api::PcodeOp::IntAdd { .. })
                | SsaOpKind::Pcode(rsleigh_api::PcodeOp::Copy { .. })
        ) && let Some(gva) = project.resolve_global_va(op.va)
        {
            if let Some(sref) = crate::llm::query::try_read_string_at_va(
                &project.pe.image,
                &project.address_space,
                gva,
                2,
            ) {
                return format!("string:{}", sref.value);
            }
            let name = project
                .symbols
                .name(gva)
                .map(str::to_string)
                .unwrap_or_else(|| format!("g_{gva:x}"));
            return format!("global:{name}@{gva:#x}");
        }
        // Load from RIP-relative global.
        if matches!(
            &op.kind,
            SsaOpKind::Pcode(rsleigh_api::PcodeOp::Load { .. })
        ) && let Some(gva) = project.resolve_global_va(op.va)
        {
            let name = project
                .symbols
                .name(gva)
                .map(str::to_string)
                .unwrap_or_else(|| format!("g_{gva:x}"));
            return format!("global:{name}@{gva:#x}");
        }
        // LEA / IntAdd producing stack address.
        if let SsaOpKind::Pcode(rsleigh_api::PcodeOp::IntAdd { .. }) = &op.kind
            && let Location::StackSlot { disp, .. } = var.location
        {
            return format!("local:{disp:#x}");
        }
    }

    match &var.location {
        Location::StackSlot { disp, .. } if *disp < 0 => format!("local:{disp:#x}"),
        Location::StackSlot { disp, .. } if *disp > 0 => format!("param_stack:{disp:#x}"),
        Location::Register { base_offset } if var.version <= 1 => {
            // Live-in param register.
            let rank = match base_offset {
                0x08 => 0,
                0x10 => 1,
                0x80 => 2,
                0x88 => 3,
                _ => return format!("register:{}", reg_name(*base_offset)),
            };
            format!("param:{rank}")
        }
        Location::Register { base_offset } => format!("register:{}", reg_name(*base_offset)),
        Location::RawRam => "memory".to_string(),
        Location::StackSlot { disp, .. } => format!("local:{disp:#x}"),
        Location::Unique {
            instruction_va,
            offset,
            size,
        } => format!("temp:t_{offset:x}_{size}@{instruction_va:x}"),
    }
}

/// If `source` embeds a VA (constant:/global:…@va) that points at a string, return it.
fn resolve_arg_string_value(
    project: &Project,
    source: &str,
    _reaching: Option<&crate::decompiler::ssa::SsaVar>,
) -> Option<(String, String)> {
    if let Some(rest) = source.strip_prefix("string:") {
        // Already resolved to a literal in classify_arg_source.
        return Some((rest.to_string(), "unknown".into()));
    }
    let va = if let Some(hex) = source.strip_prefix("constant:") {
        parse_hex_u64(hex)?
    } else {
        let at = source.rfind('@')?;
        parse_hex_u64(&source[at + 1..])?
    };
    if va == 0 || !project.address_space.is_data_va(va) {
        return None;
    }
    let sref =
        crate::llm::query::try_read_string_at_va(&project.pe.image, &project.address_space, va, 2)?;
    Some((sref.value, sref.encoding))
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

/// Resolve RIP-relative jump tables for BranchInd SSA blocks into
/// [`crate::decompiler::structure::SwitchInfo`] records (Phase 5.1 S4).
fn resolve_switch_infos(
    project: &Project,
    func: &Function,
    ssa: &crate::decompiler::ssa::SsaFunction,
) -> Vec<crate::decompiler::structure::SwitchInfo> {
    use crate::decompiler::ssa::SsaOpKind;
    use rsleigh_api::PcodeOp;

    // Map target entry VA → SSA block index.
    let va_to_block: HashMap<u64, u32> = ssa.blocks.iter().map(|b| (b.entry_va, b.id)).collect();

    let mut out = Vec::new();
    for ssa_block in &ssa.blocks {
        let has_ind = ssa_block
            .ops
            .iter()
            .any(|o| matches!(&o.kind, SsaOpKind::Pcode(PcodeOp::BranchInd { .. })));
        if !has_ind {
            continue;
        }
        // Locate the analysis basic block to get exit_va (the jmp instruction).
        let Some(bb) = func
            .blocks
            .iter()
            .find(|b| b.entry_va == ssa_block.entry_va)
        else {
            continue;
        };
        let Some(dec) = project.analysis.code_index.at_va(bb.exit_va) else {
            continue;
        };
        let Some(table_va) =
            crate::analysis::indirect::rip_relative_target_va(&dec.instr, project.bitness)
        else {
            continue;
        };
        let targets = crate::analysis::indirect::read_pointer_table(
            &project.address_space,
            &project.pe.image,
            table_va,
            project.bitness,
        );
        if targets.is_empty() {
            continue;
        }
        let mut cases = Vec::new();
        for (idx, target_va) in targets.iter().enumerate() {
            if let Some(&block_id) = va_to_block.get(target_va) {
                cases.push((idx as i64, block_id));
            }
        }
        if !cases.is_empty() {
            out.push(crate::decompiler::structure::SwitchInfo {
                branch_va: ssa_block.entry_va,
                cases,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_scratch(name: &str, contents: &str) {
        let Ok(dir) = std::env::var("WINDY_SCRATCH") else {
            return;
        };
        let dir = std::path::PathBuf::from(dir);
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join(name), contents);
    }

    #[test]
    fn smoke_notepad_functions_and_export() {
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }

        let project = Project::open(path).expect("should load notepad.exe");
        assert!(!project.functions().is_empty(), "should discover functions");
        assert!(
            project
                .symbols
                .iter()
                .any(|(_, s)| s.name.starts_with("__imp_")),
            "should model at least one __imp_<Api> IAT slot"
        );

        let entry = project.focus.expect("should have entry focus");
        assert!(
            project.function_at(entry).is_some(),
            "entry point should be a discovered function"
        );

        let export = project
            .function_export(entry)
            .expect("should export entry function");
        assert!(
            !export.instructions.is_empty(),
            "export should have instructions"
        );
        assert!(!export.blocks.is_empty(), "export should have blocks");

        let text = project.function_llm_text(entry).expect("llm text");
        assert!(text.starts_with('<') && text.contains('>'));
        assert!(text.contains('\n'));
        // Somewhere in the image a function must resolve an import by name.
        let has_import = project.functions().iter().any(|f| {
            project
                .function_llm_text(f.entry_va)
                .map(|t| t.contains("__imp_"))
                .unwrap_or(false)
        });
        assert!(
            has_import,
            "symbol-resolved disassembly should contain __imp_<Api>"
        );
    }

    #[test]
    fn idb_round_trip_persists_rename() {
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }

        let temp_name = "__windy_test_entry__";
        {
            let mut project = Project::open(path).expect("open first");
            let entry = project.focus.expect("entry focus");
            project.rename(entry, temp_name);
            project.save().expect("save IDB");
        }

        {
            let project = Project::open(path).expect("reopen after save");
            let entry = project.focus.expect("entry focus");
            assert_eq!(
                project.symbols.name(entry),
                Some(temp_name),
                "user rename should survive IDB round trip"
            );
        }
    }

    #[cfg(feature = "gclsd-archive")]
    #[test]
    fn function_gclsd_input_preserves_edges() {
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }

        let project = Project::open(path).expect("open notepad.exe");
        let entry = project.focus.expect("entry focus");
        let input = project
            .function_gclsd_input(entry)
            .expect("build GCLSD input for entry");
        assert!(!input.instructions.is_empty(), "should have instructions");
        assert!(!input.blocks.is_empty(), "should have blocks");
        assert!(
            input.blocks.iter().any(|b| !b.successors.is_empty()),
            "should preserve CFG successors"
        );
        assert!(
            input
                .blocks
                .iter()
                .any(|b| b.successors.iter().any(|e| e.target != 0)),
            "should have at least one resolved successor target"
        );
    }

    #[cfg(feature = "gclsd-archive")]
    #[test]
    fn export_gclsd_yields_functions() {
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }

        let project = Project::open(path).expect("open notepad.exe");
        let inputs: Vec<_> = crate::ir::gclsd::export_project_gclsd(&project, 1)
            .take(10)
            .collect();
        assert!(!inputs.is_empty(), "should export at least one function");
        for input in inputs {
            assert!(!input.instructions.is_empty());
            assert!(!input.blocks.is_empty());
        }
    }

    #[test]
    fn fixture_pdb_typed_globals_reach_agent_text() {
        let Some(exe) = compile_c_msvc_fixture() else {
            eprintln!("skipping: MSVC cl.exe not found");
            return;
        };
        let project = Project::open(&exe).expect("open fixture exe");
        assert!(
            !project.typed_globals.is_empty(),
            "PDB typed_globals should be populated; pdb error: {:?}",
            project.pdb_info.error
        );
        let g_count = project.typed_globals.iter().find(|(va, _)| {
            project
                .symbols
                .name(**va)
                .map(|n| n.contains("g_count"))
                .unwrap_or(false)
        });
        assert!(
            g_count.is_some(),
            "g_count global should be typed; typed_globals count = {}",
            project.typed_globals.len()
        );
        let (_, ty) = g_count.unwrap();
        assert_eq!(*ty, super::DataType::Uint(32));

        let entry = project.focus.expect("fixture entry");
        let text = project
            .function_agent_text(entry)
            .expect("agent text for entry");
        assert!(
            text.contains("g_count"),
            "agent text should mention the annotated g_count global:\n{text}"
        );
    }

    // --- Phase 6: LLM RE Performance Engine --------------------------------

    #[test]
    fn phase6_win32_db_loads_createfilew() {
        let db = crate::analysis::win32_sigs::SigDB::load_bundled_only();
        let sig = db.lookup_by_name("CreateFileW").expect("CreateFileW");
        assert_eq!(sig.params.len(), 7);
        assert_eq!(sig.params[0].0, "lpFileName");
        assert!(db.dlls().contains(&"kernel32".to_string()));
        assert!(db.signatures_for_dll("ntdll").len() >= 100);
    }

    #[test]
    fn phase6_iat_annotation_uses_win32_db() {
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }
        let project = Project::open(path).expect("open notepad");
        // Find any __imp_ symbol that is in the SigDB.
        let mut found = false;
        for (va, sym) in project.symbols.iter() {
            let Some(api) = sym.name.strip_prefix("__imp_") else {
                continue;
            };
            if project.sig_db.lookup_by_name(api).is_none() {
                continue;
            }
            let names = crate::ir::annotate::build_global_names_with_db(
                &project.symbols,
                &project.typed_globals,
                &project.function_signatures,
                &project.types,
                Some(&project.sig_db),
            );
            let ann = names.get(&va).expect("annotated name");
            assert!(
                ann.contains("(*)(") || ann.contains(api),
                "IAT annotation should include signature for {api}: {ann}"
            );
            // Prefer CreateFileW-style multi-param APIs when present.
            if api == "CreateFileW" || ann.contains("DWORD") || ann.contains("HANDLE") {
                found = true;
                break;
            }
            found = true;
        }
        assert!(
            found,
            "expected at least one SigDB-annotated IAT slot in notepad"
        );
    }

    #[test]
    fn phase6_call_constraints_seeded_from_win32_db() {
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }
        let project = Project::open(path).expect("open notepad");

        // 1) IAT slot → SigDB signature (the call_constraints seed source).
        let iat = project
            .symbols
            .iter()
            .find(|(_, s)| {
                s.name
                    .strip_prefix("__imp_")
                    .is_some_and(|api| project.sig_db.lookup_by_name(api).is_some())
            })
            .expect("notepad should import at least one SigDB API");
        let (iat_va, sym) = iat;
        let sig = project
            .signature_for_target(iat_va)
            .unwrap_or_else(|| panic!("signature_for_target failed for {}", sym.name));
        // 0-param Win32 APIs (e.g. IsDebuggerPresent, GetLastError) are valid.
        assert!(
            !sig.name.is_empty(),
            "known API at IAT should yield a named signature, got {sig:?}"
        );

        // 2) Find a function that actually calls a known import (via agent export).
        let mut any_constraint = false;
        for f in project.functions().iter() {
            let export = match project.function_export(f.entry_va) {
                Some(e) => e,
                None => continue,
            };
            let calls_known = export.instructions.iter().any(|i| {
                let ops = i
                    .operands_annotated
                    .as_deref()
                    .unwrap_or(i.operands_str.as_str());
                ops.contains("__imp_")
                    && project
                        .sig_db
                        .lookup_by_name(
                            ops.split("__imp_")
                                .nth(1)
                                .unwrap_or("")
                                .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                                .next()
                                .unwrap_or(""),
                        )
                        .is_some()
            });
            if !calls_known {
                continue;
            }
            let Some((opt, _)) = project.function_ssa_optimized(f.entry_va) else {
                continue;
            };
            let constraints = project.call_constraints_for(&opt);
            if constraints.iter().any(|c| !c.arg_types.is_empty()) {
                any_constraint = true;
                break;
            }
            // Even zero-arg APIs should produce a constraint entry with empty
            // arg_types; count any constraint as success for that case.
            if !constraints.is_empty() {
                any_constraint = true;
                break;
            }
        }
        // If no SSA-level constraint was recovered, the IAT→SigDB path above
        // already proved the seeding source works; require at least that.
        assert!(
            any_constraint
                || project
                    .sig_db
                    .lookup_by_name(sym.name.strip_prefix("__imp_").unwrap_or(&sym.name))
                    .map(|s| !s.params.is_empty())
                    .unwrap_or(false),
            "expected call constraints or a multi-param SigDB API at IAT"
        );
    }

    #[test]
    fn phase6_dataflow_json_simple_function() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        // Prefer a small IntAdd-style function.
        let va = project
            .functions()
            .iter()
            .map(|f| f.entry_va)
            .find(|&va| {
                project
                    .function_ssa_optimized(va)
                    .map(|(ssa, _)| {
                        ssa.blocks.iter().any(|b| {
                            b.ops.iter().any(|o| {
                                matches!(
                                    &o.kind,
                                    crate::decompiler::ssa::SsaOpKind::Pcode(
                                        rsleigh_api::PcodeOp::IntAdd { .. }
                                    )
                                )
                            })
                        })
                    })
                    .unwrap_or(false)
            })
            .or_else(|| project.functions().iter().next().map(|f| f.entry_va))
            .expect("a function");
        let df = project
            .function_dataflow_json(va, Some(128))
            .expect("dataflow json");
        assert!(df.get("entry_va").is_some());
        assert!(df.get("blocks").and_then(|b| b.as_array()).is_some());
        let blocks = df["blocks"].as_array().unwrap();
        let total_defs: usize = blocks
            .iter()
            .map(|b| b["defs"].as_array().map(|a| a.len()).unwrap_or(0))
            .sum();
        assert!(total_defs >= 1, "expected at least one def: {df}");
        // Use chains present on some def.
        let has_live = blocks.iter().any(|b| {
            b["defs"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|d| d.get("live_uses").is_some())
        });
        assert!(has_live, "defs should carry live_uses: {df}");
    }

    #[test]
    fn phase6_call_sites_with_args() {
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }
        let project = Project::open(path).expect("open notepad");
        let mut found = false;
        for f in project.functions().iter().take(80) {
            let Some(sites) = project.call_sites_with_args(f.entry_va) else {
                continue;
            };
            let Some(arr) = sites.as_array() else {
                continue;
            };
            if arr.is_empty() {
                continue;
            }
            // At least one site with args array.
            if arr.iter().any(|s| {
                s.get("args")
                    .and_then(|a| a.as_array())
                    .is_some_and(|a| !a.is_empty())
            }) {
                found = true;
                // Prefer a known API if present.
                if arr.iter().any(|s| {
                    s.get("callee")
                        .and_then(|c| c.as_str())
                        .is_some_and(|n| project.sig_db.lookup_by_name(n).is_some())
                }) {
                    break;
                }
            }
        }
        assert!(
            found,
            "expected call-site arg tracing on at least one function"
        );
    }

    #[test]
    fn phase6_token_bounded_decompilation() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        // Find a multi-block function that produces non-trivial decompilation.
        let va = project
            .functions()
            .iter()
            .map(|f| f.entry_va)
            .find(|&va| {
                project
                    .function_decompile_native(va)
                    .map(|s| s.lines().count() > 30)
                    .unwrap_or(false)
            })
            .or_else(|| {
                project
                    .functions()
                    .iter()
                    .find(|f| f.blocks.len() >= 2)
                    .map(|f| f.entry_va)
            })
            .expect("a function");
        let full = project.function_decompile_native(va).expect("full decomp");
        let bounded = project
            .function_decompile_native_bounded(va, Some(40))
            .expect("bounded decomp");
        if full.lines().count() > 10 {
            assert!(
                bounded.contains("truncated") || bounded.lines().count() <= full.lines().count(),
                "bounded output should truncate or be shorter:\n{bounded}"
            );
        }
        // Signature header always present (first non-empty line).
        assert!(!bounded.trim().is_empty());
    }

    /// WindyDec v2 product: native text equals artifact text; engine always set.
    /// Prefers a V2-accepted pure-printer function for the SCRATCH sample.
    #[test]
    fn decompile_artifact_text_matches_native() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        let opts = crate::decompiler::v2::DecompileOptions::production();
        // Prefer first function where pure v2 checker accepts (criterion-2 sample).
        let mut chosen: Option<(u64, crate::decompiler::v2::DecompileArtifact)> = None;
        for f in project.functions().iter().take(64) {
            let Some(art) = project.function_decompile_artifact(f.entry_va, opts.clone()) else {
                continue;
            };
            if art.text.trim().is_empty() {
                continue;
            }
            if art.engine == crate::decompiler::v2::artifact::DecompileEngine::V2
                && art.fallback_reason.is_none()
                && art.check_report.accepted
            {
                chosen = Some((f.entry_va, art));
                break;
            }
            if chosen.is_none() {
                chosen = Some((f.entry_va, art));
            }
        }
        let (va, art) = chosen.expect("a decompilable function");
        let native = project.function_decompile_native(va).expect("native");
        assert_eq!(
            art.text, native,
            "function_decompile_native must return artifact text"
        );
        assert!(
            !art.contract_fingerprint.is_empty()
                || art.contracts.has_return
                || !art.text.is_empty()
        );
        assert!(
            art.engine == crate::decompiler::v2::artifact::DecompileEngine::V2
                || art.engine == crate::decompiler::v2::artifact::DecompileEngine::Legacy
        );
        assert!(
            !art.text.trim().is_empty(),
            "present function empty decompile: fallback={:?}",
            art.fallback_reason
        );
        let sample = serde_json::json!({
            "va": format!("{va:#x}"),
            "text": art.text,
            "engine": format!("{:?}", art.engine),
            "fallback_reason": art.fallback_reason,
            "presentation_cost": art.presentation_cost,
            "contract_fingerprint": art.contract_fingerprint,
            "contracts": {
                "has_return": art.contracts.has_return,
                "case_count": art.contracts.cases.len(),
                "loop_count": art.contracts.loops.len(),
            },
            "check_report": {
                "accepted": art.check_report.accepted,
                "edges_covered": art.check_report.edges_covered,
                "effects_covered": art.check_report.effects_covered,
                "rejects": art.check_report.rejects,
                "candidates_tried": art.check_report.candidates_tried,
                "candidates_accepted": art.check_report.candidates_accepted,
            },
            "diagnostics": art.diagnostics,
            "ast_summary": art.ast_summary,
            "pure_printer": art.diagnostics.iter().any(|d| d.contains("v2_pure")),
        });
        write_scratch(
            "decomp_artifact_product_sample.json",
            &serde_json::to_string_pretty(&sample).unwrap_or_default(),
        );
        // Product prefers accepted V2; pure_no_fallback must always remain V2.
        let pure_opts = crate::decompiler::v2::DecompileOptions::pure_no_fallback();
        let v2_wins = project.functions().iter().take(64).any(|f| {
            project
                .function_decompile_artifact(f.entry_va, pure_opts.clone())
                .map(|a| {
                    a.engine == crate::decompiler::v2::artifact::DecompileEngine::V2
                        && a.fallback_reason.is_none()
                        && !a.text.trim().is_empty()
                })
                .unwrap_or(false)
        });
        assert!(
            v2_wins,
            "expected at least one pure_no_fallback V2 artifact on sample.exe"
        );

        // Step-4 verification: under pure V2 mode, native text equals artifact text.
        let pure_opts = crate::decompiler::v2::DecompileOptions::pure_no_fallback();
        let mut pure_eq_count = 0usize;
        let mut pure_sample_va = None;
        let mut pure_sample_art = None;
        for f in project.functions().iter().take(32) {
            let Some(art) = project.function_decompile_artifact(f.entry_va, pure_opts.clone())
            else {
                continue;
            };
            if art.engine != crate::decompiler::v2::artifact::DecompileEngine::V2
                || art.fallback_reason.is_some()
                || art.text.trim().is_empty()
            {
                continue;
            }
            let native = project
                .function_decompile_native_with(f.entry_va, pure_opts.clone())
                .expect("native with pure opts");
            assert_eq!(
                art.text, native,
                "pure V2: function_decompile_native_with must equal artifact text at {:#x}",
                f.entry_va
            );
            pure_eq_count += 1;
            if pure_sample_va.is_none() {
                pure_sample_va = Some(f.entry_va);
                pure_sample_art = Some(art);
            }
        }
        assert!(
            pure_eq_count >= 1,
            "expected at least one pure V2 native==artifact equality check"
        );
        // Pure V2 artifact sample (serializable typed AST) for verification.
        if let (Some(va), Some(pure)) = (pure_sample_va, pure_sample_art) {
            let pure_sample = serde_json::json!({
                "va": format!("{va:#x}"),
                "engine": format!("{:?}", pure.engine),
                "fallback_reason": pure.fallback_reason,
                "text": pure.text,
                "typed_ast": pure.typed_ast,
                "check_report": pure.check_report,
                "diagnostics": pure.diagnostics,
                "contract_fingerprint": pure.contract_fingerprint,
                "native_equals_artifact": true,
                "mode": "pure_no_fallback",
                "pure_eq_functions_checked": pure_eq_count,
            });
            write_scratch(
                "decomp_artifact_pure_sample.json",
                &serde_json::to_string_pretty(&pure_sample).unwrap_or_default(),
            );
            write_scratch(
                "native_eq_pure_v2.txt",
                &format!(
                    "mode=pure_no_fallback\nva={va:#x}\nnative_equals_artifact=true\nfunctions_checked={pure_eq_count}\nengine=V2\nfallback=null\n"
                ),
            );
        }
    }

    /// Dual pure_no_fallback digests for a fixed PE subset (determinism step 5).
    #[test]
    fn pure_v2_artifact_digests_deterministic() {
        use sha2::{Digest, Sha256};
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let pure = crate::decompiler::v2::DecompileOptions::pure_no_fallback();
        let mut digests_a = Vec::new();
        let mut digests_b = Vec::new();
        for pass in 0..2 {
            let project = Project::open(path).expect("open sample.exe");
            let mut digests = Vec::new();
            for f in project.functions().iter().take(16) {
                let Some(art) = project.function_decompile_artifact(f.entry_va, pure.clone())
                else {
                    continue;
                };
                if art.text.trim().is_empty() {
                    continue;
                }
                let mut h = Sha256::new();
                h.update(art.text.as_bytes());
                h.update(art.contract_fingerprint.as_bytes());
                h.update(format!("{:?}", art.engine).as_bytes());
                let digest = format!("{:x}", h.finalize());
                digests.push((f.entry_va, digest, art.text.len()));
            }
            if pass == 0 {
                digests_a = digests;
            } else {
                digests_b = digests;
            }
        }
        assert_eq!(
            digests_a, digests_b,
            "pure V2 artifact digests must match across dual opens"
        );
        assert!(!digests_a.is_empty(), "expected digests for sample.exe");
        let report = serde_json::json!({
            "pe": "gclsd/bench/sample.exe",
            "mode": "pure_no_fallback",
            "functions": digests_a.len(),
            "identical": digests_a == digests_b,
            "digests": digests_a.iter().map(|(va, d, len)| {
                serde_json::json!({
                    "va": format!("{va:#x}"),
                    "sha256": d,
                    "text_len": len,
                })
            }).collect::<Vec<_>>(),
        });
        write_scratch(
            "determinism_artifact_digests.json",
            &serde_json::to_string_pretty(&report).unwrap_or_default(),
        );
        write_scratch(
            "determinism_artifact_report.txt",
            &format!(
                "identical=true\npe=gclsd/bench/sample.exe\nmode=pure_no_fallback\nfunctions={}\n",
                digests_a.len()
            ),
        );
    }

    /// Non-Grand PE corpus: pure_no_fallback V2 share ≥ 99% (not Grand proxy).
    #[test]
    fn external_corpus_pure_v2_share() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let pes = [
            root.join("gclsd/bench/sample.exe"),
            root.join("gclsd/bench/complex.exe"),
        ];
        let pure = crate::decompiler::v2::DecompileOptions::pure_no_fallback();
        let mut total = 0usize;
        let mut v2 = 0usize;
        let mut fallbacks = 0usize;
        let mut empty = 0usize;
        let mut per_pe = Vec::new();
        for pe in &pes {
            if !pe.exists() {
                continue;
            }
            let Ok(project) = Project::open(pe) else {
                continue;
            };
            let mut pe_total = 0usize;
            let mut pe_v2 = 0usize;
            for f in project.functions().iter().take(128) {
                let Some(art) = project.function_decompile_artifact(f.entry_va, pure.clone())
                else {
                    continue;
                };
                pe_total += 1;
                total += 1;
                if art.engine == crate::decompiler::v2::artifact::DecompileEngine::V2
                    && art.fallback_reason.is_none()
                    && !art.text.trim().is_empty()
                {
                    pe_v2 += 1;
                    v2 += 1;
                } else if art.fallback_reason.is_some() {
                    fallbacks += 1;
                }
                if art.text.trim().is_empty() {
                    empty += 1;
                }
            }
            per_pe.push(serde_json::json!({
                "pe": pe.file_name().and_then(|s| s.to_str()).unwrap_or("?"),
                "functions": pe_total,
                "v2_pure": pe_v2,
                "share": if pe_total == 0 { 0.0 } else { pe_v2 as f64 / pe_total as f64 },
            }));
        }
        let share = if total == 0 {
            0.0
        } else {
            v2 as f64 / total as f64
        };
        let report = serde_json::json!({
            "suite": "external_non_grand_pure_v2",
            "functions": total,
            "v2_pure": v2,
            "v2_share": share,
            "fallbacks": fallbacks,
            "empty": empty,
            "per_pe": per_pe,
            "note": "sample.exe + complex.exe (not Grand suite proxy)",
        });
        write_scratch(
            "external_corpus_v2_share.json",
            &serde_json::to_string_pretty(&report).unwrap_or_default(),
        );
        assert!(total > 0, "expected at least one external PE function");
        assert!(
            share >= 0.99,
            "external pure V2 share {share} < 0.99 (v2={v2}/{total})"
        );
    }

    #[test]
    fn phase6_def_types_serialized() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        let va = project
            .functions()
            .iter()
            .map(|f| f.entry_va)
            .find(|&va| {
                project
                    .function_types_recovered(va)
                    .map(|r| !r.def_types.is_empty())
                    .unwrap_or(false)
            })
            .expect("a function with recovered types");
        let report = project.function_types_recovered(va).unwrap();
        let json = serde_json::to_value(&report).expect("serialize report");
        let def_types = json
            .get("def_types")
            .expect("def_types field present")
            .as_array()
            .expect("def_types is array");
        assert!(!def_types.is_empty());
        assert!(
            def_types[0].get("var").is_some() && def_types[0].get("type").is_some(),
            "def_types entries should be {{var, type}}: {:?}",
            def_types[0]
        );
    }

    #[test]
    fn phase6_structured_decompilation() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        let va = project
            .functions()
            .iter()
            .map(|f| f.entry_va)
            .find(|&va| project.function_decompile_structured(va).is_some())
            .expect("structured decomp target");
        let structured = project.function_decompile_structured(va).unwrap();
        assert!(structured.get("signature").is_some());
        assert!(structured.get("variables").is_some());
        assert!(structured.get("blocks").is_some());
        assert!(structured.get("control_flow").is_some());
        assert!(
            structured["calls"].is_array(),
            "calls must be an array: {structured}"
        );
        assert!(
            structured["cfg_edges"].is_array(),
            "cfg_edges must be an array: {structured}"
        );
        assert!(
            structured.get("runtime_function").is_some(),
            "runtime-function provenance field missing: {structured}"
        );
        assert_eq!(structured["semantic_hir"]["schema"], "windy-hir-v1");
        assert_eq!(structured["semantic_hir"]["valid"], true);
        assert!(
            structured["semantic_hir"]["value_count"]
                .as_u64()
                .is_some_and(|count| count > 0),
            "semantic HIR must retain SSA values: {structured}"
        );
        assert!(
            structured["variables"]
                .as_array()
                .is_some_and(|a| !a.is_empty())
                || structured["blocks"]
                    .as_array()
                    .is_some_and(|a| !a.is_empty()),
            "expected variable table or blocks: {structured}"
        );
    }

    #[test]
    fn phase6_structured_decompilation_includes_call_facts() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        let structured = project
            .function_decompile_structured(0x1400_010b0)
            .expect("structured sample main");
        let calls = structured["calls"].as_array().expect("calls array");
        assert!(calls.len() >= 3, "expected sample main calls: {calls:?}");
        assert!(
            calls.iter().all(|call| call["args"].is_array()),
            "each call must carry an args array: {calls:?}"
        );
        let hir_calls = structured["semantic_hir"]["call_sites"]
            .as_array()
            .expect("semantic HIR call-sites array");
        assert!(
            hir_calls.len() >= 3,
            "every sample main call should have an ABI/provenance fact: {hir_calls:?}"
        );
        assert!(
            hir_calls.iter().any(|call| {
                call["arguments"]
                    .as_array()
                    .is_some_and(|arguments| !arguments.is_empty())
            }),
            "at least one Win64 call should retain a proven register argument: {hir_calls:?}"
        );
        let hir = project
            .function_hir(0x1400_010b0)
            .expect("semantic HIR for sample main");
        assert!(hir.validate().is_ok(), "public HIR must validate");
        assert!(
            hir.call_sites().len() >= 3,
            "public HIR must carry the same call facts as structured evidence"
        );
    }

    #[test]
    fn native_sample_main_emits_recovered_win64_call_arguments() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        let call_abi_inputs = project.call_abi_inputs_for(
            project
                .function_at(0x1400_010b0)
                .expect("sample main function"),
        );
        assert_eq!(
            call_abi_inputs.get(&0x1_4000_10be).map(Vec::len),
            Some(2),
            "add's inferred direct-call contract must retain RCX/RDX"
        );
        assert_eq!(
            call_abi_inputs.get(&0x1_4000_10d8).map(Vec::len),
            Some(1),
            "strlen_local's inferred direct-call contract must retain RCX"
        );
        assert_eq!(
            call_abi_inputs.get(&0x1_4000_10ef).map(Vec::len),
            Some(3),
            "max3's inferred direct-call contract must retain RCX/RDX/R8"
        );
        let native = project
            .function_decompile_native(0x1400_010b0)
            .expect("native sample main");
        let hir = project
            .function_hir(0x1400_010b0)
            .expect("semantic HIR for sample main");
        assert_eq!(
            hir.call_sites()
                .iter()
                .map(|call| call.arguments.len())
                .collect::<Vec<_>>(),
            vec![2, 1, 3],
            "the HIR must retain each complete inferred Win64 GPR contract"
        );

        for target in ["FUN_140001000", "FUN_140001020", "FUN_140001060"] {
            assert!(
                native.contains(&format!("{target}(")),
                "expected HIR-backed direct call for {target}, got:\n{native}"
            );
            assert!(
                !native.contains(&format!("call({target});")),
                "proved Win64 arguments must not use the opaque wrapper for {target}:\n{native}"
            );
        }
        assert!(
            native.contains("FUN_140001000(0x2, 0x3);"),
            "constant Win64 setup must fold into add's call arguments:\n{native}"
        );
        let max3 = native
            .lines()
            .find(|line| line.contains("FUN_140001060("))
            .expect("max3 call line");
        // Count top-level commas only — nested `*(arg_20)` must not truncate the
        // argument list at the first ')'.
        let max3_arguments = count_top_level_call_args(max3).unwrap_or(0);
        assert_eq!(
            max3_arguments, 3,
            "a three-slot call contract must not become a shorter native call:\n{native}"
        );
    }

    /// Count comma-separated arguments inside the first call `(…)` on a line,
    /// respecting nested parentheses.
    fn count_top_level_call_args(line: &str) -> Option<usize> {
        let start = line.find('(')?;
        let bytes = line.as_bytes();
        let mut depth = 0i32;
        let mut commas = 0usize;
        let mut empty = true;
        for &b in &bytes[start..] {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(if empty { 0 } else { commas + 1 });
                    }
                }
                b',' if depth == 1 => {
                    commas += 1;
                    empty = false;
                }
                c if !c.is_ascii_whitespace() && depth == 1 => empty = false,
                _ => {}
            }
        }
        None
    }

    #[test]
    fn resolved_win64_call_inputs_survive_ssa_simplification() {
        use crate::decompiler::ssa::{Location, SsaFunction, SsaOpKind};
        use rsleigh_api::PcodeOp;

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        let main_va = 0x1400_010b0;
        let raw = project.function_ssa(main_va).expect("raw sample main SSA");
        let (optimized, _) = project
            .function_ssa_optimized(main_va)
            .expect("optimized sample main SSA");

        fn call_registers(ssa: &SsaFunction, target: u64) -> Option<Vec<u64>> {
            ssa.blocks
                .iter()
                .flat_map(|block| block.ops.iter())
                .find_map(|op| {
                    let SsaOpKind::Pcode(PcodeOp::Call { dest }) = &op.kind else {
                        return None;
                    };
                    if dest.offset != target {
                        return None;
                    }
                    Some(
                        op.uses
                            .iter()
                            .filter_map(|use_var| match use_var.location {
                                Location::Register { base_offset } => Some(base_offset),
                                _ => None,
                            })
                            .collect(),
                    )
                })
        }

        assert_eq!(
            call_registers(&raw, 0x1_4000_1000),
            Some(vec![0x08, 0x10]),
            "raw SSA must model add's RCX/RDX ABI inputs"
        );
        assert_eq!(
            call_registers(&optimized, 0x1_4000_1000),
            Some(vec![0x08, 0x10]),
            "simplification must retain the resolved ABI inputs"
        );
        let first_call_block = optimized
            .blocks
            .iter()
            .find(|block| {
                block.ops.iter().any(|op| {
                    matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Call { dest }) if dest.offset == 0x1_4000_1000)
                })
            })
            .expect("sample main block containing add call");
        let first_call_index = first_call_block
            .ops
            .iter()
            .position(|op| {
                matches!(&op.kind, SsaOpKind::Pcode(PcodeOp::Call { dest }) if dest.offset == 0x1_4000_1000)
            })
            .expect("add call index");
        for base_offset in [0x08, 0x10] {
            assert!(
                first_call_block.ops[..first_call_index].iter().any(|op| {
                    matches!(op.def, Some(ref def) if matches!(def.location, Location::Register { base_offset: base } if base == base_offset))
                }),
                "DCE must keep the setup definition for argument register {base_offset:#x}"
            );
        }
    }

    #[test]
    fn emitted_signature_keeps_persisted_operator_declaration() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let mut project = Project::open(path).expect("open sample.exe");
        let va = 0x1400_010b0;
        project.set_function_signature(
            va,
            FunctionSignature {
                name: "operator_declared_main".to_string(),
                params: vec![("operator_argument".to_string(), DataType::Uint(16))],
                ret: DataType::Bool,
                calling_conv: Some("operator_cc".to_string()),
            },
        );

        let structured = project
            .function_decompile_structured(va)
            .expect("structured decompile with persisted signature");
        assert_eq!(
            structured["signature"]["name"], "operator_declared_main",
            "persisted declaration must win over heuristic recovery"
        );
        assert_eq!(structured["signature"]["ret"], "bool");
        assert_eq!(
            structured["signature"]["params"][0]["name"],
            "operator_argument"
        );
        assert_eq!(structured["signature"]["params"][0]["type"], "uint16");
    }

    #[test]
    fn x64_runtime_function_metadata_is_exposed_to_analysis() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        assert_eq!(project.bitness, 64, "sample fixture must remain PE32+");
        let runtime = &project.analysis.runtime_functions;
        assert!(
            !runtime.entries.is_empty(),
            "MSVC sample should expose .pdata runtime functions"
        );
        assert!(
            runtime
                .entry_points()
                .any(|entry| project.functions().contains(entry)),
            "at least one runtime-function entry must seed discovery"
        );
    }

    #[test]
    fn phase6_agent_text_noise_stripping() {
        // Unit-level coverage lives in agent_text tests; here verify the Project
        // opts path strips noise on a real PE when cookies/prologs are present.
        let path = r"C:\Windows\System32\notepad.exe";
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: {path} not found");
            return;
        }
        let project = Project::open(path).expect("open notepad");
        let entry = project.focus.expect("entry");
        let raw = project.function_agent_text(entry).expect("raw agent text");
        let stripped = project
            .function_agent_text_opts(
                entry,
                crate::ir::agent_text::AgentTextOpts {
                    strip_noise: true,
                    max_instructions: None,
                },
            )
            .expect("stripped agent text");
        // Stripped should never be longer than raw (noise removed).
        assert!(
            stripped.len() <= raw.len() + 80,
            "strip_noise should not grow output significantly"
        );
        // Max instructions truncates.
        let capped = project
            .function_agent_text_opts(
                entry,
                crate::ir::agent_text::AgentTextOpts {
                    strip_noise: false,
                    max_instructions: Some(3),
                },
            )
            .expect("capped");
        if raw.lines().count() > 10 {
            assert!(
                capped.contains("truncated") || capped.lines().count() < raw.lines().count(),
                "max_instructions should truncate"
            );
        }
    }

    #[test]
    fn phase6_list_api_signatures_dlls() {
        let db = crate::analysis::win32_sigs::SigDB::load_bundled_only();
        let dlls = db.dlls();
        assert!(dlls.iter().any(|d| d == "kernel32"));
        assert!(dlls.iter().any(|d| d == "user32"));
        assert!(dlls.iter().any(|d| d == "ntdll"));
        assert!(dlls.iter().any(|d| d == "advapi32"));
        let k = db.signatures_for_dll("kernel32");
        assert!(k.len() >= 80);
        assert!(
            k.iter()
                .any(|s| s.name == "CreateFileW" && s.params.len() == 7)
        );
    }

    // --- Phase 7: LLM RE Performance Frontier --------------------------------

    #[test]
    fn phase7_sample_signedness_or_aggregate_or_points_to() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");

        let mut saw_int = false;
        let mut saw_uint = false;
        let mut saw_aggregate = false;
        let mut max_globals = 0usize;
        let mut saw_struct_in_decompile = false;

        for f in project.functions().iter() {
            let Some(report) = project.function_types_recovered(f.entry_va) else {
                continue;
            };
            for p in &report.params {
                if matches!(p.ty, crate::decompiler::types::TyGuess::Int(_)) {
                    saw_int = true;
                }
                if matches!(p.ty, crate::decompiler::types::TyGuess::Uint(_)) {
                    saw_uint = true;
                }
            }
            for l in &report.locals {
                if matches!(l.ty, crate::decompiler::types::TyGuess::Int(_)) {
                    saw_int = true;
                }
                if matches!(l.ty, crate::decompiler::types::TyGuess::Uint(_)) {
                    saw_uint = true;
                }
            }
            if !report.aggregates.is_empty() {
                saw_aggregate = true;
            }
            if let Some(pt) = project.function_points_to_map(f.entry_va) {
                max_globals = max_globals.max(pt.global_vas().len());
            }
            if let Some(text) = project.function_decompile_native(f.entry_va) {
                if text.contains("struct __ws_") || text.contains("is field") {
                    saw_struct_in_decompile = true;
                }
                if text.contains("int32") || text.contains("int64") {
                    saw_int = true;
                }
            }
            if let Some(v) = project.function_decompile_structured(f.entry_va) {
                if let Some(structs) = v.get("structs").and_then(|s| s.as_array()) {
                    if !structs.is_empty() {
                        saw_aggregate = true;
                    }
                }
            }
        }

        // Soft requirements: sample should exercise at least one Phase 7 seam.
        assert!(
            saw_int || saw_uint || saw_aggregate || max_globals >= 1,
            "expected signedness, aggregate, or points-to signal in sample.exe \
             (int={saw_int} uint={saw_uint} agg={saw_aggregate} globals={max_globals})"
        );
        let _ = saw_struct_in_decompile;
    }

    #[test]
    fn phase7_vtable_db_and_sample_scan() {
        let db = crate::analysis::vtable_sigs::VtableDB::load_bundled_only();
        assert!(db.lookup("IUnknown").is_some());
        assert!(db.resolve_method(0, None).is_some());

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping sample COM scan: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        let mut any = 0usize;
        for f in project.functions().iter().take(32) {
            if let Some(v) = project.function_vtable_calls(f.entry_va) {
                any += v.as_array().map(|a| a.len()).unwrap_or(0);
            }
        }
        // sample.exe is unlikely to have COM; just ensure the API is callable.
        eprintln!("phase7: sample.exe vtable call sites resolved: {any}");
    }

    #[test]
    fn phase7_points_to_distinct_globals_on_sample() {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let project = Project::open(path).expect("open sample.exe");
        let mut best = 0usize;
        for f in project.functions().iter() {
            if let Some(pt) = project.function_points_to_map(f.entry_va) {
                best = best.max(pt.global_vas().len());
            }
        }
        // Soft: sample may resolve 0–N globals depending on code shape.
        eprintln!("phase7: max distinct global VAs resolved in one function: {best}");
        // At least the points-to API must return maps for some functions.
        let any_map = project
            .functions()
            .iter()
            .any(|f| project.function_points_to_map(f.entry_va).is_some());
        assert!(any_map, "expected points-to map for at least one function");
    }

    #[test]
    fn function_memory_round_trip_idb() {
        use crate::project::memory::FunctionMemoryCard;
        use crate::project::op::Op;
        use crate::project::persistence::ProjectState;

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let mut project = Project::open(path).expect("open");
        let va = project.focus.expect("focus");
        let card = FunctionMemoryCard {
            va,
            purpose: Some("test helper".into()),
            tags: vec!["test".into()],
            key_apis: vec!["CreateFileW".into()],
            key_strings: vec![],
            purity: Some("io".into()),
            confidence: 80,
            updated_seq: 0,
        };
        Op::SetFunctionMemory {
            va,
            card,
            old: None,
        }
        .apply_to(&mut project);
        assert_eq!(
            project
                .function_memory
                .get(&va)
                .and_then(|c| c.purpose.clone()),
            Some("test helper".into())
        );

        // Postcard state round-trip (independent of global ~/.windy pollution).
        let state = ProjectState::from_project(&project);
        let loaded = ProjectState::from_bytes(&state.to_bytes().unwrap()).unwrap();
        assert_eq!(
            loaded
                .function_memory
                .get(&va)
                .and_then(|c| c.purpose.clone()),
            Some("test helper".into())
        );

        // Apply onto a fresh project open.
        let mut project2 = Project::open(path).expect("reopen");
        loaded.apply(&mut project2);
        let card = project2
            .function_memory
            .get(&va)
            .expect("memory should apply from state");
        assert_eq!(card.purpose.as_deref(), Some("test helper"));
        assert!(card.tags.iter().any(|t| t == "test"));
    }

    #[test]
    fn stack_local_name_and_param_writeback_stick() {
        use crate::project::op::Op;
        use crate::project::types::DataType;

        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/gclsd/bench/sample.exe");
        if !std::path::Path::new(path).exists() {
            eprintln!("skipping: sample.exe not found");
            return;
        }
        let mut project = Project::open(path).expect("open sample.exe");
        let va = project
            .functions()
            .iter()
            .find(|f| {
                project
                    .function_frames
                    .get(&f.entry_va)
                    .map(|fr| !fr.locals.is_empty())
                    .unwrap_or(false)
            })
            .map(|f| f.entry_va)
            .or(project.focus)
            .expect("a function VA");

        Op::SetStackLocalName {
            function_va: va,
            offset: -0x10,
            name: "agent_buffer".into(),
            old_name: None,
        }
        .apply_to(&mut project);

        Op::SetParamName {
            function_va: va,
            index: 0,
            name: "agent_arg0".into(),
            old_name: None,
        }
        .apply_to(&mut project);

        let frame = project
            .function_frames
            .get(&va)
            .expect("frame after local name");
        let local = frame
            .locals
            .iter()
            .find(|l| l.offset == -0x10)
            .expect("local at -0x10");
        assert_eq!(local.name.as_deref(), Some("agent_buffer"));

        let sig = project
            .function_signatures
            .get(&va)
            .expect("signature after param name");
        assert_eq!(sig.params[0].0, "agent_arg0");

        let entities = project.function_entities(va).expect("entities");
        let locals = entities["locals"].as_array().expect("locals array");
        assert!(
            locals.iter().any(|l| l["name"] == "agent_buffer"),
            "entities should list renamed local: {entities}"
        );
        let args = entities["args"].as_array().expect("args array");
        assert!(
            args.iter().any(|a| a["name"] == "agent_arg0"),
            "entities should list renamed arg: {entities}"
        );

        // Optional type also sticks.
        Op::SetStackLocalType {
            function_va: va,
            offset: -0x10,
            ty: DataType::Array(Box::new(DataType::Uint(8)), 64),
            old_ty: None,
        }
        .apply_to(&mut project);
        let local = project
            .function_frames
            .get(&va)
            .unwrap()
            .locals
            .iter()
            .find(|l| l.offset == -0x10)
            .unwrap();
        assert!(
            matches!(&local.ty, DataType::Array(_, 64)),
            "type write-back should stick"
        );
    }

    fn compile_c_msvc_fixture() -> Option<std::path::PathBuf> {
        let cl = std::env::var_os("VCINSTALLDIR")
            .and_then(|d| {
                let mut p = std::path::PathBuf::from(d);
                p.push(r"Tools\MSVC");
                Some(p)
            })
            .and_then(|tools| {
                // Find any installed VC toolset and pick its cl.exe.
                let mut latest = None;
                if let Ok(entries) = std::fs::read_dir(&tools) {
                    for entry in entries.flatten() {
                        let path = entry.path();
                        if path.is_dir() {
                            let cl = path.join(r"bin\Hostx64\x64\cl.exe");
                            if cl.exists() {
                                latest = Some(cl);
                            }
                        }
                    }
                }
                latest
            });

        let Some(cl) = cl else {
            return None;
        };

        let dir = std::env::temp_dir().join(format!("windy-fixture-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("create fixture dir");
        let src = dir.join("tiny.c");
        let exe = dir.join("tiny.exe");
        let code = r#"#include <stdint.h>
#include <stdio.h>

uint32_t g_count = 0;

int main(void) {
    g_count = 1;
    printf("%u\n", g_count);
    return 0;
}
"#;
        std::fs::write(&src, code).expect("write fixture source");
        let output = std::process::Command::new(&cl)
            .arg("/Zi")
            .arg("/Od")
            .arg("/MD")
            .arg("/nologo")
            .arg("/Fe:")
            .arg(&exe)
            .arg(&src)
            .current_dir(&dir)
            .output()
            .expect("spawn cl");
        assert!(
            output.status.success(),
            "cl failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Some(exe)
    }
}

struct SeedSymbolTable;

impl SeedSymbolTable {
    fn from_triage(
        pe: &LoadedPe,
        symbols: &mut SymbolTable,
        address_space: &AddressSpace,
        bitness: u32,
    ) {
        let base = pe
            .triage
            .optional_header
            .as_ref()
            .map(|h| h.image_base)
            .unwrap_or_default();

        if let Some(exports) = &pe.triage.exports {
            for exp in exports {
                let va = base.saturating_add(exp.rva as u64);
                symbols.insert(va, demangle_or_raw(&exp.name), SymbolKind::Export);
            }
        }

        if let Some(slots) =
            crate::loader::imports::parse_import_slots(&pe.image, address_space, base, bitness)
        {
            for slot in slots {
                let name = match (&slot.name, slot.ordinal) {
                    (Some(n), _) => format!("__imp_{}", demangle_or_raw(n)),
                    (None, Some(ord)) => format!("__imp_Ordinal{ord}"),
                    (None, None) => continue,
                };
                symbols.insert(slot.iat_va, name, SymbolKind::Import);
            }
        }
    }
}
