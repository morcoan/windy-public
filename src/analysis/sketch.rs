//! Compact function sketches for behavior-first agent retrieval.
//!
//! A sketch is deliberately lossy: it retains structural facts and semantic
//! motifs while discarding decoded instruction objects. The v0.3 query VM uses
//! these facts to shortlist functions before requesting expensive evidence.

use std::collections::BTreeSet;
use std::collections::HashMap;

use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::project::Project;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FunctionSketch {
    pub va: u64,
    pub size: u64,
    pub blocks: usize,
    pub instructions: usize,
    pub loops: usize,
    pub conditional_branches: usize,
    pub direct_calls: Vec<u64>,
    pub returns: usize,
    pub memory_ops: usize,
    pub byte_memory_ops: usize,
    pub global_writes: usize,
    pub adds: usize,
    pub subtracts: usize,
    pub multiplies: usize,
    pub xors: usize,
    pub zero_tests: usize,
    pub constants: Vec<u64>,
    pub motifs: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct RankedSketch {
    pub va: String,
    pub score: u32,
    pub evidence: Vec<String>,
    pub sketch: FunctionSketch,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SketchImage {
    pub sketches: Vec<FunctionSketch>,
    pub decoded_instructions: usize,
    #[serde(default)]
    pub candidate_limit_reached: bool,
    #[serde(default)]
    pub candidate_limit: usize,
    pub elapsed_ms: u128,
    #[serde(default)]
    pub cache_hit: bool,
}

/// Maximum function summaries retained in RAM by the compact path. Whole-image
/// instruction coverage remains available through the disk-backed deep index;
/// arbitrary addresses can be decoded with [`sketch_at_path`].
pub const MAX_RESIDENT_SKETCHES: usize = 65_536;

pub fn sketches(project: &Project) -> &[FunctionSketch] {
    project
        .analysis
        .function_sketches
        .get_or_init(|| build(project))
}

pub fn at_va(project: &Project, va: u64) -> Option<&FunctionSketch> {
    sketches(project).iter().find(|sketch| sketch.va == va)
}

pub fn rank(project: &Project, query: &str, limit: usize) -> Vec<RankedSketch> {
    rank_sketches(sketches(project), query, limit)
}

pub fn rank_sketches(sketches: &[FunctionSketch], query: &str, limit: usize) -> Vec<RankedSketch> {
    let query = normalize(query);
    let address_constraint = query
        .split(|character: char| !(character.is_ascii_hexdigit() || matches!(character, 'x' | 'X')))
        .find_map(|token| {
            token
                .strip_prefix("0x")
                .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        });
    let wants_crypto = contains_any(&query, &["aes", "gcm", "encrypt", "cryptographic"]);
    let by_va: HashMap<_, _> = sketches.iter().map(|sketch| (sketch.va, sketch)).collect();
    let mut ranked = Vec::new();
    for sketch in sketches {
        if address_constraint.is_some_and(|address| address != sketch.va) {
            continue;
        }
        let mut score = 0u32;
        let mut evidence = Vec::new();
        if address_constraint == Some(sketch.va) {
            score = 1_000;
            evidence.push("constraint:exact_address".to_string());
        }
        for motif in &sketch.motifs {
            let matched = match motif.as_str() {
                "nul_terminated_byte_loop" => contains_any(
                    &query,
                    &[
                        "nul",
                        "null terminated",
                        "cstring",
                        "character count",
                        "string length",
                    ],
                ),
                "bounded_select" => contains_any(&query, &["clamp", "bounded", "lower", "upper"]),
                "xor_multiply_hash" => {
                    contains_any(&query, &["hash", "xor", "multiply", "byte processing"])
                }
                "arithmetic_dispatch" => contains_any(
                    &query,
                    &["dispatcher", "dispatch", "add subtract", "arithmetic"],
                ),
                "conditional_call_pipeline" => contains_any(
                    &query,
                    &[
                        "pipeline",
                        "decoder",
                        "validator",
                        "sink",
                        "conditionally",
                        "directly calls both",
                    ],
                ),
                "linked_list_accumulator" => contains_any(
                    &query,
                    &["linked list", "next pointer", "node", "accumulating"],
                ),
                "pair_dot_product" => {
                    contains_any(&query, &["dot product", "two field", "two structures"])
                }
                _ => false,
            };
            if matched {
                score += 100;
                evidence.push(format!("motif:{motif}"));
                if motif == "nul_terminated_byte_loop" {
                    // A strlen-shaped leaf performs one byte load/test per
                    // iteration and is normally tiny.  Prefer that shape over
                    // larger parser/runtime loops that merely contain a byte
                    // loop somewhere in the function.
                    if sketch.byte_memory_ops == 1 && sketch.zero_tests == 1 {
                        score += 32;
                        evidence.push("constraint:single_byte_scan".to_string());
                    }
                    if sketch.instructions <= 32 && sketch.blocks <= 5 {
                        score += 24;
                        evidence.push("constraint:compact_leaf".to_string());
                    }
                }
                if motif == "bounded_select" && sketch.returns >= 2 && sketch.memory_ops == 0 {
                    score += 48;
                    evidence.push("constraint:pure_two_bound_select".to_string());
                }
                if motif == "linked_list_accumulator"
                    && sketch.blocks == 3
                    && sketch.zero_tests == 1
                    && sketch.instructions <= 32
                {
                    score += 32;
                    evidence.push("constraint:compact_single_loop".to_string());
                }
                if motif == "linked_list_accumulator"
                    && sketch.global_writes == 0
                    && sketch.direct_calls.is_empty()
                {
                    score += 24;
                    evidence.push("constraint:side_effect_free_pointer_walk".to_string());
                }
                if motif == "linked_list_accumulator" && sketch.adds >= 2 && sketch.memory_ops >= 3
                {
                    score += 20;
                    evidence.push("constraint:load_accumulate_advance".to_string());
                }
            }
        }
        if contains_any(&query, &["call", "caller", "reach", "pipeline"])
            && !sketch.direct_calls.is_empty()
        {
            let distance_from_three = sketch.direct_calls.len().abs_diff(3).min(3) as u32;
            score += 24u32.saturating_sub(distance_from_three * 8);
            evidence.push(format!("direct_calls:{}", sketch.direct_calls.len()));
        }
        if contains_any(&query, &["sink", "global writing", "global-writing"])
            && sketch.direct_calls.iter().any(|callee| {
                by_va
                    .get(callee)
                    .is_some_and(|value| value.global_writes > 0)
            })
        {
            score += 80;
            evidence.push("verified_callee:global_write".to_string());
        }
        if contains_any(&query, &["pipeline", "decoder", "validator", "sink"])
            && (2..=4).contains(&sketch.direct_calls.len())
        {
            let callees: Option<Vec<_>> = sketch
                .direct_calls
                .iter()
                .map(|callee| by_va.get(callee).copied())
                .collect();
            if let Some(callees) = callees
                && callees.iter().all(|callee| callee.direct_calls.is_empty())
                && callees.iter().any(|callee| callee.global_writes > 0)
                && callees.iter().any(|callee| callee.global_writes == 0)
            {
                // A real decode -> validate -> sink coordinator points at a
                // compact set of leaf stages, one of which owns the terminal
                // global write. Runtime helpers often look superficially
                // similar but call other coordinators instead of leaf stages.
                score += 160;
                evidence.push("verified_graph:leaf_stage_chain".to_string());
            }
        }
        if contains_any(&query, &["caller", "pipeline", "decoder", "validator"])
            && sketch
                .motifs
                .iter()
                .any(|motif| motif == "conditional_call_pipeline")
            && sketch.global_writes == 0
        {
            // A coordinator delegates the terminal write to its sink.  A
            // candidate that writes globals itself is more likely one of the
            // pipeline stages than the caller tying those stages together.
            score += 16;
            evidence.push("constraint:delegating_orchestrator".to_string());
            if sketch.instructions <= 32 && sketch.memory_ops <= 8 {
                score += 24;
                evidence.push("constraint:compact_coordinator".to_string());
            }
        }
        if contains_any(&query, &["loop", "walk", "traverse"]) && sketch.loops > 0 {
            score += 12;
            evidence.push(format!("loops:{}", sketch.loops));
        }
        if contains_any(&query, &["byte", "string"]) && sketch.byte_memory_ops > 0 {
            score += 8;
            evidence.push(format!("byte_memory_ops:{}", sketch.byte_memory_ops));
        }
        if wants_crypto {
            // Do not turn generic XOR/multiply code into cryptographic support.
            // Concrete AES/GCM APIs, strings, or instruction semantics belong
            // to deeper evidence; sketches honestly return no match.
            score = 0;
            evidence.clear();
        }
        if score > 0 {
            ranked.push(RankedSketch {
                va: format!("{:#x}", sketch.va),
                score,
                evidence,
                sketch: sketch.clone(),
            });
        }
    }
    ranked.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.sketch.va.cmp(&right.sketch.va))
    });
    ranked.truncate(limit.clamp(1, 8));
    ranked
}

pub fn load_or_build_cached(
    path: &std::path::Path,
    cache_root: &std::path::Path,
    image_sha256: &str,
    bitness: u32,
) -> anyhow::Result<SketchImage> {
    let started = std::time::Instant::now();
    let abi = format!("v3-sketch-2-{bitness}-bounded");
    let cache_path =
        crate::analysis::structural_cache::partition_path(cache_root, "sketch", image_sha256, &abi);
    if let Some(mut cached) =
        crate::analysis::structural_cache::load::<SketchImage>(&cache_path, &abi, image_sha256)?
    {
        cached.elapsed_ms = started.elapsed().as_millis();
        cached.cache_hit = true;
        return Ok(cached);
    }
    let mut built = build_from_path(path)?;
    crate::analysis::structural_cache::store(&cache_path, &abi, image_sha256, &built)?;
    let _ = crate::analysis::structural_cache::prune_lru(
        &cache_root.join("structural"),
        crate::analysis::structural_cache::DEFAULT_MAX_BYTES,
    );
    built.cache_hit = false;
    Ok(built)
}

/// Build compact function facts without retaining a whole-image instruction
/// collection. The first pass discovers direct-call seeds; the second decodes
/// authoritative unwind ranges and bounded leaf windows one at a time.
pub fn build_from_path(path: &std::path::Path) -> anyhow::Result<SketchImage> {
    let started = std::time::Instant::now();
    let pe = crate::loader::pe::LoadedPe::open_catalog(path)?;
    let optional = pe.triage.optional_header.as_ref();
    let sections = pe.triage.sections.as_deref().unwrap_or_default();
    let image_base = optional.map(|header| header.image_base).unwrap_or_default();
    let address_space = crate::loader::address_space::AddressSpace::new(image_base, sections);
    let magic = optional
        .map(|header| header.magic.as_str())
        .unwrap_or("PE32");
    let bitness = address_space.bitness(magic);
    let entry_va = image_base.saturating_add(
        optional
            .map(|header| header.address_of_entry_point)
            .unwrap_or_default(),
    );
    let runtime = if bitness == 64 {
        crate::analysis::unwind::parse_runtime_functions(&pe.image, &address_space)
            .unwrap_or_default()
    } else {
        crate::analysis::unwind::RuntimeFunctionTable::default()
    };
    let mut ranges = std::collections::BTreeMap::<u64, u64>::new();
    ranges
        .entry(entry_va)
        .or_insert(entry_va.saturating_add(4096));
    let mut candidate_limit_reached = false;
    for entry in runtime.entries {
        if ranges.len() >= MAX_RESIDENT_SKETCHES && !ranges.contains_key(&entry.begin_va) {
            candidate_limit_reached = true;
            continue;
        }
        ranges.insert(entry.begin_va, entry.end_va);
    }

    let mut decoded_instructions = 0usize;
    for section in address_space.exec_sections() {
        let start = section.raw_addr as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(pe.image.len());
        if start >= end {
            continue;
        }
        let ip = image_base.saturating_add(u64::from(section.vaddr));
        let mut decoder =
            Decoder::with_ip(bitness, &pe.image[start..end], ip, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instruction = decoder.decode();
            if instruction.len() == 0 {
                break;
            }
            decoded_instructions += 1;
            if instruction.flow_control() == FlowControl::Call {
                let target = instruction.near_branch_target();
                if address_space.is_executable_va(target) {
                    if ranges.len() < MAX_RESIDENT_SKETCHES || ranges.contains_key(&target) {
                        ranges.entry(target).or_insert(target.saturating_add(4096));
                    } else {
                        candidate_limit_reached = true;
                    }
                }
            }
        }
    }

    let starts: Vec<_> = ranges.keys().copied().collect();
    let mut result = Vec::with_capacity(starts.len());
    for (index, start) in starts.iter().copied().enumerate() {
        let declared_end = ranges[&start];
        let next_start = starts.get(index + 1).copied().unwrap_or(u64::MAX);
        let end = declared_end
            .min(next_start)
            .min(start.saturating_add(64 * 1024));
        if let Some(sketch) = sketch_range(&pe.image, &address_space, bitness, start, end) {
            result.push(sketch);
        }
    }
    result.sort_unstable_by_key(|sketch| sketch.va);
    Ok(SketchImage {
        sketches: result,
        decoded_instructions,
        candidate_limit_reached,
        candidate_limit: MAX_RESIDENT_SKETCHES,
        elapsed_ms: started.elapsed().as_millis(),
        cache_hit: false,
    })
}

/// Decode one bounded window without constructing a whole-image project. This
/// is the random-access escape hatch for addresses omitted from the resident
/// sketch shortlist on very large binaries.
pub fn sketch_at_path(path: &std::path::Path, va: u64) -> anyhow::Result<Option<FunctionSketch>> {
    let pe = crate::loader::pe::LoadedPe::open_catalog(path)?;
    let optional = pe.triage.optional_header.as_ref();
    let sections = pe.triage.sections.as_deref().unwrap_or_default();
    let image_base = optional.map(|header| header.image_base).unwrap_or_default();
    let address_space = crate::loader::address_space::AddressSpace::new(image_base, sections);
    let magic = optional
        .map(|header| header.magic.as_str())
        .unwrap_or("PE32");
    let bitness = address_space.bitness(magic);
    Ok(sketch_range(
        &pe.image,
        &address_space,
        bitness,
        va,
        va.saturating_add(64 * 1024),
    ))
}

fn sketch_range(
    image: &[u8],
    address_space: &crate::loader::address_space::AddressSpace,
    bitness: u32,
    start: u64,
    end: u64,
) -> Option<FunctionSketch> {
    if end <= start {
        return None;
    }
    let section = address_space.section_at_va(start)?;
    let file_offset = section.va_to_offset(address_space.image_base, start)? as usize;
    let available = (section.raw_addr as usize)
        .saturating_add(section.raw_size as usize)
        .min(image.len())
        .saturating_sub(file_offset);
    let requested = usize::try_from(end.saturating_sub(start)).unwrap_or(available);
    let bytes = image.get(file_offset..file_offset.saturating_add(requested.min(available)))?;
    let mut decoder = Decoder::with_ip(bitness, bytes, start, DecoderOptions::NONE);
    let mut instructions = 0usize;
    let mut conditional_branches = 0usize;
    let mut loops = 0usize;
    let mut calls = BTreeSet::new();
    let mut returns = 0usize;
    let mut memory_ops = 0usize;
    let mut byte_memory_ops = 0usize;
    let mut global_writes = 0usize;
    let mut adds = 0usize;
    let mut subtracts = 0usize;
    let mut multiplies = 0usize;
    let mut xors = 0usize;
    let mut zero_tests = 0usize;
    let mut constants = BTreeSet::new();
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.len() == 0 || instruction.ip() >= end {
            break;
        }
        instructions += 1;
        match instruction.flow_control() {
            FlowControl::ConditionalBranch => {
                conditional_branches += 1;
                if instruction.near_branch_target() <= instruction.ip() {
                    loops += 1;
                }
            }
            FlowControl::UnconditionalBranch => {
                if instruction.near_branch_target() <= instruction.ip() {
                    loops += 1;
                }
            }
            FlowControl::Call => {
                let target = instruction.near_branch_target();
                if target != 0 {
                    calls.insert(target);
                }
            }
            FlowControl::Return => returns += 1,
            _ => {}
        }
        match instruction.mnemonic() {
            Mnemonic::Add | Mnemonic::Inc => adds += 1,
            Mnemonic::Sub | Mnemonic::Dec => subtracts += 1,
            Mnemonic::Imul | Mnemonic::Mul => multiplies += 1,
            Mnemonic::Xor => xors += 1,
            Mnemonic::Cmp | Mnemonic::Test if is_zero_test(&instruction) => zero_tests += 1,
            _ => {}
        }
        let has_memory = (0..instruction.op_count())
            .any(|operand| instruction.op_kind(operand) == OpKind::Memory);
        if has_memory {
            memory_ops += 1;
            if instruction.memory_size().size() == 1 {
                byte_memory_ops += 1;
            }
            if instruction.op_kind(0) == OpKind::Memory
                && matches!(instruction.memory_base(), Register::RIP | Register::EIP)
                && writes_operand_zero(instruction.mnemonic())
            {
                global_writes += 1;
            }
        }
        for operand in 0..instruction.op_count() {
            if is_immediate(instruction.op_kind(operand)) {
                constants.insert(instruction.immediate(operand));
            }
        }
    }
    if instructions == 0 {
        return None;
    }
    let direct_calls: Vec<_> = calls.into_iter().collect();
    let blocks = 1 + conditional_branches + loops;
    let compact_leaf = direct_calls.is_empty() && blocks <= 16;
    let mut motifs = Vec::new();
    if compact_leaf && loops > 0 && byte_memory_ops > 0 && zero_tests > 0 && adds > 0 {
        motifs.push("nul_terminated_byte_loop".to_string());
    }
    if compact_leaf
        && loops == 0
        && conditional_branches >= 1
        && returns >= 1
        && byte_memory_ops == 0
    {
        motifs.push("bounded_select".to_string());
    }
    if compact_leaf && loops > 0 && byte_memory_ops > 0 && xors > 0 && multiplies > 0 {
        motifs.push("xor_multiply_hash".to_string());
    }
    if compact_leaf && adds > 0 && subtracts > 0 && multiplies > 0 && conditional_branches >= 2 {
        motifs.push("arithmetic_dispatch".to_string());
    }
    if direct_calls.len() >= 2
        && direct_calls.len() <= 6
        && conditional_branches > 0
        && blocks <= 24
    {
        motifs.push("conditional_call_pipeline".to_string());
    }
    if compact_leaf && loops > 0 && memory_ops >= 2 && adds > 0 && byte_memory_ops == 0 {
        motifs.push("linked_list_accumulator".to_string());
    }
    if compact_leaf && loops == 0 && memory_ops >= 4 && multiplies >= 2 && adds > 0 {
        motifs.push("pair_dot_product".to_string());
    }
    Some(FunctionSketch {
        va: start,
        size: end.saturating_sub(start),
        blocks,
        instructions,
        loops,
        conditional_branches,
        direct_calls,
        returns,
        memory_ops,
        byte_memory_ops,
        global_writes,
        adds,
        subtracts,
        multiplies,
        xors,
        zero_tests,
        constants: constants.into_iter().take(16).collect(),
        motifs,
    })
}

fn build(project: &Project) -> Vec<FunctionSketch> {
    project
        .analysis
        .functions
        .iter()
        .map(|function| {
            let mut instructions = 0usize;
            let mut conditional_branches = 0usize;
            let mut calls = BTreeSet::new();
            let mut returns = 0usize;
            let mut memory_ops = 0usize;
            let mut byte_memory_ops = 0usize;
            let mut global_writes = 0usize;
            let mut adds = 0usize;
            let mut subtracts = 0usize;
            let mut multiplies = 0usize;
            let mut xors = 0usize;
            let mut zero_tests = 0usize;
            let mut constants = BTreeSet::new();
            let loops = function
                .blocks
                .iter()
                .flat_map(|block| block.successors.iter().map(move |edge| (block, edge)))
                .filter(|(block, edge)| edge.target != 0 && edge.target <= block.entry_va)
                .count();

            for block in &function.blocks {
                for decoded in project
                    .analysis
                    .code_index
                    .window(block.entry_va, block.instr_count)
                    .iter()
                    .take_while(|decoded| decoded.ip <= block.exit_va)
                {
                    let instruction = &decoded.instr;
                    instructions += 1;
                    match instruction.flow_control() {
                        FlowControl::ConditionalBranch => conditional_branches += 1,
                        FlowControl::Call => {
                            calls.insert(instruction.near_branch_target());
                        }
                        FlowControl::Return => returns += 1,
                        _ => {}
                    }
                    match instruction.mnemonic() {
                        Mnemonic::Add | Mnemonic::Inc => adds += 1,
                        Mnemonic::Sub | Mnemonic::Dec => subtracts += 1,
                        Mnemonic::Imul | Mnemonic::Mul => multiplies += 1,
                        Mnemonic::Xor => xors += 1,
                        Mnemonic::Cmp | Mnemonic::Test if is_zero_test(instruction) => {
                            zero_tests += 1;
                        }
                        _ => {}
                    }
                    let has_memory = (0..instruction.op_count())
                        .any(|index| instruction.op_kind(index) == OpKind::Memory);
                    if has_memory {
                        memory_ops += 1;
                        if instruction.memory_size().size() == 1 {
                            byte_memory_ops += 1;
                        }
                        if instruction.op_kind(0) == OpKind::Memory
                            && matches!(instruction.memory_base(), Register::RIP | Register::EIP)
                            && writes_operand_zero(instruction.mnemonic())
                        {
                            global_writes += 1;
                        }
                    }
                    for index in 0..instruction.op_count() {
                        if is_immediate(instruction.op_kind(index)) {
                            constants.insert(instruction.immediate(index));
                        }
                    }
                }
            }
            let direct_calls: Vec<_> = calls.into_iter().collect();
            let mut motifs = Vec::new();
            let compact_leaf = direct_calls.is_empty() && function.blocks.len() <= 16;
            if compact_leaf && loops > 0 && byte_memory_ops > 0 && zero_tests > 0 && adds > 0 {
                motifs.push("nul_terminated_byte_loop".to_string());
            }
            if compact_leaf
                && loops == 0
                && conditional_branches >= 1
                && returns >= 1
                && byte_memory_ops == 0
            {
                motifs.push("bounded_select".to_string());
            }
            if compact_leaf && loops > 0 && byte_memory_ops > 0 && xors > 0 && multiplies > 0 {
                motifs.push("xor_multiply_hash".to_string());
            }
            if compact_leaf
                && adds > 0
                && subtracts > 0
                && multiplies > 0
                && conditional_branches >= 2
            {
                motifs.push("arithmetic_dispatch".to_string());
            }
            if direct_calls.len() >= 2
                && direct_calls.len() <= 6
                && conditional_branches > 0
                && function.blocks.len() <= 24
            {
                motifs.push("conditional_call_pipeline".to_string());
            }
            if compact_leaf && loops > 0 && memory_ops >= 2 && adds > 0 && byte_memory_ops == 0 {
                motifs.push("linked_list_accumulator".to_string());
            }
            if compact_leaf && loops == 0 && memory_ops >= 4 && multiplies >= 2 && adds > 0 {
                motifs.push("pair_dot_product".to_string());
            }
            FunctionSketch {
                va: function.entry_va,
                size: function.size(),
                blocks: function.blocks.len(),
                instructions,
                loops,
                conditional_branches,
                direct_calls,
                returns,
                memory_ops,
                byte_memory_ops,
                global_writes,
                adds,
                subtracts,
                multiplies,
                xors,
                zero_tests,
                constants: constants.into_iter().take(16).collect(),
                motifs,
            }
        })
        .collect()
}

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

fn writes_operand_zero(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Mov
            | Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Xor
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Inc
            | Mnemonic::Dec
    )
}

fn is_zero_test(instruction: &iced_x86::Instruction) -> bool {
    let immediate_zero = (0..instruction.op_count())
        .any(|index| is_immediate(instruction.op_kind(index)) && instruction.immediate(index) == 0);
    immediate_zero
        || (instruction.mnemonic() == Mnemonic::Test
            && instruction.op_count() >= 2
            && instruction.op_kind(0) == OpKind::Register
            && instruction.op_kind(1) == OpKind::Register
            && instruction.op_register(0) == instruction.op_register(1))
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate8_2nd
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank(va: u64) -> FunctionSketch {
        FunctionSketch {
            va,
            size: 16,
            blocks: 1,
            instructions: 4,
            loops: 0,
            conditional_branches: 0,
            direct_calls: Vec::new(),
            returns: 1,
            memory_ops: 0,
            byte_memory_ops: 0,
            global_writes: 0,
            adds: 0,
            subtracts: 0,
            multiplies: 0,
            xors: 0,
            zero_tests: 0,
            constants: Vec::new(),
            motifs: Vec::new(),
        }
    }

    #[test]
    fn crypto_terms_are_not_supported_by_generic_bitops() {
        assert!(contains_any("aes gcm encryption", &["aes", "gcm"]));
        assert!(!contains_any("byte hash", &["aes", "gcm"]));
    }

    #[test]
    fn exact_address_is_a_hard_constraint() {
        let mut first = blank(0x1000);
        first.motifs.push("bounded_select".to_string());
        let second = blank(0x2000);
        let ranked = rank_sketches(&[first, second], "inspect 0x2000", 8);
        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].sketch.va, 0x2000);
    }

    #[test]
    fn pipeline_ranking_verifies_a_global_writing_callee() {
        let mut sink = blank(0x1300);
        sink.global_writes = 1;
        let mut pipeline = blank(0x1000);
        pipeline
            .motifs
            .push("conditional_call_pipeline".to_string());
        pipeline.direct_calls = vec![0x1100, 0x1200, 0x1300];
        let mut runtime_noise = blank(0x2000);
        runtime_noise
            .motifs
            .push("conditional_call_pipeline".to_string());
        runtime_noise.direct_calls = vec![0x2100, 0x2200, 0x2300, 0x2400, 0x2500, 0x2600];
        let ranked = rank_sketches(
            &[pipeline, runtime_noise, sink],
            "decoder validation pipeline conditionally reaches a global-writing sink",
            8,
        );
        assert_eq!(ranked[0].sketch.va, 0x1000);
        assert!(
            ranked[0]
                .evidence
                .iter()
                .any(|item| item == "verified_callee:global_write")
        );
    }

    #[test]
    fn compact_single_byte_scan_outranks_general_parser_loop() {
        let mut strlen = blank(0x1000);
        strlen.instructions = 15;
        strlen.blocks = 3;
        strlen.loops = 1;
        strlen.byte_memory_ops = 1;
        strlen.zero_tests = 1;
        strlen.motifs.push("nul_terminated_byte_loop".to_string());
        let mut parser = blank(0x2000);
        parser.instructions = 80;
        parser.blocks = 11;
        parser.loops = 1;
        parser.byte_memory_ops = 5;
        parser.zero_tests = 3;
        parser.motifs.push("nul_terminated_byte_loop".to_string());
        let ranked = rank_sketches(
            &[parser, strlen],
            "walk a NUL-terminated byte string and return its character count",
            8,
        );
        assert_eq!(ranked[0].sketch.va, 0x1000);
        assert!(ranked[0].score > ranked[1].score);
    }

    #[test]
    fn delegating_pipeline_outranks_a_global_writing_stage() {
        let mut orchestrator = blank(0x1000);
        orchestrator
            .motifs
            .push("conditional_call_pipeline".to_string());
        orchestrator.direct_calls = vec![0x1100, 0x1200, 0x1300];
        let mut stage = orchestrator.clone();
        stage.va = 0x2000;
        stage.global_writes = 2;
        let ranked = rank_sketches(
            &[stage, orchestrator],
            "which caller directly calls decoder and validator and reaches the sink",
            8,
        );
        assert_eq!(ranked[0].sketch.va, 0x1000);
        assert!(ranked[0].score > ranked[1].score);
    }

    #[test]
    fn compact_pipeline_coordinator_outranks_runtime_noise() {
        let mut orchestrator = blank(0x1000);
        orchestrator
            .motifs
            .push("conditional_call_pipeline".to_string());
        orchestrator.direct_calls = vec![0x1100, 0x1200, 0x1300];
        let mut runtime_noise = orchestrator.clone();
        runtime_noise.va = 0x2000;
        runtime_noise.instructions = 90;
        runtime_noise.memory_ops = 40;
        let ranked = rank_sketches(
            &[runtime_noise, orchestrator],
            "which caller directly calls decoder and validator and reaches the sink",
            8,
        );
        assert_eq!(ranked[0].sketch.va, 0x1000);
        assert!(ranked[0].score > ranked[1].score);
    }

    #[test]
    fn verified_leaf_stage_chain_dominates_superficial_pipeline_shape() {
        let decoder = blank(0x1100);
        let mut sink = blank(0x1300);
        sink.global_writes = 1;
        let mut pipeline = blank(0x1000);
        pipeline
            .motifs
            .push("conditional_call_pipeline".to_string());
        pipeline.direct_calls = vec![0x1100, 0x1300];
        let mut runtime_stage = blank(0x2100);
        runtime_stage.direct_calls = vec![0x2200];
        let mut noise = blank(0x2000);
        noise.motifs.push("conditional_call_pipeline".to_string());
        noise.direct_calls = vec![0x2100, 0x1300];
        let ranked = rank_sketches(
            &[noise, runtime_stage, pipeline, decoder, sink],
            "decoder output through validation and into a global-writing sink",
            8,
        );
        assert_eq!(ranked[0].sketch.va, 0x1000);
        assert!(
            ranked[0]
                .evidence
                .iter()
                .any(|item| item == "verified_graph:leaf_stage_chain")
        );
    }

    #[test]
    fn pure_clamp_and_compact_list_shapes_beat_generic_control_flow() {
        let mut clamp = blank(0x1000);
        clamp.returns = 2;
        clamp.motifs.push("bounded_select".to_string());
        let mut generic_select = blank(0x2000);
        generic_select.memory_ops = 7;
        generic_select.motifs.push("bounded_select".to_string());
        let clamp_ranked = rank_sketches(
            &[generic_select, clamp],
            "clamp between lower and upper bounds",
            8,
        );
        assert_eq!(clamp_ranked[0].sketch.va, 0x1000);

        let mut list = blank(0x3000);
        list.blocks = 3;
        list.loops = 1;
        list.zero_tests = 1;
        list.motifs.push("linked_list_accumulator".to_string());
        let mut generic_loop = list.clone();
        generic_loop.va = 0x4000;
        generic_loop.blocks = 4;
        generic_loop.global_writes = 1;
        let list_ranked = rank_sketches(
            &[generic_loop, list],
            "follow a linked list next pointer while accumulating values",
            8,
        );
        assert_eq!(list_ranked[0].sketch.va, 0x3000);
    }
}
