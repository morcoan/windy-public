//! Deterministic BEL query planner and seed-and-extend cascade.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};
use std::time::Instant;

use ahash::AHashMap;
use regex::RegexBuilder;
use roaring::RoaringBitmap;
use thiserror::Error;

use super::{
    BelIndex, EntityId, EntityKind, Hit, Overlay, Provenance, ProvenanceLayer, Query, SearchMode,
    SearchResult, SparseFunctionSignature, TotalKind, closed_syncmer_hashes, normalize_ascii,
    stable_u64_hash,
};

#[derive(Debug, Error)]
pub enum BelQueryError {
    #[error("query must not be empty")]
    Empty,
    #[error("invalid regex: {0}")]
    InvalidRegex(String),
    #[error("invalid numeric query: {0}")]
    InvalidNumber(String),
    #[error("invalid or stale BEL cursor")]
    InvalidCursor,
    #[error("BEL query exceeds the safe input limit: {0}")]
    TooLarge(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MatchKind {
    Relationship,
    Ontology,
    Regex,
    Substring,
    Token,
    Prefix,
    Numeric,
    Exact,
}

impl MatchKind {
    fn weight(self) -> i64 {
        match self {
            Self::Exact => 1_000,
            Self::Numeric => 950,
            Self::Prefix => 850,
            Self::Token => 800,
            Self::Substring => 700,
            Self::Regex => 650,
            Self::Ontology => 500,
            Self::Relationship => 400,
        }
    }

    fn exactness(self) -> i64 {
        match self {
            Self::Exact | Self::Numeric => 100,
            Self::Prefix | Self::Token => 85,
            Self::Substring | Self::Regex => 70,
            Self::Ontology => 60,
            Self::Relationship => 50,
        }
    }
}

#[derive(Debug)]
struct CandidateSet {
    ids: RoaringBitmap,
    complete: bool,
    timed_out: bool,
    estimated: Option<u64>,
    strategy: &'static str,
    match_kind: MatchKind,
}

impl CandidateSet {
    fn empty(strategy: &'static str, match_kind: MatchKind) -> Self {
        Self {
            ids: RoaringBitmap::new(),
            complete: true,
            timed_out: false,
            estimated: Some(0),
            strategy,
            match_kind,
        }
    }
}

#[derive(Debug)]
struct CandidateEvidence {
    match_kind: MatchKind,
    provenance: Vec<Provenance>,
    seed_entities: BTreeSet<EntityId>,
    evidence_kinds: BTreeSet<ProvenanceLayer>,
    affinity_micros: i64,
    signature_overlap: u32,
    ontology_boost: u32,
    strategy: &'static str,
}

impl CandidateEvidence {
    fn new(match_kind: MatchKind, strategy: &'static str) -> Self {
        Self {
            match_kind,
            provenance: Vec::new(),
            seed_entities: BTreeSet::new(),
            evidence_kinds: BTreeSet::new(),
            affinity_micros: 0,
            signature_overlap: 0,
            ontology_boost: 0,
            strategy,
        }
    }

    fn add_provenance(&mut self, provenance: Provenance) {
        self.evidence_kinds.insert(provenance.layer);
        if let Some(seed) = provenance.source_entity {
            self.seed_entities.insert(seed);
        }
        if !self.provenance.contains(&provenance) {
            self.provenance.push(provenance);
        }
    }
}

#[derive(Debug)]
struct ScoredHit {
    entity_id: EntityId,
    va: u64,
    score_micros: i64,
    candidate: CandidateEvidence,
}

impl PartialEq for ScoredHit {
    fn eq(&self, other: &Self) -> bool {
        self.score_micros == other.score_micros
            && self.entity_id == other.entity_id
            && self.va == other.va
    }
}

impl Eq for ScoredHit {}

impl PartialOrd for ScoredHit {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ScoredHit {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_hits(self, other)
    }
}

#[derive(Clone, Copy, Debug)]
struct CursorKey {
    index_generation: u64,
    overlay_generation: u64,
    query_hash: u64,
    score_micros: i64,
    entity_id: EntityId,
    va: u64,
}

impl CursorKey {
    fn encode(self) -> String {
        format!(
            "bel1.{:016x}.{:016x}.{:016x}.{:016x}.{:08x}.{:016x}",
            self.index_generation,
            self.overlay_generation,
            self.query_hash,
            self.score_micros as u64,
            self.entity_id,
            self.va
        )
    }

    fn decode(value: &str) -> Option<Self> {
        let mut parts = value.split('.');
        if parts.next()? != "bel1" {
            return None;
        }
        let cursor = Self {
            index_generation: u64::from_str_radix(parts.next()?, 16).ok()?,
            overlay_generation: u64::from_str_radix(parts.next()?, 16).ok()?,
            query_hash: u64::from_str_radix(parts.next()?, 16).ok()?,
            score_micros: u64::from_str_radix(parts.next()?, 16).ok()? as i64,
            entity_id: u32::from_str_radix(parts.next()?, 16).ok()?,
            va: u64::from_str_radix(parts.next()?, 16).ok()?,
        };
        parts.next().is_none().then_some(cursor)
    }
}

struct Budget {
    deadline: Instant,
    interval: usize,
    iterations: usize,
    timed_out: bool,
}

impl Budget {
    fn new(deadline: Instant, interval: usize) -> Self {
        Self {
            deadline,
            interval: interval.max(1),
            iterations: 0,
            timed_out: false,
        }
    }

    fn tick(&mut self) -> bool {
        if self.timed_out {
            return false;
        }
        let check = self.iterations % self.interval == 0;
        self.iterations = self.iterations.saturating_add(1);
        if check && Instant::now() >= self.deadline {
            self.timed_out = true;
            return false;
        }
        true
    }
}

/// Execute a complete BEL query against one immutable base + overlay snapshot.
/// No task is spawned; deadline return means no work continues elsewhere.
pub fn search(
    index: &BelIndex,
    overlay: &Overlay,
    query: &Query,
    limit: usize,
    cursor: Option<&str>,
    deadline: Instant,
) -> Result<SearchResult, BelQueryError> {
    const MAX_QUERY_BYTES: usize = 16 * 1024;
    const MAX_EVIDENCE_CLAUSES: usize = 64;
    if query.text.len() > MAX_QUERY_BYTES
        || query
            .evidence
            .iter()
            .any(|clause| clause.len() > MAX_QUERY_BYTES)
    {
        return Err(BelQueryError::TooLarge(
            "query text and each evidence clause are capped at 16 KiB",
        ));
    }
    if query.evidence.len() > MAX_EVIDENCE_CLAUSES {
        return Err(BelQueryError::TooLarge(
            "multi-evidence queries are capped at 64 clauses",
        ));
    }
    let started = Instant::now();
    let (mode, query_text) = classify_query(query)?;
    let normalized = normalize_ascii(query_text);
    if normalized.is_empty() && mode != SearchMode::MultiEvidence {
        return Err(BelQueryError::Empty);
    }
    let query_hash = query_fingerprint(query, mode, &normalized);
    let cursor = match cursor {
        Some(value) => Some(CursorKey::decode(value).ok_or(BelQueryError::InvalidCursor)?),
        None => None,
    };
    if cursor.is_some_and(|cursor| {
        cursor.index_generation != index.generation
            || cursor.overlay_generation != overlay.generation
            || cursor.query_hash != query_hash
    }) {
        return Err(BelQueryError::InvalidCursor);
    }

    let mut budget = Budget::new(deadline, index.config.deadline_check_interval);
    let mut evidence = AHashMap::<EntityId, CandidateEvidence>::new();
    let mut complete = true;
    let estimated;
    let top_strategy;

    match mode {
        SearchMode::Relationship => {
            let seeds = collect_surface(
                index,
                overlay,
                SearchMode::Substring,
                &normalized,
                &[],
                &mut budget,
            )?;
            estimated = seeds.estimated;
            complete &= seeds.complete;
            top_strategy = "seed_one_hop";
            extend_relationships(
                index,
                overlay,
                &seeds,
                query.relationship_depth,
                &normalized,
                &mut evidence,
                &mut budget,
            );
        }
        SearchMode::MultiEvidence => {
            top_strategy = "quorum_signature_cascade";
            let outcome =
                collect_multi_evidence(index, overlay, query, &mut evidence, &mut budget)?;
            complete &= outcome.complete;
            estimated = outcome.estimated;
        }
        SearchMode::Motif => {
            top_strategy = "motif_postings";
            complete &= collect_motif(index, &normalized, &mut evidence, &mut budget);
            estimated = Some(evidence.len() as u64);
        }
        SearchMode::Ontology => {
            top_strategy = "ontology_postings";
            complete &= collect_ontology(index, &normalized, &mut evidence, &mut budget);
            estimated = Some(evidence.len() as u64);
        }
        _ => {
            let surface_query = if mode == SearchMode::Regex {
                query_text
            } else {
                &normalized
            };
            let candidates = collect_surface(
                index,
                overlay,
                mode,
                surface_query,
                &query.kinds,
                &mut budget,
            )?;
            complete &= candidates.complete;
            estimated = candidates.estimated;
            top_strategy = candidates.strategy;
            let (token_sources, token_sources_complete) = if mode == SearchMode::Token {
                token_function_sources(index, overlay, &candidates.ids, &mut budget)
            } else {
                (AHashMap::new(), true)
            };
            complete &= token_sources_complete;
            for id in &candidates.ids {
                if !budget.tick() {
                    complete = false;
                    break;
                }
                if !kind_allowed(index, overlay, id, &query.kinds) {
                    continue;
                }
                let layer = match mode {
                    SearchMode::Numeric => ProvenanceLayer::Numeric,
                    SearchMode::Token => ProvenanceLayer::Token,
                    _ if id >= overlay.base_entity_count => ProvenanceLayer::Overlay,
                    _ => ProvenanceLayer::Surface,
                };
                let mut candidate =
                    CandidateEvidence::new(candidates.match_kind, candidates.strategy);
                let source_entity = token_sources.get(&id).copied().unwrap_or(id);
                candidate.add_provenance(Provenance {
                    layer,
                    seed: Some(query_text.to_string()),
                    source_entity: Some(source_entity),
                    detail: if source_entity == id {
                        format!("verified {mode:?} match")
                    } else {
                        format!("verified token aggregate via instruction entity {source_entity}")
                    },
                });
                let df = relationship_postings(index, overlay, id)
                    .map_or(1, |postings| postings.len().max(1));
                candidate.affinity_micros = 1_000_000 / df as i64;
                evidence.insert(id, candidate);
            }
            complete &= candidates.complete && !candidates.timed_out;
        }
    }

    if budget.timed_out {
        complete = false;
    }
    // Roaring iteration defines the processing order independently of the
    // high-speed hash table's randomized bucket layout.
    let evidence_ids: RoaringBitmap = evidence.keys().copied().collect();
    let (query_signature, signature_complete) =
        query_signature(index, &evidence, &evidence_ids, &mut budget);
    complete &= signature_complete;
    let page_limit = limit.clamp(1, 512);
    let heap_limit = page_limit.saturating_add(1);
    // `Ord` makes the worst retained hit the max-heap root. This bounds query
    // memory to one page plus a lookahead item while preserving exact totals.
    let mut scored = BinaryHeap::with_capacity(heap_limit);
    let mut total = 0u64;
    let mut after_cursor = 0u64;
    for id in evidence_ids {
        let Some(mut candidate) = evidence.remove(&id) else {
            continue;
        };
        if !budget.tick() {
            complete = false;
            break;
        }
        let Some(entity) = index.entity(overlay, id) else {
            continue;
        };
        let display = index
            .display(overlay, id)
            .unwrap_or(entity.display.as_ref());
        let function_id = entity
            .func_entry
            .and_then(|va| index.function_by_va.get(&va).copied())
            .or_else(|| (entity.kind == EntityKind::Function).then_some(id));
        if let Some(function_id) = function_id {
            if !query_signature.is_empty()
                && let Some(signature) = index.signatures.signatures.get(function_id as usize)
            {
                candidate.signature_overlap =
                    if let Some(delta) = overlay.signature_deltas.get(&function_id) {
                        let mut visible = signature.clone();
                        visible.union_assign(delta);
                        visible.overlap(&query_signature)
                    } else {
                        signature.overlap(&query_signature)
                    };
                if candidate.signature_overlap > 0 {
                    candidate.add_provenance(Provenance {
                        layer: ProvenanceLayer::Signature,
                        seed: None,
                        source_entity: None,
                        detail: format!(
                            "{} fixed-width evidence bit(s) overlap",
                            candidate.signature_overlap
                        ),
                    });
                }
            }
            candidate.ontology_boost = index
                .ontology
                .func_labels
                .get(&function_id)
                .map_or(0, |labels| labels.len() as u32);
        }
        candidate.provenance.sort_by(|left, right| {
            (left.layer, left.source_entity, &left.detail).cmp(&(
                right.layer,
                right.source_entity,
                &right.detail,
            ))
        });
        let cooperativity = candidate.evidence_kinds.len() as i64;
        let length_term = length_specificity(display.len());
        // Fixed-point form of the architecture's affinity/cooperativity score.
        let score_micros = candidate.match_kind.weight() * 1_000_000
            + candidate.affinity_micros * candidate.match_kind.exactness() / 100
            + cooperativity * 100_000
            + i64::from(candidate.signature_overlap) * 10_000
            + i64::from(candidate.ontology_boost) * 25_000
            + length_term;
        total = total.saturating_add(1);
        let scored_hit = ScoredHit {
            entity_id: entity.id,
            va: entity.va.unwrap_or(u64::MAX),
            score_micros,
            candidate,
        };
        if cursor.is_some_and(|cursor| !is_after_cursor(&scored_hit, cursor)) {
            continue;
        }
        after_cursor = after_cursor.saturating_add(1);
        if scored.len() < heap_limit {
            scored.push(scored_hit);
        } else if scored
            .peek()
            .is_some_and(|worst| compare_hits(&scored_hit, worst) == Ordering::Less)
        {
            scored.pop();
            scored.push(scored_hit);
        }
    }

    let mut page = scored.into_vec();
    page.sort_by(compare_hits);
    let has_more_ranked = after_cursor > page_limit as u64;
    page.truncate(page_limit);
    let next_cursor = (has_more_ranked || !complete)
        .then(|| {
            page.last()
                .map(|hit| cursor_for(hit, index, overlay, query_hash))
        })
        .flatten();
    let timeout_or_partial = !complete;
    let short_common = mode == SearchMode::Substring && normalized.chars().count() < 3;
    let refinement_suggestion = if timeout_or_partial {
        Some(
            "Result is a deterministic lower bound. Refine the query, use exact/prefix/token mode, or increase the deadline."
                .to_string(),
        )
    } else if short_common && total > 1_000 {
        Some(
            "Short query matched broadly. Prefer at least three characters or select an entity kind."
                .to_string(),
        )
    } else {
        None
    };
    Ok(SearchResult {
        hits: page
            .into_iter()
            .filter_map(|ranked| {
                let entity = index.entity(overlay, ranked.entity_id)?;
                let display = index
                    .display(overlay, ranked.entity_id)
                    .unwrap_or(entity.display.as_ref());
                let reason = format!(
                    "{:?} match; {} independent evidence kind(s); {} seed(s)",
                    ranked.candidate.match_kind,
                    ranked.candidate.evidence_kinds.len(),
                    ranked.candidate.seed_entities.len()
                );
                Some(Hit {
                    entity_id: entity.id,
                    kind: entity.kind,
                    display: display.to_string(),
                    va: entity.va,
                    file_offset: entity.file_offset,
                    function_va: entity.func_entry,
                    provenance: ranked.candidate.provenance,
                    score: ranked.score_micros as f32 / 1_000_000.0,
                    reason,
                    strategy: ranked.candidate.strategy.to_string(),
                })
            })
            .collect(),
        total,
        total_kind: if complete {
            TotalKind::Exact
        } else {
            TotalKind::LowerBound
        },
        next_cursor,
        truncated: has_more_ranked || !complete,
        elapsed_ms: started.elapsed().as_millis(),
        timeout_or_partial,
        refinement_suggestion,
        estimated_candidates: estimated,
        strategy: top_strategy.to_string(),
        index_generation: index.generation,
        overlay_generation: overlay.generation,
    })
}

fn classify_query(query: &Query) -> Result<(SearchMode, &str), BelQueryError> {
    if query.mode != SearchMode::Auto {
        return Ok((query.mode, query.text.trim()));
    }
    let text = query.text.trim();
    let prefixes = [
        ("exact:", SearchMode::Exact),
        ("prefix:", SearchMode::Prefix),
        ("substring:", SearchMode::Substring),
        ("number:", SearchMode::Numeric),
        ("numeric:", SearchMode::Numeric),
        ("regex:", SearchMode::Regex),
        ("token:", SearchMode::Token),
        ("related:", SearchMode::Relationship),
        ("motif:", SearchMode::Motif),
        ("ontology:", SearchMode::Ontology),
    ];
    for (prefix, mode) in prefixes {
        if let Some(rest) = text.strip_prefix(prefix) {
            return Ok((mode, rest.trim()));
        }
    }
    if !query.evidence.is_empty() {
        return Ok((SearchMode::MultiEvidence, text));
    }
    if let Some(regex) = text.strip_prefix('/') {
        return Ok((SearchMode::Regex, regex));
    }
    if parse_number(text).is_some() {
        return Ok((SearchMode::Numeric, text));
    }
    Ok((SearchMode::Substring, text))
}

fn collect_surface(
    index: &BelIndex,
    overlay: &Overlay,
    mode: SearchMode,
    normalized: &str,
    kinds: &[EntityKind],
    budget: &mut Budget,
) -> Result<CandidateSet, BelQueryError> {
    let mut result = match mode {
        SearchMode::Exact => Ok(collect_exact(index, overlay, normalized, budget)),
        SearchMode::Prefix => Ok(collect_prefix(index, overlay, normalized, budget)),
        SearchMode::Substring | SearchMode::Auto => {
            Ok(collect_substring(index, overlay, normalized, kinds, budget))
        }
        SearchMode::Numeric => collect_numeric(index, overlay, normalized, budget),
        SearchMode::Regex => collect_regex(index, overlay, normalized, kinds, budget),
        SearchMode::Token => Ok(collect_token(index, overlay, normalized, budget)),
        _ => Ok(CandidateSet::empty(
            "unsupported_surface",
            MatchKind::Substring,
        )),
    }?;
    result.complete &= restrict_candidate_kinds(index, overlay, &mut result.ids, kinds, budget);
    result.timed_out |= budget.timed_out;
    Ok(result)
}

fn collect_exact(
    index: &BelIndex,
    overlay: &Overlay,
    normalized: &str,
    budget: &mut Budget,
) -> CandidateSet {
    let mut ids = RoaringBitmap::new();
    if let Some(postings) = overlay.names.get(normalized) {
        for id in postings {
            if !budget.tick() {
                return CandidateSet {
                    estimated: Some(ids.len()),
                    ids,
                    complete: false,
                    timed_out: true,
                    strategy: "fst_exact",
                    match_kind: MatchKind::Exact,
                };
            }
            ids.insert(id);
        }
    }
    let mut complete = true;
    if let Some(posting_index) = index.name_fst.map.get(normalized)
        && let Some(postings) = index.name_fst.postings.get(posting_index as usize)
    {
        for id in postings {
            if !budget.tick() {
                complete = false;
                break;
            }
            if !overlay.tombstones.contains(id) && !overlay.surface_tombstones.contains(id) {
                ids.insert(id);
            }
        }
    }
    CandidateSet {
        estimated: Some(ids.len()),
        ids,
        complete,
        timed_out: budget.timed_out,
        strategy: "fst_exact",
        match_kind: MatchKind::Exact,
    }
}

fn collect_prefix(
    index: &BelIndex,
    overlay: &Overlay,
    normalized: &str,
    budget: &mut Budget,
) -> CandidateSet {
    let safety = safety_limit(index, normalized);
    let mut ids = RoaringBitmap::new();
    let mut complete = true;
    // Differential writes are intentionally visited first so a broad query
    // cannot hide a just-written annotation behind the base safety cap.
    for (text, postings) in &overlay.names {
        if !budget.tick() {
            complete = false;
            break;
        }
        if text.starts_with(normalized) {
            for id in postings {
                if !budget.tick() {
                    complete = false;
                    break;
                }
                ids.insert(id);
            }
            if ids.len() as usize >= safety {
                complete = false;
                break;
            }
        }
    }
    let start = index
        .name_fst
        .sorted_ids
        .partition_point(|id| index.normalized[*id as usize].as_ref() < normalized);
    for &id in &index.name_fst.sorted_ids[start..] {
        if !complete {
            break;
        }
        if !budget.tick() {
            complete = false;
            break;
        }
        let candidate = index.normalized[id as usize].as_ref();
        if !candidate.starts_with(normalized) {
            break;
        }
        if !overlay.tombstones.contains(id) && !overlay.surface_tombstones.contains(id) {
            ids.insert(id);
        }
        if ids.len() as usize >= safety {
            complete = false;
            break;
        }
    }
    CandidateSet {
        estimated: Some(ids.len()),
        ids,
        complete,
        timed_out: budget.timed_out,
        strategy: "fst_prefix",
        match_kind: MatchKind::Prefix,
    }
}

fn collect_substring(
    index: &BelIndex,
    overlay: &Overlay,
    normalized: &str,
    kinds: &[EntityKind],
    budget: &mut Budget,
) -> CandidateSet {
    let hashes = closed_syncmer_hashes(
        normalized.as_bytes(),
        index.syncmer_postings.k as usize,
        index.syncmer_postings.s as usize,
    );
    let (source, strategy, estimate, seed_complete) =
        if index.syncmer_postings.complete && !hashes.is_empty() {
            let mut postings: Vec<_> = hashes
                .iter()
                .filter_map(|hash| index.syncmer_postings.map.get(hash))
                .collect();
            if postings.len() != hashes.len() {
                let (ids, complete) = collect_overlay_substring(overlay, normalized, budget);
                return CandidateSet {
                    ids,
                    complete,
                    timed_out: budget.timed_out,
                    estimated: Some(0),
                    strategy: "syncmer_empty_verify",
                    match_kind: MatchKind::Substring,
                };
            }
            postings.sort_by_key(|posting| posting.len());
            let mut intersection = RoaringBitmap::new();
            let mut complete = true;
            for id in postings[0] {
                if !budget.tick() {
                    complete = false;
                    break;
                }
                if postings.iter().skip(1).all(|posting| posting.contains(id)) {
                    intersection.insert(id);
                }
            }
            let estimate = intersection.len();
            (
                intersection,
                "closed_syncmer_verify",
                Some(estimate),
                complete,
            )
        } else {
            let (all, kind_complete) = if kinds.is_empty() {
                all_base_ids(index, budget)
            } else {
                base_kind_ids(index, kinds, budget)
            };
            (
                all,
                if index.syncmer_postings.complete {
                    "short_query_linear_verify"
                } else {
                    "budget_safe_linear_verify"
                },
                Some(if kind_complete {
                    index.entities.len() as u64
                } else {
                    0
                }),
                kind_complete,
            )
        };
    let safety = safety_limit(index, normalized);
    let (mut ids, overlay_complete) = collect_overlay_substring(overlay, normalized, budget);
    let mut complete = seed_complete && overlay_complete;
    for id in source {
        if !complete || ids.len() as usize >= safety {
            complete = false;
            break;
        }
        if !budget.tick() {
            complete = false;
            break;
        }
        if overlay.tombstones.contains(id) || overlay.surface_tombstones.contains(id) {
            continue;
        }
        if index
            .normalized(overlay, id)
            .is_some_and(|candidate| candidate.contains(normalized))
        {
            ids.insert(id);
            if ids.len() as usize >= safety {
                complete = false;
                break;
            }
        }
    }
    CandidateSet {
        ids,
        complete,
        timed_out: budget.timed_out,
        estimated: estimate,
        strategy,
        match_kind: MatchKind::Substring,
    }
}

fn collect_overlay_substring(
    overlay: &Overlay,
    normalized: &str,
    budget: &mut Budget,
) -> (RoaringBitmap, bool) {
    let mut ids = RoaringBitmap::new();
    for (&id, text) in &overlay.normalized_overrides {
        if !budget.tick() {
            return (ids, false);
        }
        if text.contains(normalized) {
            ids.insert(id);
        }
    }
    for (position, text) in overlay.normalized.iter().enumerate() {
        if !budget.tick() {
            return (ids, false);
        }
        if text.contains(normalized) {
            ids.insert(overlay.base_entity_count + position as EntityId);
        }
    }
    (ids, true)
}

fn collect_numeric(
    index: &BelIndex,
    overlay: &Overlay,
    normalized: &str,
    budget: &mut Budget,
) -> Result<CandidateSet, BelQueryError> {
    let value = parse_number(normalized)
        .ok_or_else(|| BelQueryError::InvalidNumber(normalized.to_string()))?;
    let mut ids = RoaringBitmap::new();
    let mut complete = true;
    let overlay_start = overlay
        .numeric
        .partition_point(|(candidate, _)| *candidate < value);
    let overlay_end = overlay
        .numeric
        .partition_point(|(candidate, _)| *candidate <= value);
    for &(_, id) in &overlay.numeric[overlay_start..overlay_end] {
        if !budget.tick() {
            complete = false;
            break;
        }
        ids.insert(id);
    }
    let start = index
        .numeric
        .sorted
        .partition_point(|(candidate, _)| *candidate < value);
    let end = index
        .numeric
        .sorted
        .partition_point(|(candidate, _)| *candidate <= value);
    for &(_, id) in &index.numeric.sorted[start..end] {
        if !complete || !budget.tick() {
            complete = false;
            break;
        }
        if !overlay.tombstones.contains(id) {
            ids.insert(id);
        }
    }
    Ok(CandidateSet {
        estimated: Some(ids.len()),
        ids,
        complete,
        timed_out: budget.timed_out,
        strategy: "sorted_numeric",
        match_kind: MatchKind::Numeric,
    })
}

fn collect_regex(
    index: &BelIndex,
    overlay: &Overlay,
    pattern: &str,
    kinds: &[EntityKind],
    budget: &mut Budget,
) -> Result<CandidateSet, BelQueryError> {
    let regex = RegexBuilder::new(pattern)
        .case_insensitive(true)
        .unicode(false)
        .build()
        .map_err(|error| BelQueryError::InvalidRegex(error.to_string()))?;
    let required = required_regex_literal(pattern).map(|literal| normalize_ascii(&literal));
    let seed = match required.as_deref() {
        None => {
            let (ids, complete) = all_base_ids(index, budget);
            CandidateSet {
                ids,
                complete,
                timed_out: budget.timed_out,
                estimated: Some(index.entities.len() as u64),
                strategy: "regex_linear_verify",
                match_kind: MatchKind::Regex,
            }
        }
        Some(literal) => collect_substring(index, overlay, literal, kinds, budget),
    };
    let mut ids = RoaringBitmap::new();
    let safety = safety_limit(index, required.as_deref().unwrap_or(""));
    let mut complete = seed.complete;
    // Literal-free regex seeds contain only base ids. Verify differential
    // entities first to preserve immediate visibility under tight deadlines.
    for (&id, display) in &overlay.display_overrides {
        if !budget.tick() {
            complete = false;
            break;
        }
        if regex.is_match(display) {
            ids.insert(id);
        }
    }
    for entity in &overlay.entities {
        if !budget.tick() {
            complete = false;
            break;
        }
        if regex.is_match(entity.display.as_ref()) {
            ids.insert(entity.id);
        }
    }
    for id in &seed.ids {
        if !budget.tick() {
            complete = false;
            break;
        }
        if let Some(display) = index.display(overlay, id)
            && regex.is_match(display)
        {
            ids.insert(id);
            if ids.len() as usize >= safety {
                complete = false;
                break;
            }
        }
    }
    Ok(CandidateSet {
        ids,
        complete,
        timed_out: budget.timed_out,
        estimated: seed.estimated,
        strategy: if required.is_some() {
            "required_literal_then_regex"
        } else {
            "regex_linear_verify"
        },
        match_kind: MatchKind::Regex,
    })
}

fn collect_token(
    index: &BelIndex,
    overlay: &Overlay,
    normalized: &str,
    budget: &mut Budget,
) -> CandidateSet {
    let mut ids = RoaringBitmap::new();
    let mut complete = true;
    for (&id, text) in &overlay.normalized_overrides {
        if !budget.tick() {
            complete = false;
            break;
        }
        if text
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| token == normalized)
        {
            ids.insert(id);
        }
    }
    for (position, text) in overlay.normalized.iter().enumerate() {
        if !complete || !budget.tick() {
            complete = false;
            break;
        }
        if text
            .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
            .any(|token| token == normalized)
        {
            ids.insert(overlay.base_entity_count + position as EntityId);
        }
    }
    if let Some(postings) = index.token_postings.map.get(normalized) {
        for id in postings {
            if !complete || !budget.tick() {
                complete = false;
                break;
            }
            if !overlay.tombstones.contains(id) && !overlay.surface_tombstones.contains(id) {
                ids.insert(id);
            }
        }
    }
    CandidateSet {
        estimated: Some(ids.len()),
        ids,
        complete,
        timed_out: budget.timed_out,
        strategy: "token_primary",
        match_kind: MatchKind::Token,
    }
}

fn token_function_sources(
    index: &BelIndex,
    overlay: &Overlay,
    candidates: &RoaringBitmap,
    budget: &mut Budget,
) -> (AHashMap<EntityId, EntityId>, bool) {
    let mut sources = AHashMap::new();
    for instruction_id in candidates {
        if !budget.tick() {
            return (sources, false);
        }
        let Some(instruction) = index.entity(overlay, instruction_id) else {
            continue;
        };
        if instruction.kind != EntityKind::Instruction {
            continue;
        }
        if let Some(function_va) = instruction.func_entry
            && let Some(&function_id) = index.function_by_va.get(&function_va)
            && candidates.contains(function_id)
        {
            sources.entry(function_id).or_insert(instruction_id);
        }
    }
    (sources, true)
}

fn extend_relationships(
    index: &BelIndex,
    overlay: &Overlay,
    seeds: &CandidateSet,
    requested_depth: u8,
    seed_text: &str,
    evidence: &mut AHashMap<EntityId, CandidateEvidence>,
    budget: &mut Budget,
) {
    let depth = if requested_depth == 0 {
        index.config.relationship_depth
    } else {
        requested_depth
    }
    .max(1)
    .min(index.config.max_lattice_depth);
    let mut frontier = RoaringBitmap::new();
    for seed in &seeds.ids {
        if !budget.tick() {
            return;
        }
        if let Some(functions) = relationship_postings(index, overlay, seed) {
            let df = functions.len().max(1);
            for function in functions {
                if !budget.tick() {
                    return;
                }
                let candidate = evidence
                    .entry(function)
                    .or_insert_with(|| CandidateEvidence::new(MatchKind::Relationship, "one_hop"));
                candidate.affinity_micros += 1_000_000 / df as i64;
                candidate.add_provenance(Provenance {
                    layer: ProvenanceLayer::OneHop,
                    seed: Some(seed_text.to_string()),
                    source_entity: Some(seed),
                    detail: "exact surface-to-function edge".to_string(),
                });
                frontier.insert(function);
            }
        }
    }
    let mut visited = frontier.clone();
    for hop in 1..depth {
        let mut next = RoaringBitmap::new();
        for function in &frontier {
            if !budget.tick() {
                return;
            }
            if let Some(neighbors) = index.propagation.function_neighbors.get(&function) {
                for neighbor in neighbors {
                    if !budget.tick() {
                        return;
                    }
                    if !visited.contains(neighbor) {
                        next.insert(neighbor);
                    }
                }
            }
        }
        for function in &next {
            if !budget.tick() {
                return;
            }
            let candidate = evidence.entry(function).or_insert_with(|| {
                CandidateEvidence::new(MatchKind::Relationship, "bounded_relationship")
            });
            candidate.add_provenance(Provenance {
                layer: ProvenanceLayer::OneHop,
                seed: Some(seed_text.to_string()),
                source_entity: None,
                detail: format!("exact call-graph hop {}", hop + 1),
            });
            visited.insert(function);
        }
        frontier = next;
    }
}

fn collect_multi_evidence(
    index: &BelIndex,
    overlay: &Overlay,
    query: &Query,
    evidence: &mut AHashMap<EntityId, CandidateEvidence>,
    budget: &mut Budget,
) -> Result<CandidateSet, BelQueryError> {
    let mut clauses = query.evidence.clone();
    if !query.text.trim().is_empty() {
        clauses.insert(0, query.text.trim().to_string());
    }
    if clauses.is_empty() {
        return Err(BelQueryError::Empty);
    }
    let quorum = usize::from(
        query
            .quorum
            .unwrap_or(index.config.quorum)
            .max(1)
            .min(clauses.len() as u8),
    );
    let mut counts = BTreeMap::<EntityId, usize>::new();
    let mut sources = BTreeMap::<EntityId, Vec<(String, EntityId, u64)>>::new();
    let mut complete = true;
    let mut estimated = 0u64;
    for clause in &clauses {
        if !budget.tick() {
            complete = false;
            break;
        }
        let normalized = normalize_ascii(clause.trim());
        let seeds = collect_substring(index, overlay, &normalized, &[], budget);
        complete &= seeds.complete;
        estimated = estimated.saturating_add(seeds.estimated.unwrap_or(seeds.ids.len()));
        let mut clause_functions = RoaringBitmap::new();
        for seed in &seeds.ids {
            if !budget.tick() {
                complete = false;
                break;
            }
            if let Some(functions) = relationship_postings(index, overlay, seed) {
                let df = functions.len().max(1);
                for function in functions {
                    if !budget.tick() {
                        complete = false;
                        break;
                    }
                    clause_functions.insert(function);
                    sources
                        .entry(function)
                        .or_default()
                        .push((clause.clone(), seed, df));
                }
            }
        }
        for function in clause_functions {
            if !budget.tick() {
                complete = false;
                break;
            }
            *counts.entry(function).or_default() += 1;
        }
    }
    for (function, count) in counts {
        if !budget.tick() {
            complete = false;
            break;
        }
        if count < quorum {
            continue;
        }
        let mut candidate =
            CandidateEvidence::new(MatchKind::Relationship, "quorum_signature_cascade");
        for (clause, seed, df) in sources.remove(&function).unwrap_or_default() {
            if !budget.tick() {
                complete = false;
                break;
            }
            candidate.affinity_micros += 1_000_000 / df as i64;
            candidate.add_provenance(Provenance {
                layer: ProvenanceLayer::OneHop,
                seed: Some(clause),
                source_entity: Some(seed),
                detail: "independent verified evidence seed".to_string(),
            });
        }
        evidence.insert(function, candidate);
    }
    Ok(CandidateSet {
        ids: RoaringBitmap::new(),
        complete,
        timed_out: budget.timed_out,
        estimated: Some(estimated),
        strategy: "quorum_signature_cascade",
        match_kind: MatchKind::Relationship,
    })
}

fn collect_motif(
    index: &BelIndex,
    normalized: &str,
    evidence: &mut AHashMap<EntityId, CandidateEvidence>,
    budget: &mut Budget,
) -> bool {
    for (name, functions) in &index.motifs.tokens {
        if !budget.tick() {
            return false;
        }
        if !name.contains(normalized) {
            continue;
        }
        let source = index.motifs.entities.get(name).copied();
        for function in functions {
            if !budget.tick() {
                return false;
            }
            let candidate = evidence
                .entry(function)
                .or_insert_with(|| CandidateEvidence::new(MatchKind::Exact, "motif_postings"));
            candidate.add_provenance(Provenance {
                layer: ProvenanceLayer::Motif,
                seed: Some(normalized.to_string()),
                source_entity: source,
                detail: format!("structural motif {name}"),
            });
            candidate.affinity_micros += 1_000_000 / functions.len().max(1) as i64;
        }
    }
    true
}

fn collect_ontology(
    index: &BelIndex,
    normalized: &str,
    evidence: &mut AHashMap<EntityId, CandidateEvidence>,
    budget: &mut Budget,
) -> bool {
    for (name, class_id) in &index.ontology.classes {
        if !budget.tick() {
            return false;
        }
        if !name.contains(normalized) {
            continue;
        }
        let Some(functions) = index.propagation.surface_to_funcs.get(class_id) else {
            continue;
        };
        for function in functions {
            if !budget.tick() {
                return false;
            }
            let candidate = evidence.entry(function).or_insert_with(|| {
                CandidateEvidence::new(MatchKind::Ontology, "ontology_postings")
            });
            candidate.ontology_boost += 1;
            candidate.add_provenance(Provenance {
                layer: ProvenanceLayer::Ontology,
                seed: Some(normalized.to_string()),
                source_entity: Some(*class_id),
                detail: format!("ontology class {name}"),
            });
        }
    }
    true
}

fn relationship_postings(
    index: &BelIndex,
    overlay: &Overlay,
    entity: EntityId,
) -> Option<RoaringBitmap> {
    let mut functions = overlay
        .surface_to_funcs
        .get(&entity)
        .or_else(|| index.propagation.hot_table.get(&entity))
        .or_else(|| index.propagation.surface_to_funcs.get(&entity))
        .cloned()
        .unwrap_or_default();
    if let Some(item) = index.entity(overlay, entity) {
        if item.kind == EntityKind::Function {
            functions.insert(item.id);
        } else if let Some(function_va) = item.func_entry
            && let Some(&function_id) = index.function_by_va.get(&function_va)
        {
            functions.insert(function_id);
        }
    }
    (!functions.is_empty()).then_some(functions)
}

fn query_signature(
    index: &BelIndex,
    evidence: &AHashMap<EntityId, CandidateEvidence>,
    evidence_ids: &RoaringBitmap,
    budget: &mut Budget,
) -> (SparseFunctionSignature, bool) {
    let mut signature = SparseFunctionSignature::new(index.signatures.width_bits);
    for id in evidence_ids {
        if !budget.tick() {
            return (signature, false);
        }
        let Some(candidate) = evidence.get(&id) else {
            continue;
        };
        for &seed in &candidate.seed_entities {
            if !budget.tick() {
                return (signature, false);
            }
            if index.signatures.rare_lookup.contains(seed)
                || seed >= index.entities.len() as EntityId
            {
                signature.insert(seed, index.signatures.width_bits);
            }
        }
    }
    (signature, true)
}

fn compare_hits(left: &ScoredHit, right: &ScoredHit) -> Ordering {
    right
        .score_micros
        .cmp(&left.score_micros)
        .then_with(|| left.entity_id.cmp(&right.entity_id))
        .then_with(|| left.va.cmp(&right.va))
}

fn is_after_cursor(hit: &ScoredHit, cursor: CursorKey) -> bool {
    hit.score_micros < cursor.score_micros
        || (hit.score_micros == cursor.score_micros
            && (hit.entity_id > cursor.entity_id
                || (hit.entity_id == cursor.entity_id && hit.va > cursor.va)))
}

fn cursor_for(hit: &ScoredHit, index: &BelIndex, overlay: &Overlay, query_hash: u64) -> String {
    CursorKey {
        index_generation: index.generation,
        overlay_generation: overlay.generation,
        query_hash,
        score_micros: hit.score_micros,
        entity_id: hit.entity_id,
        va: hit.va,
    }
    .encode()
}

fn query_fingerprint(query: &Query, mode: SearchMode, normalized: &str) -> u64 {
    let mut value = format!(
        "{mode:?}|{normalized}|{}|{}|{:?}",
        query.quorum.unwrap_or_default(),
        query.relationship_depth,
        query.kinds
    );
    for evidence in &query.evidence {
        value.push('|');
        value.push_str(&normalize_ascii(evidence));
    }
    stable_u64_hash(value.as_bytes())
}

fn kind_allowed(index: &BelIndex, overlay: &Overlay, id: EntityId, kinds: &[EntityKind]) -> bool {
    kinds.is_empty()
        || index
            .entity(overlay, id)
            .is_some_and(|entity| kinds.contains(&entity.kind))
}

fn all_base_ids(index: &BelIndex, budget: &mut Budget) -> (RoaringBitmap, bool) {
    let mut ids = RoaringBitmap::new();
    for &id in &index.name_fst.sorted_ids {
        if !budget.tick() {
            return (ids, false);
        }
        ids.insert(id);
    }
    (ids, true)
}

fn base_kind_ids(
    index: &BelIndex,
    kinds: &[EntityKind],
    budget: &mut Budget,
) -> (RoaringBitmap, bool) {
    let mut allowed = RoaringBitmap::new();
    for kind in kinds {
        if let Some(postings) = index.kind_postings.get(kind) {
            for id in postings {
                if !budget.tick() {
                    return (allowed, false);
                }
                allowed.insert(id);
            }
        }
    }
    (allowed, true)
}

fn restrict_candidate_kinds(
    index: &BelIndex,
    overlay: &Overlay,
    ids: &mut RoaringBitmap,
    kinds: &[EntityKind],
    budget: &mut Budget,
) -> bool {
    if kinds.is_empty() {
        return true;
    }
    let mut filtered = RoaringBitmap::new();
    for id in ids.iter() {
        if !budget.tick() {
            *ids = filtered;
            return false;
        }
        if index
            .entity(overlay, id)
            .is_some_and(|entity| kinds.contains(&entity.kind))
        {
            filtered.insert(id);
        }
    }
    *ids = filtered;
    true
}

fn safety_limit(index: &BelIndex, normalized: &str) -> usize {
    if normalized.chars().count() < 3 {
        index.config.safety_cardinality.min(10_000)
    } else {
        index.config.safety_cardinality
    }
}

fn length_specificity(length: usize) -> i64 {
    let denominator = 1.0 + ((length + 1) as f64).ln();
    (1_000_000.0 / denominator).round() as i64
}

fn parse_number(value: &str) -> Option<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse().ok()
    }
}

/// Conservative required-literal extraction.  Any construct that could make
/// a literal optional or select an alternative disables acceleration; regex
/// verification then falls back to a cooperative complete scan.
fn required_regex_literal(pattern: &str) -> Option<String> {
    if !pattern.is_ascii() {
        return None;
    }
    if pattern
        .chars()
        .any(|character| matches!(character, '|' | '*' | '?' | '{'))
    {
        return None;
    }
    let mut runs = Vec::new();
    let mut current = String::new();
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    while let Some(character) = chars.next() {
        if in_class {
            if character == ']' {
                in_class = false;
            }
            if !current.is_empty() {
                runs.push(std::mem::take(&mut current));
            }
            continue;
        }
        match character {
            '[' => {
                in_class = true;
                if !current.is_empty() {
                    runs.push(std::mem::take(&mut current));
                }
            }
            '\\' => match chars.next() {
                Some(escaped) if ".+()[]{}^$|*?\\".contains(escaped) => current.push(escaped),
                // Character classes (`\d`), byte/Unicode escapes (`\xNN`,
                // `\u{...}`), and assertions consume or reinterpret later
                // source characters. Falling back is the only conservative
                // choice without parsing the full regex AST.
                Some(_) | None => return None,
            },
            '.' | '+' | '(' | ')' | '^' | '$' => {
                if !current.is_empty() {
                    runs.push(std::mem::take(&mut current));
                }
            }
            literal => current.push(literal),
        }
    }
    if !current.is_empty() {
        runs.push(current);
    }
    runs.into_iter()
        .max_by_key(String::len)
        .filter(|run| run.len() >= 3)
}

/// Slow complete verifier used by BEL correctness benchmarks. It deliberately
/// ignores every acceleration structure.
pub fn linear_oracle_ids(
    index: &BelIndex,
    overlay: &Overlay,
    mode: SearchMode,
    text: &str,
) -> Result<Vec<EntityId>, BelQueryError> {
    let normalized = normalize_ascii(text);
    let regex = (mode == SearchMode::Regex)
        .then(|| {
            RegexBuilder::new(text)
                .case_insensitive(true)
                .unicode(false)
                .build()
                .map_err(|error| BelQueryError::InvalidRegex(error.to_string()))
        })
        .transpose()?;
    let number = (mode == SearchMode::Numeric)
        .then(|| parse_number(text).ok_or_else(|| BelQueryError::InvalidNumber(text.to_string())))
        .transpose()?;
    if let Some(number) = number {
        let mut ids = RoaringBitmap::new();
        let start = index
            .numeric
            .sorted
            .partition_point(|(candidate, _)| *candidate < number);
        let end = index
            .numeric
            .sorted
            .partition_point(|(candidate, _)| *candidate <= number);
        for &(_, id) in &index.numeric.sorted[start..end] {
            if index.entity(overlay, id).is_some() {
                ids.insert(id);
            }
        }
        let start = overlay
            .numeric
            .partition_point(|(candidate, _)| *candidate < number);
        let end = overlay
            .numeric
            .partition_point(|(candidate, _)| *candidate <= number);
        for &(_, id) in &overlay.numeric[start..end] {
            if index.entity(overlay, id).is_some() {
                ids.insert(id);
            }
        }
        return Ok(ids.into_iter().collect());
    }
    if mode == SearchMode::Token {
        let mut ids = RoaringBitmap::new();
        for entity in &index.entities {
            if entity.kind != EntityKind::Instruction
                || overlay.tombstones.contains(entity.id)
                || overlay.surface_tombstones.contains(entity.id)
            {
                continue;
            }
            let candidate = index.normalized[entity.id as usize].as_ref();
            if candidate
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|token| token == normalized)
            {
                ids.insert(entity.id);
                if let Some(function_va) = entity.func_entry
                    && let Some(&function_id) = index.function_by_va.get(&function_va)
                {
                    ids.insert(function_id);
                }
            }
        }
        for (&id, candidate) in &overlay.normalized_overrides {
            if candidate
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|token| token == normalized)
            {
                ids.insert(id);
            }
        }
        for (position, candidate) in overlay.normalized.iter().enumerate() {
            if candidate
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|token| token == normalized)
            {
                ids.insert(overlay.base_entity_count + position as EntityId);
            }
        }
        return Ok(ids.into_iter().collect());
    }
    let mut ids = Vec::new();
    for id in 0..overlay.base_entity_count + overlay.entities.len() as EntityId {
        if index.entity(overlay, id).is_none() {
            continue;
        }
        let candidate = index.normalized(overlay, id).unwrap_or_default();
        let matches = match mode {
            SearchMode::Exact => candidate == normalized,
            SearchMode::Prefix => candidate.starts_with(&normalized),
            SearchMode::Substring => candidate.contains(&normalized),
            SearchMode::Regex => regex.as_ref().is_some_and(|regex| {
                index
                    .display(overlay, id)
                    .is_some_and(|display| regex.is_match(display))
            }),
            SearchMode::Numeric => false,
            SearchMode::Token => candidate
                .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
                .any(|token| token == normalized),
            _ => false,
        };
        if matches {
            ids.push(id);
        }
    }
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_preserves_signed_score() {
        let cursor = CursorKey {
            index_generation: 1,
            overlay_generation: 2,
            query_hash: 3,
            score_micros: -4,
            entity_id: 5,
            va: 6,
        };
        let decoded = CursorKey::decode(&cursor.encode()).expect("decode cursor");
        assert_eq!(decoded.score_micros, -4);
        assert_eq!(decoded.entity_id, 5);
    }

    #[test]
    fn required_literal_is_conservative() {
        assert_eq!(required_regex_literal("Create(File|Pipe)"), None);
        assert_eq!(required_regex_literal("Create.*File"), None);
        assert_eq!(required_regex_literal(r"\x43reateFile"), None);
        assert_eq!(required_regex_literal(r"\d+File"), None);
        assert_eq!(required_regex_literal("Kernel"), None);
        assert_eq!(
            required_regex_literal("^CreateFile[AW]$"),
            Some("CreateFile".into())
        );
        let ascii_case_insensitive = RegexBuilder::new("kernel")
            .case_insensitive(true)
            .unicode(false)
            .build()
            .unwrap();
        assert!(ascii_case_insensitive.is_match("KeRnEl"));
        assert!(!ascii_case_insensitive.is_match("Kernel"));
    }
}
