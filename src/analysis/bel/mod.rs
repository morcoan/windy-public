//! Binary Evidence Lattice (BEL).
//!
//! BEL is Windy's immutable, deterministic evidence index.  The PE-derived
//! base is built once and shared by every copy-on-write project snapshot;
//! agent annotations are represented by a small differential [`Overlay`].
//! Query execution lives in [`query`] and never spawns background work.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::time::Instant;

use ahash::{AHashMap, AHashSet};
use fst::{Map, MapBuilder};
use iced_x86::{FlowControl, Formatter as _, IntelFormatter, OpKind, SymbolResolver};
use roaring::RoaringBitmap;
use serde::Serialize;
use thiserror::Error;

use crate::disasm::TableResolver;
use crate::project::Project;
use crate::project::symbols::SymbolKind;

pub mod query;

pub use query::search;

pub type EntityId = u32;

/// Single-flight index cell. A beta warmup and an arriving agent query share
/// one construction instead of multiplying CPU and peak memory.
#[derive(Debug, Default)]
pub struct BelIndexCell {
    ready: OnceLock<Arc<BelIndex>>,
    building: Mutex<bool>,
    changed: Condvar,
}

impl BelIndexCell {
    pub fn get(&self) -> Option<&Arc<BelIndex>> {
        self.ready.get()
    }

    pub fn is_building(&self) -> bool {
        *self.building.lock().unwrap()
    }
}

struct BelBuildLease<'a>(&'a BelIndexCell);

impl Drop for BelBuildLease<'_> {
    fn drop(&mut self) {
        let mut building = self.0.building.lock().unwrap();
        *building = false;
        self.0.changed.notify_all();
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    serde::Deserialize,
    schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Symbol,
    String,
    Instruction,
    Function,
    Import,
    Export,
    Comment,
    MemoryCard,
    Type,
    Motif,
    OntologyClass,
}

#[derive(Clone, Debug, Serialize)]
pub struct Entity {
    pub id: EntityId,
    pub kind: EntityKind,
    pub display: Arc<str>,
    pub va: Option<u64>,
    pub file_offset: Option<usize>,
    pub func_entry: Option<u64>,
}

/// Exact normalized-name dictionary.  The FST value addresses a bitmap so
/// duplicate strings/symbols remain lossless.
pub struct NameFst {
    pub map: Map<Vec<u8>>,
    pub postings: Vec<RoaringBitmap>,
    /// All surface entity ids in `(normalized, entity_id)` order.  Prefix and
    /// linear-oracle paths use this deterministic order.
    pub sorted_ids: Vec<EntityId>,
}

impl std::fmt::Debug for NameFst {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NameFst")
            .field("keys", &self.map.len())
            .field("postings", &self.postings.len())
            .field("entities", &self.sorted_ids.len())
            .finish()
    }
}

#[derive(Debug, Default)]
pub struct TokenPostings {
    pub map: AHashMap<Arc<str>, RoaringBitmap>,
}

/// Closed-syncmer postings.  Hash collisions only add candidates; all hits
/// are verified against normalized originals before they are returned.
#[derive(Debug)]
pub struct SyncmerPostings {
    pub map: AHashMap<u64, RoaringBitmap>,
    pub k: u8,
    pub s: u8,
    /// When false, the memory budget stopped construction and query planning
    /// must use the complete linear surface path instead.
    pub complete: bool,
}

#[derive(Debug, Default)]
pub struct NumericIndex {
    pub sorted: Vec<(u64, EntityId)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseFunctionSignature {
    pub bits: Vec<u64>,
}

impl SparseFunctionSignature {
    pub fn new(width_bits: usize) -> Self {
        Self {
            bits: vec![0; width_bits.div_ceil(64)],
        }
    }

    pub fn insert(&mut self, evidence: EntityId, width_bits: usize) {
        if width_bits == 0 {
            return;
        }
        let bit = stable_u64_hash(&evidence.to_le_bytes()) as usize % width_bits;
        self.bits[bit / 64] |= 1u64 << (bit % 64);
    }

    pub fn overlap(&self, other: &Self) -> u32 {
        self.bits
            .iter()
            .zip(&other.bits)
            .map(|(left, right)| (left & right).count_ones())
            .sum()
    }

    pub fn union_assign(&mut self, other: &Self) {
        for (left, right) in self.bits.iter_mut().zip(&other.bits) {
            *left |= *right;
        }
    }

    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|word| *word == 0)
    }
}

#[derive(Debug)]
pub struct SignatureStore {
    /// Function entities are assigned first, so function `EntityId` is a
    /// direct index into this vector.
    pub signatures: Vec<SparseFunctionSignature>,
    pub rare_vocab: Vec<EntityId>,
    pub rare_lookup: RoaringBitmap,
    pub width_bits: usize,
}

#[derive(Debug, Default)]
pub struct Propagation {
    pub surface_to_funcs: AHashMap<EntityId, RoaringBitmap>,
    pub hot_table: AHashMap<EntityId, RoaringBitmap>,
    pub function_neighbors: AHashMap<EntityId, RoaringBitmap>,
}

#[derive(Debug, Default)]
pub struct EvidenceOntology {
    pub classes: BTreeMap<Arc<str>, EntityId>,
    pub edges: AHashMap<EntityId, Vec<EntityId>>,
    pub func_labels: AHashMap<EntityId, RoaringBitmap>,
}

#[derive(Debug, Default)]
pub struct MotifIndex {
    pub tokens: BTreeMap<Arc<str>, RoaringBitmap>,
    pub entities: BTreeMap<Arc<str>, EntityId>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SlotKind {
    Symbol,
    AddressComment,
    FunctionComment,
    MemoryCard,
    GlobalType,
    FunctionType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct SlotKey {
    kind: SlotKind,
    va: u64,
}

type AnnotationSlot = (
    String,
    SlotKey,
    EntityKind,
    String,
    Option<u64>,
    Option<u64>,
);

#[derive(Clone, Debug)]
pub struct Overlay {
    pub entities: Vec<Entity>,
    pub normalized: Vec<Arc<str>>,
    pub names: BTreeMap<Arc<str>, RoaringBitmap>,
    pub tombstones: RoaringBitmap,
    /// Base entities whose old normalized text must be excluded from surface
    /// indexes while the entity itself remains a valid relationship target
    /// (notably renamed function identities).
    pub surface_tombstones: RoaringBitmap,
    pub display_overrides: BTreeMap<EntityId, Arc<str>>,
    pub normalized_overrides: BTreeMap<EntityId, Arc<str>>,
    pub signature_deltas: BTreeMap<EntityId, SparseFunctionSignature>,
    pub surface_to_funcs: AHashMap<EntityId, RoaringBitmap>,
    pub numeric: Vec<(u64, EntityId)>,
    pub generation: u64,
    pub base_entity_count: EntityId,
}

#[derive(Clone, Debug)]
#[allow(dead_code)] // public differential embedding API; Windy derives snapshots from Project ops
pub enum AnnotationChange {
    Upsert {
        kind: EntityKind,
        display: String,
        va: Option<u64>,
        function_va: Option<u64>,
        replaces: Option<EntityId>,
    },
    Tombstone {
        entity_id: EntityId,
    },
}

impl Overlay {
    pub fn empty(index: &BelIndex, generation: u64) -> Self {
        Self {
            entities: Vec::new(),
            normalized: Vec::new(),
            names: BTreeMap::new(),
            tombstones: RoaringBitmap::new(),
            surface_tombstones: RoaringBitmap::new(),
            display_overrides: BTreeMap::new(),
            normalized_overrides: BTreeMap::new(),
            signature_deltas: BTreeMap::new(),
            surface_to_funcs: AHashMap::new(),
            numeric: Vec::new(),
            generation,
            base_entity_count: index.entities.len() as EntityId,
        }
    }

    /// Build a deterministic differential snapshot from current durable state.
    pub fn from_project(index: &BelIndex, project: &Project) -> Self {
        let mut overlay = Self::empty(index, project.op_seq);
        let mut slots = current_annotation_slots(project);
        slots.sort_by(|left, right| left.0.cmp(&right.0));

        for (sort_key, slot, kind, display, va, function_va) in slots {
            let _ = sort_key;
            let normalized = normalize_ascii(&display);
            let base_id = index.slots.get(&slot).copied();
            if base_id.is_some_and(|id| index.entities[id as usize].display.as_ref() == display) {
                continue;
            }
            if slot.kind == SlotKind::Symbol
                && let Some(&function_id) = index.function_by_va.get(&slot.va)
                && index.entities[function_id as usize].display.as_ref() != display
            {
                let normalized: Arc<str> = Arc::from(normalized.clone());
                overlay.surface_tombstones.insert(function_id);
                overlay
                    .display_overrides
                    .insert(function_id, Arc::from(display.clone()));
                overlay
                    .normalized_overrides
                    .insert(function_id, normalized.clone());
                overlay
                    .names
                    .entry(normalized)
                    .or_default()
                    .insert(function_id);
            }
            if let Some(base_id) = base_id {
                overlay.tombstones.insert(base_id);
            }
            overlay.push_entity(index, kind, display, normalized, va, function_va);
        }

        overlay.numeric.sort_unstable();
        overlay
    }

    fn push_entity(
        &mut self,
        index: &BelIndex,
        kind: EntityKind,
        display: String,
        normalized: String,
        va: Option<u64>,
        function_va: Option<u64>,
    ) {
        let id = self.base_entity_count + self.entities.len() as EntityId;
        let display: Arc<str> = Arc::from(display);
        let normalized: Arc<str> = if normalized == display.as_ref() {
            display.clone()
        } else {
            Arc::from(normalized)
        };
        self.entities.push(Entity {
            id,
            kind,
            display,
            va,
            file_offset: None,
            func_entry: function_va,
        });
        self.normalized.push(normalized.clone());
        self.names.entry(normalized).or_default().insert(id);
        if let Some(value) = va {
            self.numeric.push((value, id));
        }
        if let Some(function_va) = function_va
            && let Some(&function_id) = index.function_by_va.get(&function_va)
        {
            self.surface_to_funcs
                .entry(id)
                .or_default()
                .insert(function_id);
            let delta = self
                .signature_deltas
                .entry(function_id)
                .or_insert_with(|| SparseFunctionSignature::new(index.config.signature_width_bits));
            delta.insert(id, index.config.signature_width_bits);
        }
    }

    pub fn entity(&self, id: EntityId) -> Option<&Entity> {
        let index = id.checked_sub(self.base_entity_count)? as usize;
        self.entities.get(index)
    }

    pub fn normalized(&self, id: EntityId) -> Option<&str> {
        if let Some(text) = self.normalized_overrides.get(&id) {
            return Some(text);
        }
        let index = id.checked_sub(self.base_entity_count)? as usize;
        self.normalized.get(index).map(AsRef::as_ref)
    }

    pub fn display(&self, id: EntityId) -> Option<&str> {
        self.display_overrides.get(&id).map(AsRef::as_ref)
    }

    /// Apply one differential annotation write.  This is the mutable API used
    /// by embedders; Windy's journaled Project path instead derives an
    /// equivalent overlay snapshot from the committed project state.
    pub fn apply_change(&mut self, index: &BelIndex, change: AnnotationChange) {
        match change {
            AnnotationChange::Upsert {
                kind,
                display,
                va,
                function_va,
                replaces,
            } => {
                if let Some(replaced) = replaces {
                    self.tombstones.insert(replaced);
                }
                let normalized = normalize_ascii(&display);
                self.push_entity(index, kind, display, normalized, va, function_va);
            }
            AnnotationChange::Tombstone { entity_id } => {
                self.tombstones.insert(entity_id);
            }
        }
        self.generation = self.generation.saturating_add(1);
        self.numeric.sort_unstable();
    }

    /// Rebuild only differential postings while preserving stable entity ids.
    /// Cancellation is cooperative and leaves `self` untouched.
    pub fn compact(&mut self, index: &BelIndex, cancel: &AtomicBool) -> Result<(), BelBuildError> {
        let mut names = BTreeMap::<Arc<str>, RoaringBitmap>::new();
        let mut numeric = Vec::new();
        let mut relationships = AHashMap::<EntityId, RoaringBitmap>::new();
        let mut deltas = BTreeMap::<EntityId, SparseFunctionSignature>::new();
        for (position, entity) in self.entities.iter().enumerate() {
            if position % index.config.deadline_check_interval == 0
                && cancel.load(Ordering::Relaxed)
            {
                return Err(BelBuildError::Cancelled);
            }
            if self.tombstones.contains(entity.id) {
                continue;
            }
            let normalized = self.normalized[position].clone();
            names.entry(normalized).or_default().insert(entity.id);
            if let Some(value) = entity.va {
                numeric.push((value, entity.id));
            }
            if let Some(function_va) = entity.func_entry
                && let Some(&function_id) = index.function_by_va.get(&function_va)
            {
                relationships
                    .entry(entity.id)
                    .or_default()
                    .insert(function_id);
                deltas
                    .entry(function_id)
                    .or_insert_with(|| {
                        SparseFunctionSignature::new(index.config.signature_width_bits)
                    })
                    .insert(entity.id, index.config.signature_width_bits);
            }
        }
        for (&id, normalized) in &self.normalized_overrides {
            names.entry(normalized.clone()).or_default().insert(id);
        }
        numeric.sort_unstable();
        self.names = names;
        self.numeric = numeric;
        self.surface_to_funcs = relationships;
        self.signature_deltas = deltas;
        self.generation = self.generation.saturating_add(1);
        Ok(())
    }
}

/// Stateful embedding facade matching BEL's immutable-base/differential
/// module boundary. Windy's MCP path uses the same operations directly.
#[allow(dead_code)]
pub struct BelRuntime {
    pub base: Arc<BelIndex>,
    pub overlay: Overlay,
}

#[allow(dead_code)]
pub trait SearchIndex {
    fn search(
        &self,
        query: &Query,
        limit: usize,
        cursor: Option<&str>,
        deadline: Instant,
    ) -> Result<SearchResult, query::BelQueryError>;
    fn update_overlay(&mut self, change: AnnotationChange);
    fn compact_overlay(&mut self, cancel: &AtomicBool) -> Result<(), BelBuildError>;
}

impl SearchIndex for BelRuntime {
    fn search(
        &self,
        query: &Query,
        limit: usize,
        cursor: Option<&str>,
        deadline: Instant,
    ) -> Result<SearchResult, query::BelQueryError> {
        query::search(&self.base, &self.overlay, query, limit, cursor, deadline)
    }

    fn update_overlay(&mut self, change: AnnotationChange) {
        self.overlay.apply_change(&self.base, change);
    }

    fn compact_overlay(&mut self, cancel: &AtomicBool) -> Result<(), BelBuildError> {
        self.overlay.compact(&self.base, cancel)
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BelMemoryBreakdown {
    pub entities_bytes: u64,
    pub normalized_bytes: u64,
    pub surface_posting_bytes: u64,
    pub token_posting_bytes: u64,
    pub syncmer_posting_bytes: u64,
    pub numeric_bytes: u64,
    pub signature_bytes: u64,
    pub propagation_bytes: u64,
    pub estimated_total_bytes: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct BelStats {
    pub entities: usize,
    pub functions: usize,
    pub names: usize,
    pub tokens: usize,
    pub syncmers: usize,
    pub syncmer_occurrences: usize,
    pub syncmer_complete: bool,
    pub numerics: usize,
    pub motifs: usize,
    pub ontology_classes: usize,
    pub rare_evidence: usize,
    pub fm_index_enabled: bool,
    pub build_elapsed_ms: u128,
    pub memory: BelMemoryBreakdown,
}

pub struct BelIndex {
    pub entities: Vec<Entity>,
    /// Normalized text is produced once during construction and aligned with
    /// `entities`; query verification never lowercases candidate text.
    pub normalized: Vec<Arc<str>>,
    pub name_fst: NameFst,
    pub kind_postings: AHashMap<EntityKind, RoaringBitmap>,
    pub token_postings: TokenPostings,
    pub syncmer_postings: SyncmerPostings,
    pub numeric: NumericIndex,
    pub signatures: SignatureStore,
    pub propagation: Propagation,
    pub ontology: EvidenceOntology,
    pub motifs: MotifIndex,
    pub function_by_va: AHashMap<u64, EntityId>,
    slots: AHashMap<SlotKey, EntityId>,
    pub config: BelConfig,
    pub generation: u64,
    pub base_op_seq: u64,
    pub stats: BelStats,
    /// Annotation overlays are immutable for a given journal sequence. Keep
    /// the most recent snapshot so repeated agent searches do not rescan a
    /// potentially enormous symbol table.
    overlay_cache: Mutex<Option<(u64, Arc<Overlay>)>>,
}

impl std::fmt::Debug for BelIndex {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BelIndex")
            .field("stats", &self.stats)
            .field("generation", &self.generation)
            .field("base_op_seq", &self.base_op_seq)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BelConfig {
    pub syncmer_k: u8,
    pub syncmer_s: u8,
    pub signature_width_bits: usize,
    pub rarity_threshold: u32,
    pub hot_table_size: usize,
    pub quorum: u8,
    pub safety_cardinality: usize,
    pub max_lattice_depth: u8,
    pub relationship_depth: u8,
    /// Reserved Phase-4 switch. This build keeps it false and uses the exact
    /// syncmer-or-linear path; validation rejects silent no-op enablement.
    pub enable_fm_index: bool,
    pub memory_budget_mb: usize,
    pub deadline_check_interval: usize,
}

impl Default for BelConfig {
    fn default() -> Self {
        Self {
            syncmer_k: 5,
            syncmer_s: 3,
            signature_width_bits: 1024,
            rarity_threshold: 8,
            hot_table_size: 256,
            quorum: 2,
            safety_cardinality: 100_000,
            max_lattice_depth: 2,
            relationship_depth: 1,
            enable_fm_index: false,
            memory_budget_mb: 768,
            deadline_check_interval: 4096,
        }
    }
}

impl BelConfig {
    fn validate(&self) -> Result<(), BelBuildError> {
        if self.syncmer_k == 0 || self.syncmer_s == 0 || self.syncmer_s >= self.syncmer_k {
            return Err(BelBuildError::InvalidConfig(
                "syncmer parameters require 0 < s < k".to_string(),
            ));
        }
        if self.signature_width_bits == 0 || self.signature_width_bits % 64 != 0 {
            return Err(BelBuildError::InvalidConfig(
                "signature_width_bits must be a non-zero multiple of 64".to_string(),
            ));
        }
        if self.deadline_check_interval == 0 {
            return Err(BelBuildError::InvalidConfig(
                "deadline_check_interval must be non-zero".to_string(),
            ));
        }
        if self.enable_fm_index {
            return Err(BelBuildError::InvalidConfig(
                "FM-index is optional and not enabled in this build; use complete syncmer/linear substring search"
                    .to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BelBuildProgress {
    pub stage: &'static str,
    pub completed: usize,
    pub total: usize,
}

pub struct BelBuildControl<'a> {
    pub cancel: &'a AtomicBool,
    pub deadline: Option<Instant>,
    pub progress: Option<&'a (dyn Fn(BelBuildProgress) + Send + Sync)>,
}

impl<'a> BelBuildControl<'a> {
    fn check_active(&self) -> Result<(), BelBuildError> {
        if self.cancel.load(Ordering::Relaxed) {
            return Err(BelBuildError::Cancelled);
        }
        if self
            .deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            return Err(BelBuildError::Deadline);
        }
        Ok(())
    }

    fn checkpoint(
        &self,
        stage: &'static str,
        completed: usize,
        total: usize,
        interval: usize,
    ) -> Result<(), BelBuildError> {
        if completed == 0 || completed % interval == 0 || completed == total {
            self.check_active()?;
            if let Some(progress) = self.progress {
                progress(BelBuildProgress {
                    stage,
                    completed,
                    total,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Error)]
pub enum BelBuildError {
    #[error("BEL build cancelled")]
    Cancelled,
    #[error("BEL build deadline expired")]
    Deadline,
    #[error("BEL entity count exceeds u32 capacity")]
    TooManyEntities,
    #[error("invalid BEL configuration: {0}")]
    InvalidConfig(String),
    #[error("could not build BEL FST: {0}")]
    Fst(String),
}

#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, serde::Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    #[default]
    Auto,
    Exact,
    Prefix,
    Substring,
    Numeric,
    Regex,
    Token,
    Relationship,
    Motif,
    Ontology,
    MultiEvidence,
}

#[derive(Clone, Debug)]
pub struct Query {
    pub text: String,
    pub mode: SearchMode,
    pub evidence: Vec<String>,
    pub quorum: Option<u8>,
    pub relationship_depth: u8,
    pub kinds: Vec<EntityKind>,
}

impl Query {
    pub fn auto(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            mode: SearchMode::Auto,
            evidence: Vec::new(),
            quorum: None,
            relationship_depth: 1,
            kinds: Vec::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceLayer {
    Surface,
    Token,
    Numeric,
    Signature,
    OneHop,
    Motif,
    Ontology,
    Overlay,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Provenance {
    pub layer: ProvenanceLayer,
    pub seed: Option<String>,
    pub source_entity: Option<EntityId>,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TotalKind {
    Exact,
    LowerBound,
}

#[derive(Clone, Debug, Serialize)]
pub struct Hit {
    pub entity_id: EntityId,
    pub kind: EntityKind,
    pub display: String,
    pub va: Option<u64>,
    pub file_offset: Option<usize>,
    pub function_va: Option<u64>,
    pub provenance: Vec<Provenance>,
    pub score: f32,
    pub reason: String,
    pub strategy: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SearchResult {
    pub hits: Vec<Hit>,
    pub total: u64,
    pub total_kind: TotalKind,
    pub next_cursor: Option<String>,
    pub truncated: bool,
    pub elapsed_ms: u128,
    pub timeout_or_partial: bool,
    pub refinement_suggestion: Option<String>,
    pub estimated_candidates: Option<u64>,
    pub strategy: String,
    pub index_generation: u64,
    pub overlay_generation: u64,
}

impl BelIndex {
    pub fn build(
        project: &Project,
        config: BelConfig,
        control: &BelBuildControl<'_>,
    ) -> Result<Self, BelBuildError> {
        config.validate()?;
        let started = Instant::now();
        let mut builder = IndexBuilder::new(project, config.clone());
        builder.add_functions(control)?;
        builder.add_symbols(control)?;
        builder.add_strings(control)?;
        builder.add_instructions(control)?;
        builder.add_annotations(control)?;
        builder.add_motifs(control)?;
        builder.finish(control, started)
    }

    pub fn overlay(&self, project: &Project) -> Arc<Overlay> {
        let mut cache = self.overlay_cache.lock().unwrap();
        if let Some((generation, overlay)) = cache.as_ref()
            && *generation == project.op_seq
        {
            return overlay.clone();
        }
        let overlay = Arc::new(Overlay::from_project(self, project));
        *cache = Some((project.op_seq, overlay.clone()));
        overlay
    }

    pub fn entity<'a>(&'a self, overlay: &'a Overlay, id: EntityId) -> Option<&'a Entity> {
        if overlay.tombstones.contains(id) {
            return None;
        }
        if let Some(entity) = self.entities.get(id as usize) {
            Some(entity)
        } else {
            overlay.entity(id)
        }
    }

    pub fn normalized<'a>(&'a self, overlay: &'a Overlay, id: EntityId) -> Option<&'a str> {
        if let Some(text) = overlay.normalized_overrides.get(&id) {
            return Some(text);
        }
        if id < overlay.base_entity_count {
            (!overlay.tombstones.contains(id))
                .then(|| self.normalized.get(id as usize).map(AsRef::as_ref))
                .flatten()
        } else {
            overlay.normalized(id)
        }
    }

    pub fn display<'a>(&'a self, overlay: &'a Overlay, id: EntityId) -> Option<&'a str> {
        overlay.display(id).or_else(|| {
            self.entity(overlay, id)
                .map(|entity| entity.display.as_ref())
        })
    }
}

/// Return the shared index or cooperatively build and install it. Concurrent
/// callers join one single-flight construction and observe the same immutable
/// snapshot when it completes.
pub fn get_or_build(
    project: &Project,
    config: BelConfig,
    control: &BelBuildControl<'_>,
) -> Result<Arc<BelIndex>, BelBuildError> {
    if let Some(index) = project.analysis.bel.get() {
        return Ok(index.clone());
    }
    let mut building = project.analysis.bel.building.lock().unwrap();
    loop {
        if let Some(index) = project.analysis.bel.get() {
            return Ok(index.clone());
        }
        if !*building {
            *building = true;
            break;
        }
        if control.cancel.load(Ordering::Relaxed) {
            return Err(BelBuildError::Cancelled);
        }
        let wait = if let Some(deadline) = control.deadline {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(BelBuildError::Deadline);
            };
            remaining.min(std::time::Duration::from_millis(100))
        } else {
            std::time::Duration::from_millis(100)
        };
        let (next, _) = project
            .analysis
            .bel
            .changed
            .wait_timeout(building, wait)
            .unwrap();
        building = next;
    }
    drop(building);
    let lease = BelBuildLease(project.analysis.bel.as_ref());
    let result = BelIndex::build(project, config, control).map(Arc::new);
    if let Ok(built) = &result {
        let _ = project.analysis.bel.ready.set(built.clone());
    }
    drop(lease);
    let built = result?;
    Ok(project.analysis.bel.get().cloned().unwrap_or(built))
}

struct IndexBuilder<'a> {
    project: &'a Project,
    config: BelConfig,
    entities: Vec<Entity>,
    normalized: Vec<Arc<str>>,
    function_by_va: AHashMap<u64, EntityId>,
    function_ranges: Vec<(u64, u64, EntityId)>,
    slots: AHashMap<SlotKey, EntityId>,
    token_postings: AHashMap<Arc<str>, RoaringBitmap>,
    syncmer_postings: AHashMap<u64, RoaringBitmap>,
    syncmer_occurrences: usize,
    syncmer_complete: bool,
    numeric: Vec<(u64, EntityId)>,
    propagation: Propagation,
    motifs: MotifIndex,
    ontology: EvidenceOntology,
}

impl<'a> IndexBuilder<'a> {
    fn new(project: &'a Project, config: BelConfig) -> Self {
        let estimated_entities = project
            .analysis
            .code_index
            .len()
            .saturating_add(project.analysis.functions.len())
            .saturating_add(project.symbols.entries().len())
            .saturating_add(
                project
                    .pe
                    .triage
                    .strings
                    .as_deref()
                    .unwrap_or_default()
                    .len(),
            );
        Self {
            project,
            config,
            entities: Vec::with_capacity(estimated_entities),
            normalized: Vec::with_capacity(estimated_entities),
            function_by_va: AHashMap::new(),
            function_ranges: Vec::new(),
            slots: AHashMap::new(),
            token_postings: AHashMap::new(),
            syncmer_postings: AHashMap::new(),
            syncmer_occurrences: 0,
            syncmer_complete: true,
            numeric: Vec::new(),
            propagation: Propagation::default(),
            motifs: MotifIndex::default(),
            ontology: EvidenceOntology::default(),
        }
    }

    fn add_functions(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        let total = self.project.analysis.functions.len();
        for (position, function) in self.project.analysis.functions.iter().enumerate() {
            control.checkpoint(
                "functions",
                position,
                total,
                self.config.deadline_check_interval,
            )?;
            let display = function.name(&self.project.symbols);
            let id = self.push_entity(
                EntityKind::Function,
                display,
                Some(function.entry_va),
                None,
                Some(function.entry_va),
            )?;
            self.function_by_va.insert(function.entry_va, id);
            let end = function
                .blocks
                .iter()
                .map(|block| block.exit_va)
                .max()
                .unwrap_or(function.entry_va);
            self.function_ranges.push((function.entry_va, end, id));
        }
        self.function_ranges.sort_unstable();
        control.checkpoint(
            "functions",
            total,
            total,
            self.config.deadline_check_interval,
        )
    }

    fn add_symbols(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        let mut symbols = self.project.symbols.entries();
        symbols.sort_by(|left, right| (left.0, &left.1).cmp(&(right.0, &right.1)));
        let total = symbols.len();
        for (position, (va, name, symbol_kind)) in symbols.into_iter().enumerate() {
            control.checkpoint(
                "symbols",
                position,
                total,
                self.config.deadline_check_interval,
            )?;
            let kind = match symbol_kind {
                SymbolKind::Import => EntityKind::Import,
                SymbolKind::Export => EntityKind::Export,
                SymbolKind::Function | SymbolKind::Data | SymbolKind::User => EntityKind::Symbol,
            };
            let function_va = self.owner_function_va(va);
            let id = self.push_entity(kind, name, Some(va), None, function_va)?;
            self.slots.insert(
                SlotKey {
                    kind: SlotKind::Symbol,
                    va,
                },
                id,
            );
        }
        control.checkpoint("symbols", total, total, self.config.deadline_check_interval)
    }

    fn add_strings(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        let mut strings = self
            .project
            .pe
            .triage
            .strings
            .as_deref()
            .unwrap_or_default()
            .iter()
            .collect::<Vec<_>>();
        strings
            .sort_by(|left, right| (left.offset, &left.value).cmp(&(right.offset, &right.value)));
        let total = strings.len();
        for (position, string) in strings.into_iter().enumerate() {
            control.checkpoint(
                "strings",
                position,
                total,
                self.config.deadline_check_interval,
            )?;
            let va = self
                .project
                .address_space
                .offset_to_va(string.offset as u64);
            self.push_entity(
                EntityKind::String,
                string.value.clone(),
                va,
                Some(string.offset),
                None,
            )?;
        }
        control.checkpoint("strings", total, total, self.config.deadline_check_interval)
    }

    fn add_instructions(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        let resolver: Option<Box<dyn SymbolResolver>> = Some(Box::new(
            TableResolver::from_symbol_table(&self.project.symbols),
        ));
        let mut formatter = IntelFormatter::with_options(resolver, None);
        let total = self.project.analysis.code_index.len();
        let mut range_cursor = 0usize;
        for (position, decoded) in self.project.analysis.code_index.iter().enumerate() {
            control.checkpoint(
                "instructions",
                position,
                total,
                self.config.deadline_check_interval,
            )?;
            while range_cursor + 1 < self.function_ranges.len()
                && self.function_ranges[range_cursor + 1].0 <= decoded.ip
            {
                range_cursor += 1;
            }
            let function_id = self
                .function_ranges
                .get(range_cursor)
                .filter(|(start, end, _)| decoded.ip >= *start && decoded.ip <= *end)
                .map(|(_, _, id)| *id);
            let function_va = function_id
                .and_then(|id| self.entities.get(id as usize))
                .and_then(|entity| entity.va);
            let mut display = String::new();
            formatter.format(&decoded.instr, &mut display);
            let id = self.push_entity(
                EntityKind::Instruction,
                display.clone(),
                Some(decoded.ip),
                None,
                function_va,
            )?;
            insert_instruction_tokens(&mut self.token_postings, &display, id, function_id);
            for operand in 0..decoded.instr.op_count() {
                if is_immediate(decoded.instr.op_kind(operand)) {
                    self.numeric.push((decoded.instr.immediate(operand), id));
                }
            }
        }
        control.checkpoint(
            "instructions",
            total,
            total,
            self.config.deadline_check_interval,
        )
    }

    fn add_annotations(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        let mut slots = current_annotation_slots(self.project);
        slots.sort_by(|left, right| left.0.cmp(&right.0));
        let total = slots.len();
        for (position, (_, slot, kind, display, va, function_va)) in slots.into_iter().enumerate() {
            control.checkpoint(
                "annotations",
                position,
                total,
                self.config.deadline_check_interval,
            )?;
            // Symbols were already inserted with their richer import/export
            // kinds; the slot walk includes them only for overlay comparison.
            if slot.kind == SlotKind::Symbol {
                continue;
            }
            let id = self.push_entity(kind, display, va, None, function_va)?;
            self.slots.insert(slot, id);
        }
        control.checkpoint(
            "annotations",
            total,
            total,
            self.config.deadline_check_interval,
        )
    }

    fn add_motifs(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        let mut detected: BTreeMap<&'static str, RoaringBitmap> = BTreeMap::new();
        let total = self.project.analysis.functions.len();
        for (position, function) in self.project.analysis.functions.iter().enumerate() {
            control.checkpoint(
                "motifs",
                position,
                total,
                self.config.deadline_check_interval,
            )?;
            let Some(&function_id) = self.function_by_va.get(&function.entry_va) else {
                continue;
            };
            if function.outgoing.is_empty() {
                detected
                    .entry("leaf_function")
                    .or_default()
                    .insert(function_id);
            }
            if function.outgoing.len() >= 5 {
                detected
                    .entry("dispatcher")
                    .or_default()
                    .insert(function_id);
            }
            if function.blocks.iter().any(|block| {
                block
                    .successors
                    .iter()
                    .any(|edge| edge.target != 0 && edge.target <= block.entry_va)
            }) {
                detected
                    .entry("loop_backedge")
                    .or_default()
                    .insert(function_id);
            }
            if function
                .blocks
                .iter()
                .any(|block| block.successors.len() > 1)
            {
                detected
                    .entry("conditional_control")
                    .or_default()
                    .insert(function_id);
            }
            if function.blocks.iter().any(|block| {
                self.project
                    .analysis
                    .code_index
                    .window(block.entry_va, block.instr_count)
                    .iter()
                    .any(|decoded| {
                        matches!(
                            decoded.instr.flow_control(),
                            FlowControl::IndirectCall | FlowControl::IndirectBranch
                        )
                    })
            }) {
                detected
                    .entry("indirect_dispatch")
                    .or_default()
                    .insert(function_id);
            }
        }
        for (name, functions) in detected {
            let id = self.push_entity(EntityKind::Motif, name.to_string(), None, None, None)?;
            self.motifs
                .tokens
                .insert(Arc::from(name), functions.clone());
            self.motifs.entities.insert(Arc::from(name), id);
            self.propagation.surface_to_funcs.insert(id, functions);
        }
        control.checkpoint("motifs", total, total, self.config.deadline_check_interval)
    }

    fn add_ontology(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        const CLASSES: &[(&str, &[&str])] = &[
            (
                "network",
                &["socket", "connect", "recv", "send", "winhttp", "internet"],
            ),
            (
                "crypto",
                &[
                    "bcrypt", "crypt", "aes", "sha", "md5", "chacha", "encrypt", "decrypt",
                ],
            ),
            (
                "filesystem",
                &["createfile", "readfile", "writefile", "deletefile", "path"],
            ),
            (
                "process",
                &["createprocess", "openprocess", "thread", "process"],
            ),
            (
                "memory",
                &[
                    "virtualalloc",
                    "virtualfree",
                    "heapalloc",
                    "memcpy",
                    "memmove",
                ],
            ),
            ("registry", &["regopen", "regquery", "regset", "registry"]),
            (
                "user_interface",
                &["createwindow", "messagebox", "dispatchmessage", "dialog"],
            ),
        ];
        let root = self.push_entity(
            EntityKind::OntologyClass,
            "evidence".to_string(),
            None,
            None,
            None,
        )?;
        self.ontology.classes.insert(Arc::from("evidence"), root);
        let mut children = Vec::new();
        let mut base_classes = Vec::<(Arc<str>, EntityId, RoaringBitmap)>::new();
        let membership_total = CLASSES.len().saturating_mul(self.entities.len());
        for (position, (class, needles)) in CLASSES.iter().enumerate() {
            control.checkpoint(
                "ontology",
                position,
                CLASSES.len(),
                self.config.deadline_check_interval,
            )?;
            let class_id = self.push_entity(
                EntityKind::OntologyClass,
                (*class).to_string(),
                None,
                None,
                None,
            )?;
            self.ontology.classes.insert(Arc::from(*class), class_id);
            children.push(class_id);
            let mut functions = RoaringBitmap::new();
            for (entity_position, entity) in self.entities.iter().enumerate() {
                control.checkpoint(
                    "ontology_membership",
                    position
                        .saturating_mul(self.entities.len())
                        .saturating_add(entity_position),
                    membership_total,
                    self.config.deadline_check_interval,
                )?;
                if entity.id == class_id || entity.kind == EntityKind::OntologyClass {
                    continue;
                }
                let normalized = &self.normalized[entity.id as usize];
                if needles.iter().any(|needle| normalized.contains(needle))
                    && let Some(postings) = self.propagation.surface_to_funcs.get(&entity.id)
                {
                    functions |= postings;
                }
            }
            for (label_position, function_id) in functions.iter().enumerate() {
                control.checkpoint(
                    "ontology_labels",
                    label_position,
                    functions.len() as usize,
                    self.config.deadline_check_interval,
                )?;
                self.ontology
                    .func_labels
                    .entry(function_id)
                    .or_default()
                    .insert(class_id);
            }
            base_classes.push((Arc::from(*class), class_id, functions.clone()));
            self.propagation
                .surface_to_funcs
                .insert(class_id, functions);
        }
        let mut root_functions = RoaringBitmap::new();
        for (_, _, functions) in &base_classes {
            root_functions |= functions;
        }
        self.propagation
            .surface_to_funcs
            .insert(root, root_functions);
        self.ontology.edges.insert(root, children);

        // Materialize exact pairwise co-occurrence classes. Their ids are
        // allocated after all parents, so parent→combination edges remain a
        // deterministic DAG rather than an undirected similarity graph.
        let pair_total = base_classes
            .len()
            .saturating_mul(base_classes.len().saturating_sub(1))
            / 2;
        let mut pair_position = 0usize;
        for left in 0..base_classes.len() {
            for right in left + 1..base_classes.len() {
                control.checkpoint("ontology_cooccurrence", pair_position, pair_total, 1)?;
                pair_position = pair_position.saturating_add(1);
                let functions = &base_classes[left].2 & &base_classes[right].2;
                if functions.is_empty() {
                    continue;
                }
                let name: Arc<str> = Arc::from(format!(
                    "{}+{}",
                    base_classes[left].0, base_classes[right].0
                ));
                let class_id = self.push_entity(
                    EntityKind::OntologyClass,
                    name.to_string(),
                    None,
                    None,
                    None,
                )?;
                self.ontology.classes.insert(name, class_id);
                self.ontology
                    .edges
                    .entry(base_classes[left].1)
                    .or_default()
                    .push(class_id);
                self.ontology
                    .edges
                    .entry(base_classes[right].1)
                    .or_default()
                    .push(class_id);
                for (label_position, function_id) in functions.iter().enumerate() {
                    control.checkpoint(
                        "ontology_cooccurrence_labels",
                        label_position,
                        functions.len() as usize,
                        self.config.deadline_check_interval,
                    )?;
                    self.ontology
                        .func_labels
                        .entry(function_id)
                        .or_default()
                        .insert(class_id);
                }
                self.propagation
                    .surface_to_funcs
                    .insert(class_id, functions);
            }
        }
        control.checkpoint(
            "ontology",
            CLASSES.len(),
            CLASSES.len(),
            self.config.deadline_check_interval,
        )
    }

    fn finish(
        mut self,
        control: &BelBuildControl<'_>,
        started: Instant,
    ) -> Result<BelIndex, BelBuildError> {
        control.checkpoint("relationships", 0, self.entities.len(), 1)?;
        self.build_relationships(control)?;
        // Ontology membership is derived from exact surface→function edges,
        // so enrichment must run after relationship construction.
        self.add_ontology(control)?;
        self.build_syncmers(control)?;
        self.numeric.sort_unstable();
        self.numeric.dedup();
        let name_fst = build_name_fst(&self.normalized)?;
        let mut kind_postings = AHashMap::<EntityKind, RoaringBitmap>::new();
        for entity in &self.entities {
            kind_postings
                .entry(entity.kind)
                .or_default()
                .insert(entity.id);
        }
        let signatures = self.build_signatures(control)?;
        self.build_hot_table(control)?;
        let generation = stable_u64_hash(
            format!(
                "{}:{}:{}:{}",
                self.project.image_sha256,
                self.config.syncmer_k,
                self.config.syncmer_s,
                self.config.signature_width_bits
            )
            .as_bytes(),
        );
        let memory = estimate_memory(MemoryEstimateInput {
            entities: &self.entities,
            normalized: &self.normalized,
            names: &name_fst,
            kinds: &kind_postings,
            tokens: &self.token_postings,
            syncmers: &self.syncmer_postings,
            numeric: &self.numeric,
            signatures: &signatures,
            propagation: &self.propagation,
        });
        let stats = BelStats {
            entities: self.entities.len(),
            functions: self.function_by_va.len(),
            names: name_fst.map.len(),
            tokens: self.token_postings.len(),
            syncmers: self.syncmer_postings.len(),
            syncmer_occurrences: self.syncmer_occurrences,
            syncmer_complete: self.syncmer_complete,
            numerics: self.numeric.len(),
            motifs: self.motifs.tokens.len(),
            ontology_classes: self.ontology.classes.len(),
            rare_evidence: signatures.rare_vocab.len(),
            fm_index_enabled: self.config.enable_fm_index,
            build_elapsed_ms: started.elapsed().as_millis(),
            memory,
        };
        Ok(BelIndex {
            entities: self.entities,
            normalized: self.normalized,
            name_fst,
            kind_postings,
            token_postings: TokenPostings {
                map: self.token_postings,
            },
            syncmer_postings: SyncmerPostings {
                map: self.syncmer_postings,
                k: self.config.syncmer_k,
                s: self.config.syncmer_s,
                complete: self.syncmer_complete,
            },
            numeric: NumericIndex {
                sorted: self.numeric,
            },
            signatures,
            propagation: self.propagation,
            ontology: self.ontology,
            motifs: self.motifs,
            function_by_va: self.function_by_va,
            slots: self.slots,
            config: self.config,
            generation,
            base_op_seq: self.project.op_seq,
            stats,
            overlay_cache: Mutex::new(None),
        })
    }

    fn push_entity(
        &mut self,
        kind: EntityKind,
        display: String,
        va: Option<u64>,
        file_offset: Option<usize>,
        func_entry: Option<u64>,
    ) -> Result<EntityId, BelBuildError> {
        let id =
            EntityId::try_from(self.entities.len()).map_err(|_| BelBuildError::TooManyEntities)?;
        let display: Arc<str> = Arc::from(display);
        let normalized: Arc<str> = if display.bytes().any(|byte| byte.is_ascii_uppercase()) {
            Arc::from(normalize_ascii(display.as_ref()))
        } else {
            display.clone()
        };
        self.normalized.push(normalized);
        self.entities.push(Entity {
            id,
            kind,
            display,
            va,
            file_offset,
            func_entry,
        });
        if let Some(value) = va {
            self.numeric.push((value, id));
        }
        if let Some(value) = file_offset {
            self.numeric.push((value as u64, id));
        }
        Ok(id)
    }

    fn owner_function_va(&self, va: u64) -> Option<u64> {
        let position = self
            .function_ranges
            .partition_point(|(start, _, _)| *start <= va);
        let (_, end, id) = self.function_ranges.get(position.checked_sub(1)?)?;
        (va <= *end)
            .then(|| self.entities.get(*id as usize).and_then(|entity| entity.va))
            .flatten()
    }

    fn build_relationships(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        let total = self.entities.len();
        for position in 0..total {
            control.checkpoint(
                "relationships",
                position,
                total,
                self.config.deadline_check_interval,
            )?;
            let entity = &self.entities[position];
            if !matches!(entity.kind, EntityKind::Instruction | EntityKind::Function)
                && let Some(function_va) = entity.func_entry
                && let Some(&function_id) = self.function_by_va.get(&function_va)
            {
                self.propagation
                    .surface_to_funcs
                    .entry(entity.id)
                    .or_default()
                    .insert(function_id);
            }
            if !matches!(entity.kind, EntityKind::Instruction | EntityKind::Function)
                && let Some(va) = entity.va
            {
                for (xref_position, xref) in self.project.analysis.xrefs.to(va).iter().enumerate() {
                    if xref_position % self.config.deadline_check_interval == 0 {
                        control.check_active()?;
                    }
                    if let Some(owner_va) = self.owner_function_va(xref.from_va)
                        && let Some(&function_id) = self.function_by_va.get(&owner_va)
                    {
                        self.propagation
                            .surface_to_funcs
                            .entry(entity.id)
                            .or_default()
                            .insert(function_id);
                    }
                }
            }
        }

        for (function_position, function) in self.project.analysis.functions.iter().enumerate() {
            if function_position % self.config.deadline_check_interval == 0 {
                control.check_active()?;
            }
            let Some(&source) = self.function_by_va.get(&function.entry_va) else {
                continue;
            };
            for (target_position, target_va) in function.outgoing.iter().enumerate() {
                if target_position % self.config.deadline_check_interval == 0 {
                    control.check_active()?;
                }
                if let Some(&target) = self.function_by_va.get(target_va) {
                    self.propagation
                        .function_neighbors
                        .entry(source)
                        .or_default()
                        .insert(target);
                    self.propagation
                        .function_neighbors
                        .entry(target)
                        .or_default()
                        .insert(source);
                }
            }
        }
        control.checkpoint(
            "relationships",
            total,
            total,
            self.config.deadline_check_interval,
        )
    }

    fn build_syncmers(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        let total = self.normalized.len();
        // Reserve at most one quarter of the configured memory budget for raw
        // syncmer occurrences.  If exceeded, discard the incomplete map and
        // force the complete linear fallback at query time.
        let occurrence_budget = self.config.memory_budget_mb.saturating_mul(1024 * 1024)
            / 4
            / std::mem::size_of::<EntityId>();
        'texts: for (position, text) in self.normalized.iter().enumerate() {
            control.checkpoint(
                "syncmers",
                position,
                total,
                self.config.deadline_check_interval,
            )?;
            let mut unique = AHashSet::new();
            let bytes = text.as_bytes();
            let k = self.config.syncmer_k as usize;
            let s = self.config.syncmer_s as usize;
            if bytes.len() >= k {
                for (window_position, window) in bytes.windows(k).enumerate() {
                    if window_position % self.config.deadline_check_interval == 0 {
                        control.check_active()?;
                    }
                    if is_closed_syncmer(window, s) {
                        unique.insert(stable_u64_hash(window));
                    }
                    if self.syncmer_occurrences.saturating_add(unique.len()) > occurrence_budget {
                        self.syncmer_postings.clear();
                        self.syncmer_occurrences = 0;
                        self.syncmer_complete = false;
                        break 'texts;
                    }
                }
            }
            for hash in unique {
                self.syncmer_postings
                    .entry(hash)
                    .or_default()
                    .insert(position as EntityId);
                self.syncmer_occurrences += 1;
            }
        }
        control.checkpoint(
            "syncmers",
            total,
            total,
            self.config.deadline_check_interval,
        )
    }

    fn build_signatures(
        &self,
        control: &BelBuildControl<'_>,
    ) -> Result<SignatureStore, BelBuildError> {
        let width = self.config.signature_width_bits;
        let mut signatures = vec![SparseFunctionSignature::new(width); self.function_by_va.len()];
        let mut rare_vocab = Vec::new();
        for (position, (&entity, functions)) in self.propagation.surface_to_funcs.iter().enumerate()
        {
            if position % self.config.deadline_check_interval == 0 {
                control.check_active()?;
            }
            let degree = functions.len();
            let kind = self.entities.get(entity as usize).map(|item| item.kind);
            if degree > 0
                && degree <= u64::from(self.config.rarity_threshold)
                && !matches!(kind, Some(EntityKind::Instruction | EntityKind::Function))
            {
                rare_vocab.push((degree, entity));
            }
        }
        rare_vocab.sort_unstable();
        let rare_vocab: Vec<_> = rare_vocab.into_iter().map(|(_, entity)| entity).collect();
        let mut rare_lookup = RoaringBitmap::new();
        for (evidence_position, &evidence) in rare_vocab.iter().enumerate() {
            if evidence_position % self.config.deadline_check_interval == 0 {
                control.check_active()?;
            }
            rare_lookup.insert(evidence);
            if let Some(functions) = self.propagation.surface_to_funcs.get(&evidence) {
                for (function_position, function) in functions.iter().enumerate() {
                    if function_position % self.config.deadline_check_interval == 0 {
                        control.check_active()?;
                    }
                    if let Some(signature) = signatures.get_mut(function as usize) {
                        signature.insert(evidence, width);
                    }
                }
            }
        }
        Ok(SignatureStore {
            signatures,
            rare_vocab,
            rare_lookup,
            width_bits: width,
        })
    }

    fn build_hot_table(&mut self, control: &BelBuildControl<'_>) -> Result<(), BelBuildError> {
        let mut by_degree = Vec::with_capacity(self.propagation.surface_to_funcs.len());
        for (position, (&entity, functions)) in self.propagation.surface_to_funcs.iter().enumerate()
        {
            if position % self.config.deadline_check_interval == 0 {
                control.check_active()?;
            }
            by_degree.push((functions.len(), entity));
        }
        by_degree.sort_by(|left, right| right.cmp(left));
        for (position, (_, entity)) in by_degree
            .into_iter()
            .take(self.config.hot_table_size)
            .enumerate()
        {
            if position % self.config.deadline_check_interval == 0 {
                control.check_active()?;
            }
            if let Some(functions) = self.propagation.surface_to_funcs.get(&entity) {
                self.propagation.hot_table.insert(entity, functions.clone());
            }
        }
        Ok(())
    }
}

fn build_name_fst(normalized: &[Arc<str>]) -> Result<NameFst, BelBuildError> {
    let mut sorted_ids: Vec<_> = (0..normalized.len() as EntityId).collect();
    sorted_ids.sort_by(|left, right| {
        normalized[*left as usize]
            .cmp(&normalized[*right as usize])
            .then_with(|| left.cmp(right))
    });
    let mut grouped: Vec<(Arc<str>, RoaringBitmap)> = Vec::new();
    for &id in &sorted_ids {
        let key = &normalized[id as usize];
        if let Some((last, postings)) = grouped.last_mut()
            && last.as_ref() == key.as_ref()
        {
            postings.insert(id);
            continue;
        }
        let mut postings = RoaringBitmap::new();
        postings.insert(id);
        grouped.push((key.clone(), postings));
    }
    let mut builder = MapBuilder::memory();
    for (index, (key, _)) in grouped.iter().enumerate() {
        builder
            .insert(key.as_bytes(), index as u64)
            .map_err(|error| BelBuildError::Fst(error.to_string()))?;
    }
    let bytes = builder
        .into_inner()
        .map_err(|error| BelBuildError::Fst(error.to_string()))?;
    let map = Map::new(bytes).map_err(|error| BelBuildError::Fst(error.to_string()))?;
    Ok(NameFst {
        map,
        postings: grouped.into_iter().map(|(_, postings)| postings).collect(),
        sorted_ids,
    })
}

fn current_annotation_slots(project: &Project) -> Vec<AnnotationSlot> {
    let mut slots = Vec::new();
    for (va, name, symbol_kind) in project.symbols.entries() {
        let entity_kind = match symbol_kind {
            SymbolKind::Import => EntityKind::Import,
            SymbolKind::Export => EntityKind::Export,
            SymbolKind::Function | SymbolKind::Data | SymbolKind::User => EntityKind::Symbol,
        };
        slots.push((
            format!("00:{va:016x}"),
            SlotKey {
                kind: SlotKind::Symbol,
                va,
            },
            entity_kind,
            name,
            Some(va),
            project.function_at(va).map(|function| function.entry_va),
        ));
    }
    for (va, text) in project.comments.addr_entries() {
        slots.push((
            format!("10:{va:016x}"),
            SlotKey {
                kind: SlotKind::AddressComment,
                va,
            },
            EntityKind::Comment,
            text,
            Some(va),
            owner_function_entry(project, va),
        ));
    }
    for (va, text) in project.comments.function_entries() {
        slots.push((
            format!("11:{va:016x}"),
            SlotKey {
                kind: SlotKind::FunctionComment,
                va,
            },
            EntityKind::Comment,
            text,
            Some(va),
            Some(va),
        ));
    }
    for (&va, card) in &project.function_memory {
        let display = [
            card.purpose.as_deref().unwrap_or_default().to_string(),
            card.tags.join(" "),
            card.key_apis.join(" "),
            card.key_strings.join(" "),
            card.purity.as_deref().unwrap_or_default().to_string(),
        ]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" | ");
        slots.push((
            format!("20:{va:016x}"),
            SlotKey {
                kind: SlotKind::MemoryCard,
                va,
            },
            EntityKind::MemoryCard,
            display,
            Some(va),
            Some(va),
        ));
    }
    let mut globals: Vec<_> = project.typed_globals.iter().collect();
    globals.sort_by_key(|(va, _)| **va);
    for (&va, ty) in globals {
        slots.push((
            format!("30:{va:016x}"),
            SlotKey {
                kind: SlotKind::GlobalType,
                va,
            },
            EntityKind::Type,
            project.types.render(ty),
            Some(va),
            owner_function_entry(project, va),
        ));
    }
    for (&va, signature) in project.function_signatures.iter() {
        let params = signature
            .params
            .iter()
            .map(|(name, ty)| format!("{name}: {}", project.types.render(ty)))
            .collect::<Vec<_>>()
            .join(", ");
        let display = format!(
            "{}({params}) -> {}",
            signature.name,
            project.types.render(&signature.ret)
        );
        slots.push((
            format!("31:{va:016x}"),
            SlotKey {
                kind: SlotKind::FunctionType,
                va,
            },
            EntityKind::Type,
            display,
            Some(va),
            Some(va),
        ));
    }
    slots
}

fn owner_function_entry(project: &Project, va: u64) -> Option<u64> {
    project.analysis.functions.iter().find_map(|function| {
        function
            .blocks
            .iter()
            .any(|block| va >= block.entry_va && va <= block.exit_va)
            .then_some(function.entry_va)
    })
}

pub fn normalize_ascii(text: &str) -> String {
    text.chars()
        .map(|character| character.to_ascii_lowercase())
        .collect()
}

fn insert_instruction_tokens(
    postings: &mut AHashMap<Arc<str>, RoaringBitmap>,
    text: &str,
    instruction_id: EntityId,
    function_id: Option<EntityId>,
) {
    for raw in text
        .split(|character: char| !character.is_ascii_alphanumeric() && character != '_')
        .filter(|token| !token.is_empty())
    {
        let token = if raw.bytes().any(|byte| byte.is_ascii_uppercase()) {
            std::borrow::Cow::Owned(raw.to_ascii_lowercase())
        } else {
            std::borrow::Cow::Borrowed(raw)
        };
        if let Some(existing) = postings.get_mut(token.as_ref()) {
            existing.insert(instruction_id);
            if let Some(function_id) = function_id {
                existing.insert(function_id);
            }
        } else {
            let mut entities = RoaringBitmap::new();
            entities.insert(instruction_id);
            if let Some(function_id) = function_id {
                entities.insert(function_id);
            }
            postings.insert(Arc::from(token.as_ref()), entities);
        }
    }
}

fn is_immediate(kind: OpKind) -> bool {
    matches!(
        kind,
        OpKind::Immediate8
            | OpKind::Immediate16
            | OpKind::Immediate32
            | OpKind::Immediate64
            | OpKind::Immediate8to16
            | OpKind::Immediate8to32
            | OpKind::Immediate8to64
            | OpKind::Immediate32to64
    )
}

/// Return hashes of all closed syncmers in `text`.
pub(crate) fn closed_syncmer_hashes(text: &[u8], k: usize, s: usize) -> Vec<u64> {
    if k == 0 || s == 0 || s >= k || text.len() < k {
        return Vec::new();
    }
    let mut hashes = Vec::new();
    for window in text.windows(k) {
        if is_closed_syncmer(window, s) {
            hashes.push(stable_u64_hash(window));
        }
    }
    hashes.sort_unstable();
    hashes.dedup();
    hashes
}

fn is_closed_syncmer(window: &[u8], s: usize) -> bool {
    let mut minimum = &window[..s];
    for candidate in window.windows(s).skip(1) {
        if candidate < minimum {
            minimum = candidate;
        }
    }
    &window[..s] == minimum || &window[window.len() - s..] == minimum
}

pub(crate) fn stable_u64_hash(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    bytes.iter().fold(OFFSET, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(PRIME)
    })
}

fn bitmap_bytes(map: &AHashMap<EntityId, RoaringBitmap>) -> u64 {
    map.values().map(|bitmap| bitmap.len() * 4).sum()
}

struct MemoryEstimateInput<'a> {
    entities: &'a [Entity],
    normalized: &'a [Arc<str>],
    names: &'a NameFst,
    kinds: &'a AHashMap<EntityKind, RoaringBitmap>,
    tokens: &'a AHashMap<Arc<str>, RoaringBitmap>,
    syncmers: &'a AHashMap<u64, RoaringBitmap>,
    numeric: &'a [(u64, EntityId)],
    signatures: &'a SignatureStore,
    propagation: &'a Propagation,
}

fn estimate_memory(input: MemoryEstimateInput<'_>) -> BelMemoryBreakdown {
    let entities_bytes = std::mem::size_of_val(input.entities) as u64
        + input
            .entities
            .iter()
            .map(|entity| entity.display.len() as u64)
            .sum::<u64>();
    let normalized_bytes = input
        .normalized
        .iter()
        .zip(input.entities)
        .filter(|(normalized, entity)| !Arc::ptr_eq(normalized, &entity.display))
        .map(|(text, _)| text.len() as u64)
        .sum();
    let surface_posting_bytes = input
        .names
        .postings
        .iter()
        .map(|bitmap| bitmap.len() * 4)
        .sum::<u64>()
        + input
            .kinds
            .values()
            .map(|bitmap| bitmap.len() * 4)
            .sum::<u64>();
    let token_posting_bytes = input.tokens.values().map(|bitmap| bitmap.len() * 4).sum();
    let syncmer_posting_bytes = input.syncmers.values().map(|bitmap| bitmap.len() * 4).sum();
    let numeric_bytes = std::mem::size_of_val(input.numeric) as u64;
    let signature_bytes = input
        .signatures
        .signatures
        .iter()
        .map(|signature| (signature.bits.len() * 8) as u64)
        .sum::<u64>()
        + input.signatures.rare_vocab.len() as u64 * 4
        + input.signatures.rare_lookup.len() * 4;
    let propagation_bytes = bitmap_bytes(&input.propagation.surface_to_funcs)
        + bitmap_bytes(&input.propagation.hot_table)
        + bitmap_bytes(&input.propagation.function_neighbors);
    let estimated_total_bytes = entities_bytes
        + normalized_bytes
        + surface_posting_bytes
        + token_posting_bytes
        + syncmer_posting_bytes
        + numeric_bytes
        + signature_bytes
        + propagation_bytes;
    BelMemoryBreakdown {
        entities_bytes,
        normalized_bytes,
        surface_posting_bytes,
        token_posting_bytes,
        syncmer_posting_bytes,
        numeric_bytes,
        signature_bytes,
        propagation_bytes,
        estimated_total_bytes,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::project::comments::CommentScope;
    use crate::project::op::Op;

    fn fixture_index(name: &str) -> (Project, Arc<BelIndex>, Arc<Overlay>) {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("gclsd/bench")
            .join(name);
        let project = Project::open(path).expect("open BEL fixture");
        let cancel = AtomicBool::new(false);
        let mut config = BelConfig::default();
        config.safety_cardinality = 1_000_000;
        let control = BelBuildControl {
            cancel: &cancel,
            deadline: None,
            progress: None,
        };
        let index = Arc::new(BelIndex::build(&project, config, &control).expect("build BEL"));
        let overlay = index.overlay(&project);
        (project, index, overlay)
    }

    fn result_ids(result: &SearchResult) -> Vec<EntityId> {
        let mut ids: Vec<_> = result.hits.iter().map(|hit| hit.entity_id).collect();
        ids.sort_unstable();
        ids
    }

    fn assert_matches_oracle(index: &BelIndex, overlay: &Overlay, mode: SearchMode, text: &str) {
        let query = Query {
            text: text.to_string(),
            mode,
            evidence: Vec::new(),
            quorum: None,
            relationship_depth: 1,
            kinds: Vec::new(),
        };
        let mut cursor = None;
        let mut actual = Vec::new();
        let mut reported_total = None;
        for _ in 0..1_000 {
            let result = search(
                index,
                overlay,
                &query,
                128,
                cursor.as_deref(),
                Instant::now() + Duration::from_secs(30),
            )
            .expect("BEL query");
            assert_eq!(result.total_kind, TotalKind::Exact, "query={text:?}");
            reported_total = Some(result.total);
            actual.extend(result.hits.iter().map(|hit| hit.entity_id));
            cursor = result.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        actual.sort_unstable();
        let mut oracle =
            query::linear_oracle_ids(index, overlay, mode, text).expect("linear oracle");
        oracle.sort_unstable();
        if actual != oracle {
            let actual_set: std::collections::BTreeSet<_> = actual.iter().copied().collect();
            let oracle_set: std::collections::BTreeSet<_> = oracle.iter().copied().collect();
            let missing: Vec<_> = oracle_set
                .difference(&actual_set)
                .take(20)
                .map(|id| {
                    let entity = &index.entities[*id as usize];
                    (*id, entity.kind, entity.va, entity.display.to_string())
                })
                .collect();
            let extra: Vec<_> = actual_set
                .difference(&oracle_set)
                .take(20)
                .map(|id| {
                    let entity = &index.entities[*id as usize];
                    (*id, entity.kind, entity.va, entity.display.to_string())
                })
                .collect();
            eprintln!("BEL oracle mismatch mode={mode:?} missing={missing:?} extra={extra:?}");
        }
        assert_eq!(reported_total, Some(oracle.len() as u64));
        assert_eq!(actual, oracle, "query={text:?}, mode={mode:?}");
    }

    #[test]
    fn normalization_changes_ascii_only() {
        assert_eq!(normalize_ascii("CreateFileW-É"), "createfilew-É");
    }

    #[test]
    fn closed_syncmers_are_deterministic_and_context_free() {
        let first = closed_syncmer_hashes(b"abcdefghijk", 5, 3);
        let second = closed_syncmer_hashes(b"xxabcdefghijkyy", 5, 3);
        assert!(!first.is_empty());
        assert!(first.iter().all(|hash| second.contains(hash)));
    }

    #[test]
    fn sparse_signature_overlap_is_fixed_width() {
        let mut left = SparseFunctionSignature::new(1024);
        let mut right = SparseFunctionSignature::new(1024);
        left.insert(7, 1024);
        right.insert(7, 1024);
        assert_eq!(left.overlap(&right), 1);
    }

    #[test]
    fn fst_preserves_duplicate_surface_entities() {
        let normalized: Vec<Arc<str>> = vec![
            Arc::from("duplicate"),
            Arc::from("duplicate"),
            Arc::from("wide-évidence"),
        ];
        let fst = build_name_fst(&normalized).expect("build duplicate FST");
        let posting = fst.map.get("duplicate").expect("duplicate key");
        assert_eq!(fst.postings[posting as usize].len(), 2);
    }

    #[test]
    fn cancellation_invalid_regex_and_short_query_safety_are_explicit() {
        let path =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("gclsd/bench/sample.exe");
        let project = Project::open(path).expect("open cancellation fixture");
        let cancelled = AtomicBool::new(true);
        let control = BelBuildControl {
            cancel: &cancelled,
            deadline: None,
            progress: None,
        };
        assert!(matches!(
            BelIndex::build(&project, BelConfig::default(), &control),
            Err(BelBuildError::Cancelled)
        ));

        *project.analysis.bel.building.lock().unwrap() = true;
        let waiting_cancel = AtomicBool::new(false);
        let waiting = BelBuildControl {
            cancel: &waiting_cancel,
            deadline: Some(Instant::now()),
            progress: None,
        };
        assert!(matches!(
            get_or_build(&project, BelConfig::default(), &waiting),
            Err(BelBuildError::Deadline)
        ));
        *project.analysis.bel.building.lock().unwrap() = false;
        project.analysis.bel.changed.notify_all();

        let cancel = AtomicBool::new(false);
        let mut config = BelConfig::default();
        config.safety_cardinality = 2;
        let control = BelBuildControl {
            cancel: &cancel,
            deadline: None,
            progress: None,
        };
        let index = BelIndex::build(&project, config, &control).expect("build safety index");
        let overlay = index.overlay(&project);
        let invalid = search(
            &index,
            &overlay,
            &Query {
                text: "(".to_string(),
                mode: SearchMode::Regex,
                evidence: Vec::new(),
                quorum: None,
                relationship_depth: 1,
                kinds: Vec::new(),
            },
            8,
            None,
            Instant::now() + Duration::from_secs(5),
        );
        assert!(matches!(
            invalid,
            Err(query::BelQueryError::InvalidRegex(_))
        ));
        let oversized = search(
            &index,
            &overlay,
            &Query::auto("x".repeat(16 * 1024 + 1)),
            8,
            None,
            Instant::now() + Duration::from_secs(5),
        );
        assert!(matches!(oversized, Err(query::BelQueryError::TooLarge(_))));
        let common = search(
            &index,
            &overlay,
            &Query::auto("e"),
            8,
            None,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("short-query safety result");
        assert!(common.truncated);
        assert_eq!(common.total_kind, TotalKind::LowerBound);
        assert!(common.refinement_suggestion.is_some());
    }

    #[test]
    fn entity_assignment_is_deterministic_across_builds() {
        let (project, first, _) = fixture_index("sample.exe");
        let cancel = AtomicBool::new(false);
        let control = BelBuildControl {
            cancel: &cancel,
            deadline: None,
            progress: None,
        };
        let second = BelIndex::build(&project, first.config.clone(), &control)
            .expect("second deterministic build");
        let first_keys: Vec<_> = first
            .entities
            .iter()
            .map(|entity| {
                (
                    entity.id,
                    entity.kind,
                    entity.display.clone(),
                    entity.va,
                    entity.file_offset,
                    entity.func_entry,
                )
            })
            .collect();
        let second_keys: Vec<_> = second
            .entities
            .iter()
            .map(|entity| {
                (
                    entity.id,
                    entity.kind,
                    entity.display.clone(),
                    entity.va,
                    entity.file_offset,
                    entity.func_entry,
                )
            })
            .collect();
        assert_eq!(first.generation, second.generation);
        assert_eq!(first_keys, second_keys);
    }

    #[test]
    fn bel_surface_modes_equal_linear_oracle() {
        let (_project, index, overlay) = fixture_index("sample.exe");
        let entity = index
            .entities
            .iter()
            .find(|entity| {
                matches!(
                    entity.kind,
                    EntityKind::Import
                        | EntityKind::Export
                        | EntityKind::String
                        | EntityKind::Symbol
                ) && entity.display.is_ascii()
                    && entity.display.len() >= 8
                    && entity.va.is_some()
            })
            .expect("fixture surface entity");
        let exact = entity.display.to_ascii_uppercase();
        let prefix: String = entity.display.chars().take(5).collect();
        let substring: String = entity.display.chars().skip(1).take(6).collect();
        let regex = regex::escape(entity.display.as_ref());
        let regex_hex_escape = format!(
            r"\x{:02x}{}",
            entity.display.as_bytes()[0],
            regex::escape(&entity.display[1..])
        );

        assert_matches_oracle(&index, &overlay, SearchMode::Exact, &exact);
        assert_matches_oracle(&index, &overlay, SearchMode::Prefix, &prefix);
        assert_matches_oracle(&index, &overlay, SearchMode::Substring, &substring);
        assert_matches_oracle(&index, &overlay, SearchMode::Regex, &regex);
        assert_matches_oracle(&index, &overlay, SearchMode::Regex, &regex_hex_escape);
        assert_matches_oracle(&index, &overlay, SearchMode::Token, "mov");
        let token_result = search(
            &index,
            &overlay,
            &Query {
                text: "mov".to_string(),
                mode: SearchMode::Token,
                evidence: Vec::new(),
                quorum: None,
                relationship_depth: 1,
                kinds: Vec::new(),
            },
            512,
            None,
            Instant::now() + Duration::from_secs(30),
        )
        .expect("token provenance query");
        let function_hit = token_result
            .hits
            .iter()
            .find(|hit| hit.kind == EntityKind::Function)
            .expect("aggregate token function hit");
        assert!(function_hit.provenance.iter().any(|proof| {
            proof.source_entity.is_some_and(|source| {
                index.entities[source as usize].kind == EntityKind::Instruction
            })
        }));
        assert_matches_oracle(
            &index,
            &overlay,
            SearchMode::Numeric,
            &format!("{:#x}", entity.va.expect("surface VA")),
        );
    }

    #[test]
    fn syncmer_acceleration_is_checksum_identical_to_oracle() {
        let (project, index, overlay) = fixture_index("complex.exe");
        assert!(index.syncmer_postings.complete);
        let query_text = index
            .entities
            .iter()
            .filter(|entity| {
                matches!(
                    entity.kind,
                    EntityKind::Import
                        | EntityKind::Export
                        | EntityKind::String
                        | EntityKind::Symbol
                ) && entity.display.is_ascii()
                    && entity.display.len() >= 10
            })
            .find_map(|entity| {
                let text = &index.normalized[entity.id as usize];
                (!closed_syncmer_hashes(
                    text.as_bytes(),
                    index.config.syncmer_k as usize,
                    index.config.syncmer_s as usize,
                )
                .is_empty())
                .then(|| text.to_string())
            })
            .expect("fixture substring with a closed syncmer");
        assert_matches_oracle(&index, &overlay, SearchMode::Substring, &query_text);
        let result = search(
            &index,
            &overlay,
            &Query {
                text: query_text.clone(),
                mode: SearchMode::Substring,
                evidence: Vec::new(),
                quorum: None,
                relationship_depth: 1,
                kinds: Vec::new(),
            },
            512,
            None,
            Instant::now() + Duration::from_secs(30),
        )
        .expect("syncmer query");
        assert_eq!(result.strategy, "closed_syncmer_verify");

        let mut fallback_config = index.config.clone();
        fallback_config.memory_budget_mb = 0;
        let cancel = AtomicBool::new(false);
        let fallback = BelIndex::build(
            &project,
            fallback_config,
            &BelBuildControl {
                cancel: &cancel,
                deadline: None,
                progress: None,
            },
        )
        .expect("memory-budget fallback index");
        assert!(!fallback.syncmer_postings.complete);
        let fallback_overlay = fallback.overlay(&project);
        assert_matches_oracle(
            &fallback,
            &fallback_overlay,
            SearchMode::Substring,
            &query_text,
        );
    }

    #[test]
    fn rename_comment_and_compaction_are_immediately_searchable() {
        let (mut project, index, baseline_overlay) = fixture_index("sample.exe");
        let cached_overlay = index.overlay(&project);
        assert!(Arc::ptr_eq(&baseline_overlay, &cached_overlay));
        assert!(baseline_overlay.entities.is_empty());
        assert!(baseline_overlay.normalized_overrides.is_empty());
        let (&va, _) = index
            .function_by_va
            .iter()
            .find(|(va, _)| project.symbols.get(**va).is_some())
            .expect("named fixture function");
        let old_name = project.symbols.name(va).expect("old name").to_string();
        let old_kind = project.symbols.get(va).expect("symbol").kind;
        let new_name = format!("bel_private_rename_{va:x}");
        project.op_seq = project.op_seq.saturating_add(1);
        Op::RenameSymbol {
            va,
            name: new_name.clone(),
            kind: old_kind,
            old_name: None,
            old_kind: None,
        }
        .apply_to(&mut project);
        let comment = format!("bel overlay comment {va:x}");
        project.op_seq = project.op_seq.saturating_add(1);
        Op::SetComment {
            va,
            scope: CommentScope::Function,
            text: comment.clone(),
            old_text: None,
        }
        .apply_to(&mut project);
        let overlay = index.overlay(&project);
        assert!(!Arc::ptr_eq(&baseline_overlay, &overlay));

        let renamed = Query {
            text: new_name.clone(),
            mode: SearchMode::Exact,
            evidence: Vec::new(),
            quorum: None,
            relationship_depth: 1,
            kinds: Vec::new(),
        };
        let result = search(
            &index,
            &overlay,
            &renamed,
            32,
            None,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("renamed search");
        assert!(result.hits.iter().any(|hit| hit.va == Some(va)));

        let stale = search(
            &index,
            &overlay,
            &Query {
                text: old_name,
                mode: SearchMode::Exact,
                evidence: Vec::new(),
                quorum: None,
                relationship_depth: 1,
                kinds: Vec::new(),
            },
            32,
            None,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("old-name search");
        assert!(!stale.hits.iter().any(|hit| hit.va == Some(va)));
        assert_matches_oracle(&index, &overlay, SearchMode::Exact, &comment);

        let mut runtime = BelRuntime {
            base: index.clone(),
            overlay: (*overlay).clone(),
        };
        let injected = "bel differential injection".to_string();
        runtime.update_overlay(AnnotationChange::Upsert {
            kind: EntityKind::Comment,
            display: injected.clone(),
            va: Some(va),
            function_va: Some(va),
            replaces: None,
        });
        let before = runtime
            .search(
                &Query {
                    text: injected.clone(),
                    mode: SearchMode::Exact,
                    evidence: Vec::new(),
                    quorum: None,
                    relationship_depth: 1,
                    kinds: Vec::new(),
                },
                32,
                None,
                Instant::now() + Duration::from_secs(5),
            )
            .expect("overlay before compaction");
        runtime
            .compact_overlay(&AtomicBool::new(false))
            .expect("compact overlay");
        let after = runtime
            .search(
                &Query {
                    text: injected,
                    mode: SearchMode::Exact,
                    evidence: Vec::new(),
                    quorum: None,
                    relationship_depth: 1,
                    kinds: Vec::new(),
                },
                32,
                None,
                Instant::now() + Duration::from_secs(5),
            )
            .expect("overlay after compaction");
        assert_eq!(result_ids(&before), result_ids(&after));
        let injected_id = after.hits[0].entity_id;
        runtime.update_overlay(AnnotationChange::Tombstone {
            entity_id: injected_id,
        });
        let removed = runtime
            .search(
                &Query {
                    text: "bel differential injection".to_string(),
                    mode: SearchMode::Exact,
                    evidence: Vec::new(),
                    quorum: None,
                    relationship_depth: 1,
                    kinds: Vec::new(),
                },
                32,
                None,
                Instant::now() + Duration::from_secs(5),
            )
            .expect("tombstoned overlay search");
        assert!(removed.hits.is_empty());
    }

    #[test]
    fn deadline_cursor_motif_ontology_and_multi_evidence_contracts() {
        let (_project, index, overlay) = fixture_index("complex.exe");
        let expired = search(
            &index,
            &overlay,
            &Query::auto("e"),
            8,
            None,
            Instant::now() - Duration::from_millis(1),
        )
        .expect("deadline result");
        assert!(expired.timeout_or_partial);
        assert_eq!(expired.total_kind, TotalKind::LowerBound);

        let broad = Query::auto("mov");
        let first = search(
            &index,
            &overlay,
            &broad,
            2,
            None,
            Instant::now() + Duration::from_secs(10),
        )
        .expect("first page");
        let repeated = search(
            &index,
            &overlay,
            &broad,
            2,
            None,
            Instant::now() + Duration::from_secs(10),
        )
        .expect("repeat page");
        assert_eq!(result_ids(&first), result_ids(&repeated));
        if let Some(cursor) = &first.next_cursor {
            let second = search(
                &index,
                &overlay,
                &broad,
                2,
                Some(cursor),
                Instant::now() + Duration::from_secs(10),
            )
            .expect("second page");
            assert!(first.hits.iter().all(|left| {
                second
                    .hits
                    .iter()
                    .all(|right| left.entity_id != right.entity_id)
            }));
        }

        let (motif, motif_functions) = index
            .motifs
            .tokens
            .iter()
            .find(|(_, functions)| !functions.is_empty())
            .expect("non-empty motif");
        let motif_result = search(
            &index,
            &overlay,
            &Query {
                text: motif.to_string(),
                mode: SearchMode::Motif,
                evidence: Vec::new(),
                quorum: None,
                relationship_depth: 1,
                kinds: Vec::new(),
            },
            512,
            None,
            Instant::now() + Duration::from_secs(10),
        )
        .expect("motif search");
        assert_eq!(motif_result.total, motif_functions.len());
        assert!(motif_result.hits.iter().all(|hit| {
            hit.provenance
                .iter()
                .any(|proof| proof.layer == ProvenanceLayer::Motif)
        }));

        let (class, class_id) = index
            .ontology
            .classes
            .iter()
            .find(|(_, class_id)| {
                index
                    .propagation
                    .surface_to_funcs
                    .get(class_id)
                    .is_some_and(|functions| !functions.is_empty())
            })
            .expect("ontology class with exact function evidence");
        let ontology_result = search(
            &index,
            &overlay,
            &Query {
                text: class.to_string(),
                mode: SearchMode::Ontology,
                evidence: Vec::new(),
                quorum: None,
                relationship_depth: 1,
                kinds: Vec::new(),
            },
            512,
            None,
            Instant::now() + Duration::from_secs(10),
        )
        .expect("ontology search");
        assert_eq!(
            ontology_result.total,
            index.propagation.surface_to_funcs[class_id].len()
        );

        let (target_id, clauses) = index
            .function_by_va
            .iter()
            .find_map(|(&function_va, &function_id)| {
                let clauses: Vec<_> = index
                    .entities
                    .iter()
                    .filter(|entity| {
                        entity.func_entry == Some(function_va)
                            && entity.kind == EntityKind::Instruction
                            && entity.display.len() >= 5
                    })
                    .take(2)
                    .map(|entity| entity.display.to_string())
                    .collect();
                (clauses.len() == 2).then_some((function_id, clauses))
            })
            .expect("function with two instruction evidence clauses");
        let multi = search(
            &index,
            &overlay,
            &Query {
                text: String::new(),
                mode: SearchMode::MultiEvidence,
                evidence: clauses,
                quorum: Some(2),
                relationship_depth: 1,
                kinds: Vec::new(),
            },
            512,
            None,
            Instant::now() + Duration::from_secs(20),
        )
        .expect("multi-evidence search");
        assert!(multi.hits.iter().any(|hit| hit.entity_id == target_id));
    }
}
