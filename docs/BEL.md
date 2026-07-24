# Binary Evidence Lattice (BEL)

BEL is Windy's local, deterministic search engine for PE evidence. It indexes
functions, symbols, imports, exports, extracted strings, formatted instructions,
numeric values, exact relationships, structural motifs, ontology labels, and
durable user annotations.

The implementation lives in `src/analysis/bel/`. The immutable base is stored
in `Analysis::bel` and shared across copy-on-write `Project` snapshots. The
current project state produces an operation-generation-keyed differential
overlay snapshot, so a rename, comment, type, or memory-card write is
searchable immediately without rescanning unchanged symbols on every query.

## Guarantees

- Exact, prefix, substring, numeric, token, and regex hits are verified against
  stored original or once-normalized evidence.
- Exact and substring modes have no false negatives when `total_kind=exact`.
  A deadline or safety-cardinality stop is explicitly returned as
  `total_kind=lower_bound`, `truncated=true`, and `timeout_or_partial=true`.
- ASCII case folding happens once during index construction and once for the
  query. Candidate strings are never lowercased in the hot loop.
- Query execution is synchronous and cooperative. It never starts detached
  work. Once a deadline result returns, no work from that query remains.
- Entity assignment, ranking, tie-breaking, and cursors are deterministic for
  an index/overlay generation.
- Every returned hit has a strategy, reason, and provenance path.
- The immutable base is never edited. Overlay writes and tombstones are
  separately compactable and preserve stable entity IDs.

## Index layers

1. `EntityStore`: dense `u32` IDs and one original display value per item.
2. `NameFst`: normalized exact dictionary with bitmap values for duplicates and
   a deterministic sorted ID array for prefix scans.
3. `TokenPostings`: instruction tokens and the functions containing them.
4. `SyncmerPostings`: closed-syncmer candidate postings for selective
   substring and required-regex-literal queries.
5. `NumericIndex`: sorted `(value, EntityId)` entries for VAs, file offsets,
   and decoded immediates.
6. `SignatureStore`: 1024-bit sparse evidence signatures for functions.
7. `Propagation`: exact surface-to-function and bounded call-neighbor edges,
   plus a hot table for high-degree evidence.
8. `MotifIndex`: exact structural tags such as `loop_backedge`,
   `conditional_control`, `indirect_dispatch`, `dispatcher`, and
   `leaf_function`.
9. `EvidenceOntology`: a deterministic DAG rooted at `evidence`, with static
   network, crypto, filesystem, process, memory, registry, and UI classes plus
   exact pairwise co-occurrence classes below their parents.
10. `Overlay`: current names/comments/types/memory, tombstones, signature
    deltas, numeric entries, and relationship deltas.

Closed syncmers are only an acceleration structure. A query with no usable
syncmer, or an index whose syncmer budget was exhausted, takes the complete
cooperative linear verification path. This fallback is required: sparse
sampling by itself is not a proof of completeness for every possible short
query.

## Construction and single flight

Construction stages are functions, symbols, strings, instructions, annotations,
motifs, exact relationships, ontology enrichment, syncmers, FST/numeric
finalization, signatures, and the hot table. Long explicit loops check an
atomic cancellation flag and optional deadline at bounded intervals and report
stage progress.

`BelIndexCell` is single-flight. The private beta starts one lifecycle build
after a PE opens. If an agent searches during that build, it waits on the same
cell up to its own deadline rather than constructing a second index. Manager
shutdown raises the builder cancellation flag and joins cleanly.

## Query modes

Use the MCP tool `search_bel`:

```json
{
  "project_id": "...",
  "query": "CreateFileW",
  "mode": "substring",
  "limit": 32,
  "deadline_ms": 30000
}
```

Modes:

| Mode | Seed and verification path |
|---|---|
| `exact` | FST lookup, duplicate bitmap, exact normalized verification |
| `prefix` | sorted normalized range, exact prefix verification |
| `substring` | rare closed-syncmer intersection or complete linear fallback, then exact verification |
| `numeric` | binary range over VA/file-offset/immediate postings |
| `regex` | conservative required-literal seed when provably mandatory, then ASCII-case-insensitive Rust regex verification; otherwise cooperative linear verification |
| `token` | mnemonic/operand token bitmap |
| `relationship` | verified surface seeds, exact surface-to-function edge, optional bounded call-graph extension |
| `motif` | exact motif postings to functions |
| `ontology` | exact class postings to functions |
| `multi_evidence` | independent verified clauses, quorum, exact propagation, signature-assisted ranking |

`mode=auto` also accepts `exact:`, `prefix:`, `substring:`, `number:`,
`regex:`, `token:`, `related:`, `motif:`, and `ontology:` prefixes. A leading
slash selects regex, and a valid decimal or `0x` literal selects numeric mode.

For multi-evidence:

```json
{
  "project_id": "...",
  "query": "recv",
  "mode": "multi_evidence",
  "evidence": ["socket", "WSAGetLastError", "loop_backedge"],
  "quorum": 2
}
```

`kinds` can restrict direct surface results to any serialized `EntityKind`.
Relationship, motif, ontology, and multi-evidence results are functions.

## Ranking and cursors

BEL computes the architecture score in deterministic fixed-point form:

```text
match weight
+ inverse-DF affinity × exactness
+ independent evidence-kind cooperativity
+ sparse signature overlap
+ ontology boost
+ display-length specificity
```

Tie-breaks are `entity_id` then VA ascending. The public `score` is the fixed
point value converted to `f32`; ordering never depends on floating-point
comparison. Ranking retains only one page plus a lookahead item in a bounded
heap; display strings are materialized only for returned hits.

`next_cursor` encodes the base generation, overlay generation, query
fingerprint, fixed-point score, entity ID, and VA. Reusing a cursor after a
write or with another query returns `INVALID_BEL_QUERY` rather than silently
skipping or duplicating results.

## Overlay semantics

Visible evidence is `(base − tombstones) ∪ overlay`. Renamed functions need one
extra distinction: their stable function entity remains valid for graph and
signature edges, while its old surface text is tombstoned and its display is
overridden. This keeps relationship results stable without leaving stale names
searchable.

Windy's production path derives the overlay from the current journaled project
snapshot and caches it by `op_seq`; a write creates a new generation on the
next query. Embedders can use `BelRuntime`, `AnnotationChange`,
`update_overlay`, and cooperative `compact_overlay` directly.

## Safety and totals

- Invalid regex and numeric values are explicit query errors.
- Query text/evidence clauses are capped at 16 KiB and multi-evidence input at
  64 clauses.
- One- and two-character substring/prefix queries use the lower short-query
  safety cardinality.
- The normal safety cardinality bounds retained candidates for huge/common
  searches.
- A complete cheap intersection returns `total_kind=exact`.
- A deadline or safety stop returns the verified match count as a lower bound,
  a refinement suggestion, and no claim of completeness.
- Page size is capped at 512. Legacy `search_summary` keeps offset pagination
  through 511; deeper navigation uses BEL cursors.

## Defaults and memory

Defaults are `k=5`, `s=3`, 1024-bit signatures, rarity threshold 8, hot table
256, quorum 2, safety cardinality 100,000, relationship depth 1, maximum
lattice depth 2, and a 768 MiB budget. One quarter of the budget is reserved
for conservative raw syncmer-occurrence accounting. If that portion would be
exceeded, the incomplete syncmer map is discarded and substring queries use
the exact fallback.

Instruction display and normalized text share the same `Arc<str>` when no
ASCII uppercase conversion is needed. Instruction-to-function ownership is
derived directly from the entity instead of allocating millions of one-element
relationship bitmaps.

`get_server_status` exposes `bel_ready`, `bel_building`, stage activity, and a
component memory estimate. The optional FM-index switch is rejected if enabled
in this build; the complete syncmer/linear path is authoritative.

## Verification and benchmarks

```powershell
cargo test --features beta analysis::bel
cargo run --release --features beta -- bench bel --pe C:\path\target.exe --iterations 100
```

The benchmark reports cold PE open/build time, component memory, warm
p50/p95/p99, selected strategy, totals, and paginated linear-oracle checksums
for direct modes, including broad token searches up to 100,000 hits. The test
suite covers mixed ASCII case, duplicate FST values, syncmer and budget-fallback
oracle equality, numeric/escaped-regex/prefix/exact/substring/token equality,
renames, comments, tombstones, compaction, deterministic rebuilds, stale-free
cursors, deadlines, cancellation, input/short-query safety, motifs, populated
ontology, and quorum multi-evidence.

Research lineage: closed syncmers (Edgar 2021), seed-and-extend (BLAST), Roaring
bitmaps (Chambi/Lemire et al.), finite-state dictionaries, sparse coding,
hierarchical ontologies, and classic exact inverted-index verification. BEL's
correctness comes from complete candidate paths plus verification—not from the
biological analogies.
