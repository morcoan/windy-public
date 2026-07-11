# Agent-Native Reconstruction Runtime
## A 12–18 Month Systems Roadmap for Catalog Reconstruction in Cultural Heritage Collections

**Audience:** board, engineering lead, and pilot-institution registrars.
**Scope:** a headless runtime that lets LLM agents reconstruct incomplete exhibition catalogs from fragmentary object records, partial condition reports, box inventories with opaque accession numbers, multi-venue loan packages, and mislabeled photo contact sheets. It is not a CMS, not a DAM, and not a chat product.

---

## 1. Design thesis

The failure mode of naive AI bridges to museum systems is well understood: they mirror the CMS. A hundred menu actions become a hundred tools, a query returns four thousand rows, and the model drowns. The classical systems (TMS, EMu, PastPerfect, CollectionSpace and their peers) win on catalog depth, Spectrum-procedure coverage, and format breadth, and they should keep winning there. This runtime competes on exactly one axis: how efficiently and safely an agent can turn fragmentary documentation into verified catalog structure.

Three commitments follow from that axis, and everything in this roadmap is downstream of them.

First, **evidence over dumps**. An agent never receives a table scan. It receives compact, token-budgeted evidence cards in which every field carries a citation back to an immutable source fragment (a scanned registrar card, a row in a box inventory, a frame on a contact sheet). If the agent wants more, it asks for a specific bounded excerpt.

Second, **claims, not edits**. The unit of agent output is a claim ("this sherd joins vessel 19", "frame 14 on contact sheet CS-1987-03 depicts accession 87.112.4a") evaluated against measured and documentary evidence, producing a verdict of supported, contradicted, or insufficient — with insufficient being a first-class, rewarded outcome. Writes to the graph are two-phase proposals with a complete inverse, so every rename, relabel, merge, and containment change is durable and reversible.

Third, **the catalog is a recovered graph**. Objects, parts, crates, venues, loan packages, images, and documents are nodes; the product's job is recovering typed edges among them from degraded evidence. Quality is therefore measured the way graph recovery is measured — per-edge-type precision and recall, cluster metrics for identity, tree metrics for containment — against gold built from public museum open data plus adjudicated pilot data.

The operating loop: ingest → fragment → extract field observations → block and propose identities → agent investigates via cards and claim checks → human review queue → reversible commit → notes persist to the next session.

---

## 2. Data model

Six layers, all in one Postgres instance for the first 18 months (sources in S3-compatible object storage). The layering matters more than the storage engine: the bottom layers are immutable and the top layers are event-sourced, which is what makes undo, audit, and benchmark replay cheap.

### 2.1 Layer overview

**Source layer (immutable).** `source_documents` (one per ingested artifact: a PDF condition report, a spreadsheet, a contact sheet scan) and `fragments` (the addressable unit: a page region, a spreadsheet row, a single contact-sheet frame, an OCR block). Fragments carry checksums, byte/page/frame locators, OCR text, and image references. Nothing above this layer is ever quoted without a fragment ID.

**Observation layer.** `field_observations`: (fragment_id, field, value_raw, value_norm, extractor@version, confidence). Extraction is versioned so a better accession-number parser can re-run over the same fragments and its outputs can be diffed. Measurements normalize to millimeters/grams in `measurements` with dimension type (height, rim diameter, wall thickness at break) and stated tolerance.

**Identity layer.** `entities` are candidate real-world things — objects, vessels, sherds-as-parts, crates, trays, loan packages, venues, exhibitions, lenders. `entity_members` links fragments to entities with weights; an entity is literally a cluster over fragments, and merges/splits are events, not destructive updates. `aliases` holds every designation an entity has ever carried: raw string, canonical key, scheme guess, and lineage (`succeeds_number`) so a 1994 renumbering campaign is queryable history rather than lost context.

**Assertion layer.** `edges`: (src, dst, rel_type, status, confidence, evidence_refs[], created_by, workspace_scope). Status lifecycle is proposed → accepted | rejected | superseded. `claims` and `claim_evaluations` record every claim check ever run, with the evidence gathered and the verdict, so calibration is measurable over time.

**Containment and logistics layer.** `containers` (self-referential, typed: crate, tray, cavity, mount) plus a closure table for fast subtree queries. `packages` (a loan or exhibition) → ordered `venue_legs` → `leg_events` (incoming condition check, outgoing condition check, courier note). `container_assignments` scope object-in-container facts to a leg or a time interval, with a database-level exclusion constraint (GiST on object_id, overlapping interval) so one object can never be silently in two crates at once.

**Memory and control layer.** `notes` (workspace-scoped, taggable, retrievable — the agent's cross-session memory), `workspaces` and `grants` (capability tokens scoping read and write classes), and `change_events` — the append-only ledger. Every mutation is an event with a stored inverse; `revert(change_id)` replays the inverse. This table is the undo system, the audit trail, and the reproducibility mechanism for evaluations.

### 2.2 Schema sketch (abridged)

```sql
fragments(id, source_id, kind, locator jsonb, sha256, text, image_ref)
field_observations(id, fragment_id, field, value_raw, value_norm,
                   extractor, extractor_ver, confidence)
measurements(id, entity_id, fragment_id, dim_type, value_mm numeric,
             tolerance_mm numeric)
entities(id, entity_type, best_label, workspace_visibility)
entity_members(entity_id, fragment_id, weight, since_event)
aliases(id, entity_id, raw, canonical_key, scheme_guess, part_suffix,
        supersedes_alias)
edges(id, src, dst, rel_type, status, confidence, evidence_refs uuid[],
      created_by, workspace_scope, since_event)
claims(id, claim_type, payload jsonb, workspace)
claim_evaluations(claim_id, verdict, confidence, evidence_refs uuid[],
                  checker_ver, ts)
containers(id, container_type, label, dims_envelope_mm int[3])
containment_closure(ancestor, descendant, depth)
container_assignments(object_id, container_id, leg_id, during tstzrange,
  EXCLUDE USING gist (object_id WITH =, during WITH &&))
packages(id, title, kind); venue_legs(id, package_id, venue_id, seq,
  arrive, depart); leg_events(id, leg_id, object_id, event_type, fragment_id)
notes(id, workspace_id, subject_entity, text, tags text[], author, ts)
change_events(seq bigserial, entity_id, event_type, payload jsonb,
              inverse jsonb, actor, proposal_id, ts)
```

### 2.3 Relation ontology v1

Fifteen edge types, frozen as a versioned spec in month 1, mapped to CIDOC-CRM properties where the mapping is clean (e.g., `part_of` ≈ P46, `located_in` ≈ P55, `documented_in` ≈ P70) and recorded as advisory where it is contested. The set: `part_of`, `joins` (physical sherd-to-sherd join, symmetric), `same_as` (identity merge candidate), `depicted_in` (object↔image), `documented_in` (object↔condition report / registrar card / correspondence), `located_in`, `packed_in` (leg-scoped), `contains` (container nesting), `included_in` (object↔exhibition checklist), `borrowed_for` (object↔package), `lent_by`, `exhibited_at` (package leg↔venue), `condition_event_of`, `succeeds_number` (alias lineage), `derived_from` (fragment provenance, e.g., an OCR block from a scan). Anything outside these fifteen is expressed as a note until the ontology is deliberately revised, which is a governance event, not a pull request.

### 2.4 Accession-number canonicalization

Opaque numbering is the single highest-leverage extraction problem, so it gets an explicit algorithm rather than a prompt. Canonicalization: uppercase; collapse whitespace; map separator classes (., -, /, space) to a single delimiter while retaining the raw form; expand two-digit years with an era heuristic bounded by the institution's founding date; zero-pad numeric segments to fixed width per segment position; detect and split part suffixes (`1998.24.13a–c` yields a parent alias plus three part aliases with `part_of` proposals); emit a scheme guess (tripartite year.lot.object, L-prefixed loan numbers, TR temporary receipts, X unaccessioned, field/excavation numbers with context-locus-lot shape). Ambiguity is preserved: a string that canonicalizes plausibly under two schemes produces two candidate keys, both indexed, and disambiguation becomes a claim for the agent rather than a silent guess in the parser.

---

## 3. Indexes

Concrete, because retrieval quality is the ceiling on everything the agent does downstream.

**Alias matching.** B-tree on `aliases(canonical_key)` for exact canonical hits; GIN with `pg_trgm` on `aliases(raw)` for fuzzy matching of corrupted numbers, with similarity thresholds tuned per scheme guess (loan numbers tolerate less fuzz than handwritten field numbers). A small side table of per-institution scheme statistics feeds the threshold tuning.

**Lexical search.** Postgres full-text (tsvector, per-language configs) with GIN over fragment text and over rendered card text. OpenSearch/Tantivy is explicitly deferred unless p95 search latency exceeds target beyond ~5M fragments; one database is worth a lot of operational simplicity to a nonprofit.

**Vector search.** pgvector HNSW indexes on two embedding spaces: text embeddings over fragments and cards, and image embeddings (an open CLIP/SigLIP-family model) over contact-sheet frames and catalog photography, enabling cross-modal frame-to-record matching. Workspace filtering uses partitioned embedding tables rather than post-filtering so recall under filters stays honest — this is the classic HNSW-plus-filter trap and it is worth designing around on day one.

**Measurements.** B-tree on `measurements(dim_type, value_mm)` so join candidacy queries ("rim diameter within ±3 mm, wall thickness at break within ±0.8 mm") are range scans, not table scans.

**Graph adjacency.** Composite b-trees on `edges(src, rel_type, status)` and `edges(dst, rel_type, status)`; a partial index `WHERE status = 'proposed'` backs the human review queue. `containment_closure(ancestor, descendant)` primary key plus a descendant-first index makes "everything in crate 12" and "path from sherd to pallet" both single index scans.

**Ledger.** `change_events` is append-only: BRIN on ts for time-window audits, b-tree on (entity_id, seq) for per-entity replay.

---

## 4. Agent tool surface: evidence over dumps

Twelve tools, frozen as a versioned contract. The discipline is behavioral, not just numerical: every read is capped, cited, and deterministic; every write is a proposal with evidence; abstention is a legal answer everywhere.

| Tool | Purpose | Caps & contract |
|---|---|---|
| `search_evidence(q, filters)` | Hybrid lexical+vector search over fragments and cards | ≤25 hits, each a ≤3-line teaser + fragment citation; cursor pagination; deterministic order |
| `get_card(entity_id, view)` | The workhorse: evidence card with view = core, conservation, movement, imagery | ≤600 tokens; 100% field citation |
| `get_fragment(fragment_id, span)` | Bounded raw excerpt of a source | ≤1,500 chars or one image frame; includes page/frame locator |
| `find_candidates(anchor, rel_type)` | Ranked candidates for a relation (join partners, parent vessel, matching frames) | ≤25; each with feature attribution ("rim Ø Δ1.8 mm; same excavation lot; fabric term match") |
| `check_claim(claim)` | Structured claim → verdict + evidence + calibrated confidence | Verdicts: supported / contradicted / insufficient; never returns a verdict without ≥1 measured or documentary evidence item |
| `propose_change(kind, payload, evidence[], note)` | link, unlink, rename, relabel, merge, split, move_container | Returns proposal_id; evidence refs mandatory (notes exempt); idempotency key required |
| `apply(proposal_id)` | Commit, if the workspace grant allows this change class to auto-apply; otherwise queues for review | Writes one change_event with stored inverse |
| `revert(change_id)` | Inverse replay | Always available to the change's workspace; cascading reverts are explicit, never implicit |
| `notes_write / notes_search` | Cross-session memory | Workspace-scoped; taggable; searchable via the same hybrid index |
| `container_view(id or object_id, leg)` | List a container's contents or an object's containment path for a leg | Subtree responses capped at 50 nodes with cursors |
| `diff_legs(package_id, legA, legB)` | Venue-to-venue discrepancy report | Returns typed discrepancies (missing outgoing, condition delta, crate reassignment), each cited |
| `history(entity_id)` | The ledger, per entity | Cursor pagination |

**Evidence card anatomy** (the ≤600-token contract): a header (entity ID, best label, alias list with schemes), key observed fields each with superscript fragment citations, normalized measurements, the entity's accepted and proposed edges with status, open questions ("two candidate parents; lot adjacency supports V.19 [f-2231], rim profile drawn only for V.7 [f-0904]"), and a "what would resolve this" hint line. Cards are rendered, cached, and invalidated by the event log — they are a product surface, and their information density per token is a tracked metric, not an aesthetic.

**Access control** is capability-token based: a token grants a workspace, a read scope, and a set of auto-applyable change classes (e.g., notes always; relabels of agent-created labels usually; merges and joins never — those queue for a registrar). Donor and lender personal data is a restricted field class excluded from cards by default.

---

## 5. Claim checks against measured evidence

Claim families ship with dedicated deterministic evidence gatherers; the LLM narrates, but the gatherers decide what counts.

**Join / part-whole** ("this sherd joins vessel 19"): dimensional compatibility (wall thickness at break within tolerance, rim diameter arc consistency), fabric/ware/medium term compatibility via AAT-anchored normalization of free-text terms, findspot adjacency (same or adjacent excavation context/locus/lot), part-suffix logic (an `a` part with a documented `a–c` parent), and image evidence (embedding similarity between sherd photography and vessel photography above a per-corpus threshold, always flagged for human visual confirmation, never auto-accepted alone).

**Identity** ("box-inventory row 214 is the same object as registrar card 87.112.4"): canonical alias match or lineage, measurement agreement, medium/culture agreement, and negative checks (conflicting dimensions beyond tolerance contradict rather than merely fail to support).

**Containment and movement** ("this vessel was in crate 12, tray B during the second venue leg"): crate-list mentions, condition-report phrases ("removed from crate 12, tray B" is a first-class extraction pattern), leg-scoped assignment consistency, and the exclusion constraint as a hard backstop.

**Checklist membership** ("this object was in the 1987 venue-two hanging"): loan correspondence, per-leg condition events (an incoming condition report at a venue is strong membership evidence), catalog/label transcripts.

Every evaluation is persisted with its evidence, checker version, and confidence, which makes the calibration program (§11) possible: reliability diagrams per claim family, expected calibration error targets, and — critically — **abstention precision**: when the system says "insufficient," was resolving evidence actually absent from the corpus, or did retrieval miss it? Gold for that question comes from the benchmark harness, where we know what evidence exists.

---

## 6. Measuring graph and relationship recovery

Identity clusters are scored with pairwise F1 and B³ F1 (both reported; B³ behaves better under the heavy cluster-size skew that shredded museum records produce). Typed edges are scored per relation with precision/recall at accepted status, plus upstream candidate recall@k, because a claim checker cannot rescue a candidate generator that never surfaces the true join partner. Hierarchies — part-whole trees and crate nesting — are scored with normalized tree edit distance and exact-path accuracy. Exhibition checklists are scored as set F1 per exhibition plus venue-leg attribution accuracy (right object, wrong venue is a distinct, tracked error). Temporal containment violations are structurally impossible to commit (the exclusion constraint), so the metric there is detection recall on injected violations in synthetic packages.

One system-level number matters most and is reported alongside every capability metric: **verified edges per thousand agent tokens**, benchmarked against a naive baseline agent given raw table dumps over the identical corpus. The runtime's reason to exist is that this ratio is several times better and never comes at the cost of an irreversible error.

---

## 7. Benchmark program from public museum open data

Build the harness before the product (Phase 0). The method throughout is **degrade-and-recover**: take clean, openly licensed collection data as hidden ground truth, apply parameterized degradation operators (field dropout, OCR-style character noise, record shredding into simulated source types, label shuffling, separator corruption in accession numbers), and score reconstruction. Fixed agent budgets (max tool calls, max tokens) make runs comparable; hidden test splits keep them honest.

| Suite | Source data | Task & gold | Primary metrics |
|---|---|---|---|
| **Met-Shred** | The Met Open Access CSV (CC0, ~480k object rows) | Each record shredded into 2–5 fragments styled as registrar card / inventory row / label transcript, plus noise; recover identity clusters | B³ F1, pairwise F1 |
| **Accession Gauntlet** | Numbering styles drawn from Met, Smithsonian Open Access, Rijksmuseum, Tate (frozen GitHub snapshot), National Gallery of Art open data, plus synthetic legacy corruptions (dots→dashes, two-digit years, dropped lot segments, transcription slips) | Match corrupted designations to canonical records | Alias match P/R/F1; canonicalization accuracy per scheme |
| **PartWhole** | Smithsonian and Met multi-part records (a/b/c… suffixes); NGA per-object dimension rows | Recover parent-part trees from shredded part records | Parent recovery F1; tree edit distance |
| **Joins-Arch** | Archaeological datasets (Open Context; Penn Museum's published object data) providing real context/locus/lot structure, seeded with synthetic sherd attributes (fabric class, wall thickness, rim diameter) drawn from plausible distributions | Sherd→vessel join recovery with measured evidence | Candidate recall@25; verdict accuracy vs. gold joins; ECE |
| **Checklist-Recon** | MoMA's open exhibition dataset (exhibitions with participant links from 1929 onward; artwork-level links partial, so gold is the explicitly linked subset) with links hidden; Cleveland Museum of Art open access exhibition-history fields as alternate gold | Reconstruct exhibition membership from partial checklists, correspondence-style text, and label transcripts | Checklist set F1; venue attribution accuracy |
| **ContactSheet-CC0** | CC0 images from Met and CMA, downscaled to grayscale "frames," labels shuffled and truncated | Re-match frames to object records; repair labels | Match recall@5; label-repair accuracy |
| **CrateNest & LoanLegs** | Synthetic generators seeded with real object dimensions (Met, NGA) to build crate→tray→cavity manifests and multi-venue packages, then shredded into partial packing lists and per-leg documents; discrepancies injected (object absent from a leg's outgoing report, silent crate swap) | Reconstruct containment trees; detect discrepancies | Path accuracy, tree edit distance; discrepancy detection recall at ≤5% FPR |

Two honest caveats shape the program. First, museums do not publish condition reports, crate lists, or courier files, so those suites are synthetic-seeded-by-real; the only real gold for them comes from pilot institutions, which is why the roadmap budgets quarterly adjudication sessions with registrars (~200 adjudicated claims per quarter, compensated) starting in Phase 2. Second, license hygiene: redistribute only CC0-derived suites (Met, Smithsonian OA, CMA, NGA qualify); treat other sources as eval-only inside the harness and verify terms per source before any public release.

---

## 8. Multi-package loans and shared workspaces

A loan or exhibition is a `package`; a package has ordered `venue_legs`; a workspace is a scoped view-plus-write-grant over one or more packages. The design decision that prevents the classic mess: **identity is global, assertion is scoped**. The same vessel appearing in a 1998 traveling show and a 2004 single-venue loan is one entity; but a workspace's proposed edges live in that workspace's scope until promoted. When two workspaces assert incompatible facts — venue-two's team places the vessel in crate 12 while the study-collection workspace records it back on shelf R4 for the same interval — the runtime does not last-write-win. It raises a typed conflict into both review queues, with both evidence chains side by side, and the exclusion constraint blocks commit until a human resolves which interval is wrong.

`diff_legs` is the daily-driver tool here: given a package and two consecutive legs, it reports objects present in leg N's incoming documents but absent from leg N−1's outgoing, condition deltas between paired condition events, and crate reassignments between legs — each finding cited to the fragments that generated it. Reconstruction of historical multi-venue packages (the nonprofit's core backlog case) is the same machinery run over archival documents instead of live ones.

## 9. Archival crates as nested packages

Crates are first-class entities, not string fields. The containment model is a typed tree — crate → tray → cavity/mount — with dimension envelopes per container, backed by the closure table for subtree and path queries and by leg-scoped assignments for time. Packing manifests are *reconstructed*, not assumed: crate-list fragments, condition-report phrases, and courier notes each contribute `packed_in` and `contains` proposals, and the tree the reviewers accept is the manifest. Integrity rules: single parent per object per leg (hard, via the exclusion constraint); dimension sanity (object dimensions must fit the cavity envelope with padding tolerance) as a *flag*, never a hard block, because historical dimension data is dirty and a false block teaches users to distrust the system. Crates get renamed and relabeled as often as objects do — "Crate 12" in the 1998 files is "MFA-C-012" in the 2001 files — so crates get aliases, `succeeds_number` lineage, and the same reversible rename machinery as everything else.

---

## 10. Phased roadmap, months 0–18

**Phase 0 — Benchmark-first foundations (months 0–1).** Stand up Postgres + pgvector + pg_trgm + FTS and object storage; freeze relation ontology v1 and the evidence-card contract as versioned specs; implement the degradation harness and ship Met-Shred and the Accession Gauntlet; run the naive-dump baseline agent and publish its numbers internally. *Exit criteria:* harness runs in CI; baseline B³ F1 and tokens-per-verified-edge recorded; specs signed off by one practicing registrar.

**Phase 1 — Evidence substrate and read-only agent surface (months 1–4).** Ingestors for the three highest-value source types: spreadsheet/CSV box inventories, OCR'd PDF condition reports (using existing OCR, not our own — see §12), and contact-sheet scans with per-frame segmentation and image embeddings. Fragment store, field observations, canonicalization v1, alias indexes, cards v1, and the read-only tool set (`search_evidence`, `get_card`, `get_fragment`, `find_candidates`). One pilot conservator team goes hands-on, read-only. *Exit criteria:* Accession Gauntlet F1 ≥ 0.90; Met-Shred candidate recall@25 ≥ 0.85; p95 read latency ≤ 500 ms; pilot team retrieves against real documents weekly.

**Phase 2 — Identity, claims, and reversible writes (months 4–7).** Entity clustering (blocking on canonical keys, embedding candidates, rule features) with reviewable merges; `check_claim` v1 for identity and part-whole families; the full proposal ledger (`propose_change` / `apply` / `revert`) with review queues; rename/relabel end-to-end with undo; notes API. First quarterly gold-adjudication session with pilot registrars. Weekly chaos drill: random revert-and-replay of the day's events must reproduce state bit-for-bit. *Exit criteria:* Met-Shred B³ F1 ≥ 0.80; claim verdict accuracy ≥ 0.75 on adjudicated gold; zero irreversibility defects in four consecutive chaos drills; a real relabeling backlog (≥200 labels) executed and one deliberately reverted.

**Phase 3 — Relationship recovery at scale (months 7–10).** Join and part-whole recovery on Joins-Arch and PartWhole; the contact-sheet relabeling loop (embedding retrieval → agent claim → human visual confirm → durable relabel); `documented_in` linking of condition reports to objects; checklist reconstruction v1 on Checklist-Recon. A thin review UI for cluster- and claim-level approval, because the reviewers are conservators and registrars, not engineers. *Exit criteria:* join candidate recall@25 ≥ 0.85 with verdict accuracy ≥ 0.80; ContactSheet match recall@5 ≥ 0.85; checklist F1 ≥ 0.55 (this is the hard task; the target is honest); reviewer median time-per-decision under 45 seconds.

**Phase 4 — Loans, legs, crates, shared workspaces (months 10–13).** Package/leg/leg-event model; `diff_legs`; containment trees with leg-scoped assignments and the exclusion constraint; cross-workspace identity sharing with scoped assertions and the conflict queue; CrateNest and LoanLegs suites drive development. One pilot reconstructs a real historical multi-venue exhibition end-to-end. *Exit criteria:* containment path accuracy ≥ 0.85; discrepancy detection recall ≥ 0.90 at ≤5% FPR; one real traveling-exhibition archive reconstructed with a registrar's sign-off; conflict queue exercised on a real cross-workspace collision.

**Phase 5 — Calibration, breadth, hardening, openness (months 13–18).** Calibration program to ECE ≤ 0.05 per major claim family; importers two and three (TMS and EMu export formats — mapped, tested, done well, and nothing else); security review of capability tokens and restricted-field handling (lender/donor data); backup-restore and ledger-replay drills at scale; pilots expand to three institutions; public release of the CC0 benchmark suites and eval kit under the working name **ReCat**, with the naive-dump baseline included so the field can reproduce the comparison. *Exit criteria:* M18 scoreboard targets (§11) met; three pilots active with signed data agreements; ReCat public with ≥1 external group running it.

---

## 11. Metrics scoreboard

North star: **verified relationships recovered per reviewer-hour, at zero irreversible errors.** Guardrails that hold at every milestone: irreversible-change count = 0; silent-overwrite count = 0; citation coverage = 100% of card fields and claim verdicts; every accepted edge traceable to ≥1 fragment.

| Metric (suite) | M6 | M12 | M18 |
|---|---|---|---|
| Identity B³ F1 (Met-Shred, hard split) | 0.80 | 0.88 | 0.92 |
| Alias match F1 (Accession Gauntlet) | 0.90 | 0.95 | 0.97 |
| Join candidate recall@25 (Joins-Arch) | 0.85 | 0.92 | 0.95 |
| Claim verdict accuracy, adjudicated gold | 0.75 | 0.85 | 0.90 |
| Expected calibration error, per claim family | ≤0.10 | ≤0.08 | ≤0.05 |
| Checklist set F1 (Checklist-Recon) | — | 0.70 | 0.80 |
| Containment path accuracy (CrateNest) | — | 0.85 | 0.93 |
| Discrepancy detection recall @ ≤5% FPR (LoanLegs) | — | 0.90 | 0.95 |
| Tokens per verified edge vs. naive-dump baseline | −40% | −55% | −65% |
| p95 read-tool latency | 500 ms | 400 ms | 400 ms |
| Reviewer acceptance of proposals (health band, not target) | 60–85% | 60–85% | 60–85% |

Acceptance rate is monitored as a band: persistently above it means the agent is sandbagging (proposing only sure things and leaving recall on the table); persistently below it means reviewer time is being wasted. Both are defects.

---

## 12. What not to build

Not a collections management system. Acquisition, accessioning, deaccession, valuation, insurance, rights and reproduction, and the rest of the Spectrum procedure set stay in the institution's CMS of record; this runtime reads exports and writes back reviewed reconstructions, and drawing that line early is what keeps a small nonprofit team alive against vendors with twenty-year head starts.

Not a DAM and not an image server. No derivative pipelines, no color management, no IIIF serving — consume IIIF manifests and existing image URLs; never become the system of record for pixels.

Not a universal ontology project. Fifteen relation types with advisory CIDOC-CRM mappings, revised deliberately. Full-CRM modeling is a research career, not a product milestone, and every hour spent on E-class taxonomy debates is an hour not spent on join recall.

Not an autonomous writer. No change class ever moves to auto-apply until its claim family has cleared calibration targets on adjudicated gold for two consecutive quarters — and merges, joins, and cross-workspace promotions stay human-gated for the full 18 months regardless.

Not an OCR engine, not a custom foundation model, not a chat UI, not a real-time collaborative editor. Use existing OCR and budget for correction loops; use commodity frontier models through the tool contract; let partners bring their own agent front-ends; batch review queues beat live co-editing for registrar workflows. And not an authority-file editor: link to AAT, TGN, ULAN and Nomenclature terms, never manage them. Finally, not an importer for every legacy system: three formats done exceptionally (CSV/spreadsheet, TMS export, EMu export) beat ten done vaguely, because a bad import silently poisons the evidence layer that everything above it trusts.

---

## 13. Top 5 actions

1. **Ship the benchmark harness before any product feature.** Within 30 days: Met-Shred and the Accession Gauntlet running in CI, the naive-dump baseline agent measured, numbers on the wall. Every subsequent design argument gets settled by this harness.
2. **Freeze the two contracts.** Relation ontology v1 (the fifteen edge types) and the evidence-card contract (≤600 tokens, 100% citation, deterministic rendering) as versioned specs, reviewed and signed by a practicing registrar, in month 1.
3. **Build the immutable fragment store and the alias index first, and put read-only tools in one conservator team's hands by month 4.** Retrieval against real degraded documents will reshape the canonicalizer and the card format more than any internal debate.
4. **Implement the two-phase ledger before the first rename ships, and chaos-drill it weekly.** Propose → review → apply → revert with bit-for-bit replay is the safety property the entire pitch rests on; it cannot be retrofitted.
5. **Recruit two to three pilot institutions with genuinely messy backlogs — a traveling-exhibition archive, an excavation study collection with unjoined sherds — and contract quarterly, compensated gold-adjudication sessions with their registrars.** Public open data builds the harness; only pilot data makes condition reports, crate lists, and loan files real. Consider a part-time registrar-in-residence as the standing voice of the user inside the engineering loop.
