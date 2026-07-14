# Absorption of agent_native_reconstruction_roadmap.md

Source: `agent_native_reconstruction_roadmap.md` (museum framing).  
This file is the **complete transfer ledger**: every major section is mapped to
an implementation or a named deferral with a kill/trigger condition.

## §1 Design thesis

| Thesis | Status | Where |
|---|---|---|
| Evidence over dumps | **Done** | `get_function_evidence`, Evidence Card v1 |
| Claims, not vibes (supported/contradicted/insufficient) | **Done** | `verify_claims` (`unknown` = insufficient) |
| Writes reversible with inverse | **Done** | `Op` + undo/redo |
| Two-phase propose → review → apply | **Deferred** | Soft: `apply_rename_batch.evidence[]`. **Trigger:** hard-gate when claim ECE ≤ 0.08 on eval gold for 2 quarters of agent runs. **Kill:** if agent friction rises without quality gain. |
| Human review queue | **Deferred** | No registrar role. **Trigger:** multi-operator shared projects need conflict UI. |
| Recovered graph as primary product | **Partial** | Call/xref/import edges exist; typed edge *status* not first-class. **Trigger:** multi-module false links dominate harness failures. |

Operating loop (ingest → observe → claim → commit → memory): covered by open PE → evidence → verify → apply → `set_function_memory`.

## §2 Data model layers

| Layer | Status | Windy mapping / deferral |
|---|---|---|
| Source (immutable fragments) | **Done** | PE bytes + VA locators; `cite` + `get_fragment` |
| Observation (versioned extractors) | **Partial** | Live extractors only. **Trigger:** need A/B of string/type passes → add `extractor@version` side table. |
| Identity / aliases / lineage | **Done** | symbols + `alias_history` |
| Assertion (edges + claims + evaluations) | **Partial** | claims + `.claims.jsonl`; edge objects with `proposed\|accepted` deferred until false cross-module links hurt eval |
| Containment / packages / legs | **Partial** | workspaces + members. Nested firmware-like maps deferred until PE bench plateaus (**trigger:** eval suite needs ELF/flash fixtures) |
| Memory / change ledger | **Done** | `function_memory` + op journal + claim journal |

Postgres/S3 warehouse: **Kill** as product path; single-process IDB is intentional.

## §3 Indexes

| Idea | Status | Trigger to build |
|---|---|---|
| Alias exact + fuzzy | Partial (exact symbols) | Fuzzy demangle/typo match only if rename miss rate high in agent logs |
| Lexical + vector search | Partial (`search_summary`) | Vector search only if dump baseline still wins on large bins after card density work |
| Measurement ranges | N/A museum-specific | — |
| Graph adjacency indexes | Partial (xref/call indexes) | Promote when edge-status model lands |
| Append-only ledger BRIN | Done enough (op_log + claim jsonl) | — |

## §4 Agent tool surface (≤12 discipline)

Contract frozen: evidence card + claim registry. Tool sprawl is an anti-goal in `AGENTS.md`.  
New tools require contract bump or absorption entry.

## §5 Claim checks against measured evidence

| Claim family | Status |
|---|---|
| Identity / API / string / local / arity | **Done** (registry v1) |
| Join / part-whole (museum) | **N/A** → PE analogue is stack aggregate / struct; **trigger:** structured-decompile score card fails locals |
| Containment / movement | **N/A** until multi-image flash maps |
| Checklist membership | **N/A** |
| Calibration ECE program | **Partial** (log exists). **Trigger:** ≥200 logged claims then plot ECE |

## §6–7 Metrics & degrade-and-recover benchmarks

| Item | Status |
|---|---|
| Verified facts / 1k tokens | **Done** (`eval_metrics`, `eval-agent-loop`) |
| Degrade-and-recover strip suite | **Partial** (sample.exe + scorecard). **Trigger:** expand gold set when improving decomp |
| Decompile scorecard vs classical engine | **Done** (`decomp_scorecard`, `decomp-scorecard` CLI) |
| Naive dump baseline | **Done** |

## §8 Multi-package / scoped assertions

Workspaces + cross-project name/fingerprint match: **Done**.  
Identity-global / assertion-scoped conflicts: **Deferred** until two projects assert incompatible export links in real agent runs.

## §9 Nested archival packages

Firmware-like nested layouts: **Deferred**. **Trigger:** PE scorecard mean ≥ Ghidra on gold *and* agent tasks need non-PE images.

## §10 Phased roadmap (museum months) → windy

Phases 0–2 of the museum doc map to shipped W0–C work.  
Phases 3–5 (joins at scale, loans, calibration public release): only the PE analogues (scorecard, claim log, multi-DLL similar) are in scope; the rest is **Kill** for this product.

## §11 Scoreboard targets

Use PE scorecard + agent_loop numbers as the living scoreboard (not museum B³ F1).  
Irreversible overwrite count stays 0 via op journal.

## §12 What not to build (adopted)

Not a full IDA/Ghidra CMS of record; not 100 MCP tools; not custom foundation model first; not universal ontology project; not autonomous high-risk merge without gates; not every loader format on day one.

## §13 Top 5 (museum) → windy status

1. Benchmark harness first → **Done** (eval_metrics + decomp_scorecard)  
2. Freeze contracts → **Done**  
3. Fragment store + read tools → **Done** (cites + get_fragment)  
4. Two-phase ledger chaos drills → **Partial** (op undo tests; no weekly chaos) **Trigger:** multi-client corruption  
5. Pilot institutions → **N/A** (agent PE users); replaced by gold PE fixtures  

## Exhaustion

Museum-specific: CIDOC-CRM, AAT/TGN, condition OCR, crate GiST constraints, registrar adjudication, IIIF/DAM, TMS/EMu importers — **Kill** for windy. No further extraction without a new product mandate.

## Decompile quality loop (this goal)

- Smoke gold: `eval/gold/sample_source_gold.json` from `gclsd/bench/sample.c`
- Quality gold: `eval/gold/complex_source_gold.json` from `gclsd/bench/complex.c`
  (nested control, switch-like dispatch, loops, struct-ish args; quality gates
  `no_rsp` / `no_stack_home` / `max_assign` / `null_term` / `char_cast`)
- Engines: Windy `function_decompile_native` vs checked-in Ghidra JSON
  (`gclsd/bench/ghidra_output.json`, `gclsd/bench/complex_ghidra_output.json`)
- Commands: `windy bench scorecard` and
  `windy bench scorecard --gold eval/gold/complex_source_gold.json`
- Tests: `scorecard_on_sample_exe_is_deterministic`,
  `complex_scorecard_shows_ghidra_ahead_when_fixture_present`,
  `quality_gates_prefer_ghidra_clean_over_ssa_stack_homes`
