# Changelog

## 0.3.0 — Evidence Query VM

- Replaced the v0.2 surface with six agent-only MCP tools and opaque,
  action-id-only continuations.
- Added demand-driven catalog, sketch, function, global, and explicit deep
  stages with checksummed structural cache partitions and bounded artifacts.
- Added streaming function sketches, constraint-intersection retrieval, and
  graph-backed verification without retaining decoded instructions globally.
- Added an eight-byte partitioned deep instruction index and stopped automatic
  whole-image BEL construction.
- Added the deterministic SQLite microbenchmark and failure-driven Luna
  evaluation loop; models and training remain external to Windy.
- Added durable rename/comment proposals with revision, idempotency, close,
  reopen, and persistence verification continuations.

## 0.2.0 — agent-first MCP architecture

- Removed the GUI, window/GPU dependency graph, startup target arguments, and
  automatic recent-project reopen.
- Running `windy` now starts the loopback MCP host with a read-only terminal
  statistics display.
- Replaced the wide advertised API with twelve MCP v2 tools plus deterministic
  on-demand capability discovery/execution.
- Added asynchronous target-open jobs, target close, response envelopes,
  4 KiB default budgets, artifact paging, revision checks, and idempotent edits.
- Stopped automatic whole-image BEL construction and compacted exact
  instruction lookup keys from 64-bit host pairs to 32-bit PE RVA/index pairs.
- Removed the product-facing `windy-agent`; model experiments remain external
  evaluation clients.
- Added Evidence Card v2 and the breaking API migration guide while leaving
  the frozen v1 contract unchanged.

All notable changes will be documented here.

## 0.1.2 — agent substrate + BEL + Windows dumps

**Version of this public-main drop: `0.1.2`.** Not a 0.1.1 patch and not a
“0.1.1-beta” label — this is the next release after 0.1.1’s decompiler-quality
work.

Public `main` tip after this stack is not “just minidumps.” Relative to
`996961a` (pre-substrate) it is **~15.6k lines / 52 files** across the
substrate + dump commits: a pure-MCP reverse-engineering substrate for
external agents, then multi‑GB user-mode dump analysis on the **same**
headless server.

| field | public build | `--features beta` edge build |
|---|---|---|
| product / MCP name | `windy` | `windy-beta` |
| channel | `public` | `private-beta` |
| version string | **`0.1.2`** | `0.1.2-beta.local` |
| endpoint | `http://127.0.0.1:8765/mcp` (`serve-mcp` / `agent`) | same |

### From “PE workbench” → “agent substrate”

Before this drop, Windy was already a PE reverse-engineering workbench with
MCP and native decompile. This beta makes external agents (Cursor, Claude,
Grok, OpenCode, …) first-class operators:

- **Binary Evidence Lattice (BEL)** — first-class searchable evidence index
  (`search_bel`): exact / prefix / substring / numeric / regex / token /
  relationship / motif / ontology / multi-evidence, with provenance and stable
  cursors. Eager build on beta open; deadline-bound lazy on public builds.
  Docs: `docs/BEL.md`.
- **Evidence-first tool ladder** — `get_triage` (deterministic fixed-point
  ranking), `get_function_evidence` one-shot packs, claims / consistency /
  function memory cards, reversible `Op` journals.
- **Structured memory reads** — `read_pointers`, `walk_list`,
  `read_struct_array`, `describe_address` (resolved, not raw hex walls).
- **Provenance** — interprocedural `trace_value` with honest `died` reasons
  (depth cap, indirect, …).
- **Beta packaging** — `scripts/package-beta.ps1`, `docs/BETA_README.md`,
  product split via `build_info` (`windy` vs `windy-beta`).
- **Agent-loop harness** — workspace crate `eval/agent-bench` (raw Anthropic
  HTTP; not inside the windy binary), free `--local` P0/P1 A-vs-B vs
  pefile/capstone, manifest-derived clean-checkout task gold, balanced honest
  abstentions, Grok multi-agent workflows, and reports under
  `docs/benchmarks/agent-loop-v1*`.

Commits in this stack: `321371c` (substrate/BEL/beta), `01c8a78` /
`3ee4ad8` / `9f250bc` (agent-bench realism + free local + Grok A/B).

### Windows user-mode `.dmp` on the same MCP

Then dumps land as first-class citizens **without a second server**:

- **MDMP only** (user minidumps / full-memory user dumps). Kernel dumps hard-reject.
- **Dump sessions** — open `.dmp` via `open_project` → `kind=dump_session`
  (modules, threads, exception if any, sparse Memory64 map, GB-scale mmap).
- **Crash / hang triage** — `get_dump_triage`, `list_dump_modules`,
  `list_dump_threads`, `list_memory_regions`, `describe_dump`,
  `get_thread_stack` (FP chain + RSP scan; works without Exception stream).
- **Hybrid RE** — `open_dump_module` extracts a runtime-base PE image, runs the
  full PE analysis pipeline (functions, evidence, decompile, BEL on the
  **module only** — never process-wide BEL on a 10 GiB dump).
- **Cross-module IAT** — resolved absolute IAT slots → `module!export` via dump
  memory + auto-workspace / cross-project index.
- **CLI** — `windy dump-info path.dmp`; local `*.dmp` fixtures gitignored.

Commit: `16adf42` (builds on the substrate above).

### Agent ladder (one port)

```text
serve-mcp / agent          →  http://127.0.0.1:8765/mcp
open_project  (.exe|.dll|.dmp)
  PE / dump_module:  get_triage → get_function_evidence → …
  dump_session:      get_dump_triage → open_dump_module → (same PE tools)
search_bel                 →  prefer over naive string greps on large images
```

### What this is not

- Not a change to the frozen LLM4Decompile export format. The emitter split and
  Win64 call-argument recovery are internal decompiler improvements.
- Not kernel dump / WinDbg parity.
- Not an installer or public auto-update feed — private beta packaging stays
  local ZIP + loopback MCP.

### Start

```powershell
cargo run --features beta -- serve-mcp
# agents open PE or .dmp themselves via open_project
```

## 0.1.1 - decompiler quality update

Post-0.1.0 native decompiler ratchet. Product path is still **checked V2 with
legacy fallback**; pure-V2 remains the strict measurement lane.

### What's new

- **Expression recovery** for common MSVC lowerings: shifts as multiplies,
  IDIV/IREM returns, self-xor/sub folds, signed `-1` from all-ones, relational
  `BoolNot`, soft `>` / `!=` freeload rewrites, byte zero-tests.
- **Tail / call recovery**: foreign imm `jmp` as return-call, mid/`leaf`
  naming, apply/`f` icall and `jmp reg` apply, multi-block tails, adjacent
  MSVC `.map` names on callees.
- **Structure presentation**: eq-if ladders folded to `switch`, multi-const
  phi selects, multi-if keep (no leaf freeload collapse), while `je`-exit
  invert for soft `!=`.
- **Stores / memory**: loop GPR accumulators emitted as `*reg` assigns;
  RawRam out-param stores kept when value trees mention `rsp` (param homes).
- **SEH / COM**: ACCESS_VIOLATION filter constants; field null-guards for soft
  `>`.
- **Product policy**: fewer needless legacy fallbacks on recovered tails and
  Select cond placeholders (still rejects goto/`cond_N` soup).
- Regression tests for each accepted ratchet step.

### Decompiler quality (Grand v2-strict, 475 functions / 64 programs)

| lane | v0.1.0 pure floor | **0.1.1** | Δ |
|---|---:|---:|---:|
| pure_v2 overall | 0.698 | **0.938** | **+0.24** |
| product overall | ~0.70 | **0.884** | **+0.18** |
| pure catastrophic rate | 0.352 | **0.025** | −0.33 |
| pure SemanticReturnWrong | 206 | **18** | −188 |
| pure CallTargetWrong | 28 | **5** | −23 |
| pure SwitchCaseMissing | 20 | **5** | −15 |
| pure MissingStore | 10 | **1** | −9 |
| pure_v2 share / fallbacks | 1.0 / 0 | **1.0 / 0** | same |
| pure omitted | 5 | **5** | same (inlined/folded) |

Same suite, comparison engines at 0.1.1 tip: **pure V2 0.938**, Ghidra **0.879**,
product **0.884**, legacy **0.649**. Pure V2 is ahead of Ghidra on this corpus;
product is roughly Ghidra-level with residual CTW/LRW still higher.

### Why scores moved

Not a faster binary — **more correct, more source-like pseudocode**:

1. Returns and conditions match soft gold instead of flag soup.
2. Callees get real names / recoverable tails instead of empty returns.
3. Switches and multi-if/loop regions survive freeload collapse.
4. Memory effects (loop accumulators, out-params) show up as stores.

Archived four-lane report: `docs/benchmarks/v0.1.1-grand-v2-four-lanes.json`  
Compact summary: `docs/benchmarks/v0.1.1-summary.json`

### Still open

- Product residual CTW/LRW/SRW still above pure on full corpus (re-archive
  `v2-strict` for official post-Phase-3 histograms when convenient).
- Remaining product fallbacks on freeload name `a` (e.g. boss COM) — extract fix,
  not blanket checker allow.
- Pure SRW freeload leftovers; StructureAlignLow ~28.
- P3 still weaker than P0–P2 overall (open-ended LTCG diversity).
- Five pure omitted targets **reconfirmed by design** (not Windy false omits):
  - `a01_signed_rel/P3/unsigned_lt` — ICF-folded into `signed_lt` (shared map VA)
  - `c03_dispatch/P3/classify` — body absent under LTCG (unreachable from `main`)
  - `boss_com_variant_router/{P1,P2,P3}/Release` — COM method inlined (no own-object `Release`)
- (Phase 4 landed) optional further emit helper dedupe — out of scope for the
  mechanical split.

### Phase 2 note (pure_v2 call-arg fidelity)

- Direct Call AST emission now recovers Win64 integer args in lockstep with HIR
  (`region_ast`), closing the dogfood `Source2Main` class of
  `dropped_call_arguments` rejects. Regression:
  `direct_call_emits_win64_args_matching_abi_uses`.

### Phase 4 note (code health only — no quality claim)

`structure/emit.rs` mechanical split into sibling modules (verbatim moves):

- `emit_fold.rs` — CfgOnly text passes (ladder/goto/`minimize_gotos`)
- `emit_polish.rs` — LegacySemantic `polish_*`
- `emit_region.rs` — `structure_emit_core` + region/expression emission
- `emit.rs` — public façade (`NameCtx`, `decompile*`) + re-exports + tests

No intentional behavior change; presentation pipeline order unchanged.

### Phase 3 note (product vs pure / fewer legacy fallbacks)

Product path falls back to legacy when the typed-AST checker rejects. Two reject
classes were over-firing relative to pure V2 quality:

1. **`invented_call_arguments`** — AST may recover more call args than the
   lightweight HIR Win64 lift. Extra args are now allowed (same spirit as extra
   recovered call sites); **dropped** args still reject.
2. **`unresolved_ast_placeholders` on `v` / `store_val`** — thin store RHS when
   uses are missing. No longer treated as synthetic rejects; freeload `a`/`b`/`ret`
   and `cond_N` still reject.

Sample P3 packs A/D/G (53 present functions): product fallbacks **27 → 5**,
pack-A `main` no longer legacy-falls back. Regressions:
`checker_allows_extra_ast_call_arguments_beyond_hir`,
`checker_allows_thin_store_value_placeholder`,
`p3_a02_main_product_no_legacy_fallback`.

## 0.1.0

Initial public release: portable Windows x64 GUI, headless Streamable HTTP MCP,
checked native V2 decompilation with legacy fallback, evidence tools, IDBs and
journals, `doctor` / packaging / SBOM.
