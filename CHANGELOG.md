# Changelog

All notable changes will be documented here.

## 0.1.1-beta — agent substrate + BEL + Windows dumps (public main)

**This is the big jump past 0.1.1-as-decompiler-only.** Public `main` tip
`16adf42` is not “just minidumps.” Relative to `996961a` (pre-beta) it is
**~15.6k lines / 52 files** across five commits: a pure-MCP reverse-engineering
substrate for external agents, then multi‑GB user-mode dump analysis on the
**same** headless server.

Identity when built with `--features beta`:

| field | value |
|---|---|
| MCP / product name | `windy-beta` |
| channel | `private-beta` |
| version string | `0.1.1-beta.local` |
| endpoint | `http://127.0.0.1:8765/mcp` (`serve-mcp` / `agent`) |

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
  pefile/capstone, Grok multi-agent workflows, reports under
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

- Not a rewrite of the decompiler emit pipeline (local emit_fold splits remain
  unpublished WIP).
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

- Product CTW (~32) / LRW (~17) lag pure.
- Pure SRW freeload leftovers; StructureAlignLow ~28.
- P3 weaker than P0–P2 (especially product P3).
- Five omitted pure targets (inlined/folded identities).

## 0.1.0

Initial public release: portable Windows x64 GUI, headless Streamable HTTP MCP,
checked native V2 decompilation with legacy fallback, evidence tools, IDBs and
journals, `doctor` / packaging / SBOM.
