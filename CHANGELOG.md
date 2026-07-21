# Changelog

All notable changes will be documented here.

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
