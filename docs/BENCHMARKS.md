# Benchmarks and release acceptance

Windy's north-star metric is `verified_facts_per_1k_tokens`: facts statically supported by the binary per thousand agent-context tokens.

## Reproducibility commands

```powershell
windy.exe bench agent-loop --pe gclsd\bench\sample.exe --limit 16
windy.exe bench scorecard
windy.exe bench scorecard --gold eval\gold\complex_source_gold.json
windy.exe bench grand --suite v2-strict --output artifacts\strict-v2.json
```

The hidden v0.1 aliases `eval-agent-loop`, `decomp-scorecard`, and `grand-bench` remain available for older scripts.

## Strict V2 lane

The release lane uses exact-VA, pure-V2 output. It does not permit legacy fallback or a dual-engine picker. Every report must archive:

- the exact JSON report;
- SHA-256 of `eval/grand/manifest.json`;
- source commit or dirty-tree identifier;
- benchmark suite and compiler profiles;
- Ghidra export provenance available with the authored fixtures.

Release acceptance requires:

- `pure_v2_share == 1.0` and `pure_fallback_count == 0`;
- overall score at least `0.6976985453832655` and catastrophic rate at most `0.35157894736842105`;
- no increase in omitted-function count;
- no empty present functions;
- a targeted per-exit semantic-return regression that fails on the old global substitution and passes on the candidate.

The v0.1.0 candidate's exact-address run and machine-readable status are in
`docs/benchmarks/v0.1.0-rc/provenance.json`. Its locked forward guard is
`docs/benchmarks/v0.1.0-baseline.json`; workflow acceptance uses the exact
floating-point bounds and pinned manifest/report hashes in that file. The
supplied approximate pre-change summary remains archived for audit and is
explicitly non-comparable. Its old approximately `0.902` score is never an
acceptance threshold.

The checked-in Grand corpus is rebuilt and compared with fully analyzed Ghidra
exports using the procedure in `eval/grand/README.md`. Exact source identities
come from MSVC linker MAPs embedded in the manifest; no decompiler output or
gold-aware ranking is used to select a function VA. The committed Ghidra JSON
contains only allowlisted authored target functions, not statically linked CRT
pseudocode.

Committed release reports belong under `docs/benchmarks/`. A report without its manifest hash and source identity is diagnostic only, not a publishable comparison.

## Interpretation

Source-gold scoring measures structural and semantic recovery on authored fixtures. Ghidra output is a comparison lane, not ground truth. Scores should be reported with omitted functions, catastrophic errors, fallbacks, and provenance rather than as a single headline number.
