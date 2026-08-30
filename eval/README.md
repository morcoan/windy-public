# Evaluation

Evaluation clients live here so the released `windy` executable remains a pure
MCP substrate.

| Path | Purpose |
|---|---|
| `microbench/` | Compact deterministic SQLite tool-use benchmark |
| `agent-bench/` | External HTTP MCP agent-loop harness |
| `fixtures/pe/` | Small authored PE/source/Ghidra fixtures |
| `gold/` | Source-gold scoring contracts for the small PE fixtures |
| `grand/` | Larger exact-address decompiler corpus and rebuild tooling |

Common checks:

```powershell
python -m unittest discover eval/microbench
cargo test -p agent-bench
cargo test eval_metrics
cargo test decomp_scorecard
```

Private benchmark instances, answers, trajectories, local models, and curator
corpora are ignored. Do not commit model transcripts or sealed holdout gold.
See [the benchmark policy](../docs/BENCHMARKS.md) and each subdirectory README
for suite-specific instructions.
