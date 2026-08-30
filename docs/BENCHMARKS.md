# Benchmarks

Windy's north-star metric is verified binary facts per thousand visible agent
tokens, with no silently supported false claims. Evaluation code remains outside
the shipped MCP server.

## Active suites

- `eval/microbench/`: Python-standard-library SQLite runner for compact,
  deterministic tool-use cases. Private instances, gold, and trajectories are
  ignored by Git.
- `eval/agent-bench/`: external agent-loop client that exercises Windy only
  through streamable HTTP MCP.
- `cargo test eval_metrics`: bounded evidence-card versus text-dump wiring
  checks.
- `cargo test decomp_scorecard`: native decompiler comparison against authored
  source gold and checked-in Ghidra exports.
- `eval/grand/`: larger exact-address decompiler corpus and provenance.

```powershell
python -m unittest discover eval/microbench
cargo test -p agent-bench
cargo test eval_metrics
cargo test decomp_scorecard
```

To issue a blinded microbench task while a local host is running:

```powershell
python -m eval.microbench.microbench --root . issue --split canary `
  --endpoint http://127.0.0.1:8765/mcp
```

## Reporting policy

Every committed performance report must identify the source commit, target
hashes, suite and compiler profiles, cold/warm state, repetitions, and relevant
hardware. Source-gold comparisons must include omitted functions, catastrophic
errors, fallbacks, and provenance; Ghidra output is a comparison lane, not
ground truth.

The [v0.3.0 release report](benchmarks/v0.3.0-local-review.md) records the
current architecture, Luna development-set evaluation, context measurements,
runtime measurements, and limitations. Historical v0.1 snapshots are available
from Git history rather than carried on the current branch.
