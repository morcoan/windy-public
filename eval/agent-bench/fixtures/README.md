# agent-bench fixtures

## Generated wiring reports

Offline harness output (`--live` omitted). **Synthetic by construction:**

- Arm A returns gold answers (scorer wiring check).
- Arms B/C return wrong fixed answers.

These are **not** product measurements. Do not copy them into
`docs/benchmarks/` or cite them as A-vs-B evidence.

Generate into a local scratch directory (reports are not tracked):

```bash
cargo run -p agent-bench -- --root . --limit 8 \
  --output .artifacts/agent-bench/wiring-check-report.json \
  --markdown .artifacts/agent-bench/wiring-check-report.md
```
