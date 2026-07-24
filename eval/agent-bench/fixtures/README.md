# agent-bench fixtures

## `wiring-check-report.*`

Offline harness output (`--live` omitted). **Synthetic by construction:**

- Arm A returns gold answers (scorer wiring check).
- Arms B/C return wrong fixed answers.

These are **not** product measurements. Do not copy them into
`docs/benchmarks/` or cite them as A-vs-B evidence.

Regenerate:

```bash
cargo run -p agent-bench -- --root . --limit 8 \
  --output eval/agent-bench/fixtures/wiring-check-report.json \
  --markdown eval/agent-bench/fixtures/wiring-check-report.md
```
