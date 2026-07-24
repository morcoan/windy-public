# Agent loop wiring check (SYNTHETIC - not a benchmark)

> Offline mode returns gold for arm A and wrong answers for B/C by construction.
> Do not cite these numbers as product evidence. Run `--live` for real A-vs-B.

- harness: `agent-bench-v1-wiring-check`
- synthetic: true
- live: false
- commit: 321371c1a2eb62186e1c7bf3838e2e51543a2274

| arm | tasks | success | abstain (correct) | tool_calls | prompt_tokens (all fields) | wall_ms |
|---|---:|---:|---:|---:|---:|---:|
| A | 8 | 8 | 8 (8) | 24 | 20000 | 0 |
| B | 8 | 0 | 0 (0) | 40 | 23200 | 0 |

Prompt tokens = input_tokens + cache_creation_input_tokens + cache_read_input_tokens.
