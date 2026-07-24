# Agent loop v1

- harness: `agent-bench-v1`
- live: false
- commit: 996961a855e48b30f9aaaa3179fcbd8b13b7d7fe

| arm | tasks | success | abstain (correct) | tool_calls | prompt_tokens (all fields) | wall_ms |
|---|---:|---:|---:|---:|---:|---:|
| A | 8 | 8 | 8 (8) | 24 | 20000 | 0 |
| B | 8 | 0 | 0 (0) | 40 | 23200 | 0 |

Prompt tokens = input_tokens + cache_creation_input_tokens + cache_read_input_tokens.
