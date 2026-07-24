# Agent loop v1 (local tools — free, no Anthropic)

> Arm A: `windy agent-query`. Arm B: python + pefile. Zero model tokens.

- harness: `agent-bench-v1-local-tools`
- synthetic: false
- live: false
- commit: 01c8a7818600792a173f20e2646f18ed84dda47c

| arm | tasks | success | abstain (correct) | tool_calls | prompt_tokens (all fields) | wall_ms |
|---|---:|---:|---:|---:|---:|---:|
| A | 12 | 1 | 1 (0) | 12 | 0 | 1889 |
| B | 12 | 6 | 8 (6) | 24 | 0 | 1996 |

Prompt tokens = input_tokens + cache_creation_input_tokens + cache_read_input_tokens.
