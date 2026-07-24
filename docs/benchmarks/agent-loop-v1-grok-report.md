# Agent loop v1 (Grok session subagents — free, no Anthropic)

> Arm A: Windy/Grok. Arm B: pefile/Grok. Mode `grok_workflow`. No Anthropic. Grok session subagents used (workflow agent-bench-grok-ab, 26 agents).

- harness: `agent-bench-v1-grok-subagents`
- synthetic: false
- live: false
- model: grok (session subagents)
- mode: grok_workflow
- agents: 26
- commit: 3ee4ad8d8ffc579012e47fa3a95f2b1585ddbe00

| arm | tasks | success | abstain (correct) | tool_calls | wall note |
|---|---:|---:|---:|---:|---|
| A | 12 | 1 | 1 (0) | 12 | not measured (payload) |
| B | 12 | 6 | 12 (6) | 37 | not measured (payload) |

Prompt tokens = input_tokens + cache_creation_input_tokens + cache_read_input_tokens not billed to Anthropic; Grok session tokens used for subagents.

## Family split

| family | A success | B success | n |
|---|---:|---:|---:|
| locate | 1/6 | 0/6 | 6 |
| abstain | 0/6 | 6/6 | 6 |
