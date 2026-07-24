# Agent loop v1

North-star measurement for **Windy as an RE substrate for agents**, compared
against what an agent does without it (`pip install pefile capstone` + a REPL).

The old in-process `run_agent_loop_eval` path compared evidence cards to a
hardcoded dump rate of `0.0`. That metric could not fail and has been removed.
Use this harness instead.

## Harness

```text
eval/agent-bench   # workspace crate (reqwest lives here, not in windy)
```

```bash
# Offline scoring wiring only (synthetic answers — NOT a product measurement)
cargo run -p agent-bench -- --root . --limit 12 --profile P0 --profile P1 \
  --output eval/agent-bench/fixtures/wiring-check-report.json \
  --markdown eval/agent-bench/fixtures/wiring-check-report.md

# Live model loop (requires ANTHROPIC_API_KEY and a built windy binary)
# Arm B gets bash + write_file + read_file in a scratch dir with a pefile/capstone venv.
cargo build --release
cargo run -p agent-bench -- --root . --live --limit 12 \
  --output docs/benchmarks/agent-loop-v1-report.json \
  --markdown docs/benchmarks/agent-loop-v1-report.md
```

**`docs/benchmarks/` holds live reports only.** Offline wiring fixtures live under
`eval/agent-bench/fixtures/wiring-check-*` and are labeled `synthetic: true`.
Do not treat A=perfect / B=zero offline tables as evidence.

## Arms

| Arm | Tools | Intent |
|-----|--------|--------|
| **A** windy-evidence | `get_triage`, `search_bel`, `get_function_evidence`, `read_pointers`, `walk_list`, `describe_address`, `trace_value`, … | Product surface |
| **B** python-tools | `bash` + `write_file` + `read_file` in scratch; harness provisions venv with `pefile`/`capstone` | Baseline without Windy |
| **C** windy-dump | `get_function_agent_text`, `read_va` only | Dump-style Windy (ablation) |

## Task families (gold from `eval/grand`)

| Family | Question | Gold |
|--------|----------|------|
| **Locate** | VA for source name? | `identity_maps[*].entry_va` when `status=present` |
| **Abstain** | Same for inlined/missing | Correct answer is **refusal** |
| Enumerate / triage / provenance | Structured list / ranking / value origin | C source + identity maps (live only) |

Identity `status` labels (`present` / `folded` / `inlined-only` / `missing`) make
honest abstention scoreable — especially at P3 `/O2 /GL /LTCG`.

## Token accounting

Anthropic `usage.input_tokens` is the **uncached remainder only**. Report:

```text
prompt_tokens = input_tokens
              + cache_creation_input_tokens
              + cache_read_input_tokens
```

Each arm has a different tool set (cache prefix). Comparing `input_tokens`
alone manufactures cost differences that are pure caching artifacts.

## Expected headline

- **P0**: both arms often look fine on locate.
- **P3**: python-fed agents confabulate VAs for functions LTCG deleted; evidence-fed
  agents abstain when identity says `inlined-only` / `missing`.

## New MCP tools exercised by arm A

| Tool | Role |
|------|------|
| `read_pointers` | N resolved pointers |
| `walk_list` | Linked list walk + field decode |
| `read_struct_array` | Struct array with layout |
| `describe_address` | Section/symbol/function/string |
| `get_triage` | First-minute ranked functions |
| `trace_value` | Interprocedural provenance with `died` reason |

## Provenance fields in reports

Machine-readable reports record model id, harness commit, task-set SHA-256, and
per-arm totals (success, abstention precision/recall, all three usage fields,
tool calls, wall time).
