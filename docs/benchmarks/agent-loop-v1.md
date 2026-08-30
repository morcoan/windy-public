# Agent loop v1 (historical v0.2 methodology)

This document describes the frozen v0.2 comparison harness and its former MCP
surface. It is retained for interpreting baseline results, not as v0.3 usage
documentation. Use `eval/microbench/` and `docs/MCP.md` for current runs.

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
# Offline scoring wiring only (synthetic answers - NOT a product measurement)
cargo run -p agent-bench -- --root . --limit 12 --profile P0 --profile P1 \
  --output eval/agent-bench/fixtures/wiring-check-report.json \
  --markdown eval/agent-bench/fixtures/wiring-check-report.md

# FREE local tool agents (no Anthropic tokens):
# Arm A = deterministic Windy MCP evidence ladder (not a single agent-query)
# Arm B = python + pefile
cargo build -p windy -p agent-bench
cargo run -p agent-bench -- --root . --local --balanced --limit 12 \
  --arm a --arm b --profile P0 --profile P1 \
  --output docs/benchmarks/agent-loop-v1-local-report.json \
  --markdown docs/benchmarks/agent-loop-v1-local-report.md

# Optional: free multi-agent orchestration (Grok workflows / subagents, still no Anthropic)
# /workflow agent-bench-grok-ab  — Arm A prompt requires AGENTS.md MCP ladder
# (get_triage / search_bel / functions_named / get_function_evidence), not agent-query only

# Live model loop (requires ANTHROPIC_API_KEY and a built windy binary) - PAID
cargo build --release
cargo run -p agent-bench -- --root . --live --limit 12 \
  --output docs/benchmarks/agent-loop-v1-report.json \
  --markdown docs/benchmarks/agent-loop-v1-report.md
```

**Report namespaces**

| Path | What |
|------|------|
| `eval/agent-bench/fixtures/wiring-check-*` | Synthetic offline scorer wiring only |
| `docs/benchmarks/agent-loop-v1-local-report.*` | Free local tools A-vs-B (no model tokens) |
| `docs/benchmarks/agent-loop-v1-report.*` | Paid Anthropic live loop only |

Do not treat wiring-check A=perfect / B=zero tables as product evidence.

## Arms

| Arm | Tools | Intent |
|-----|--------|--------|
| **A** windy-evidence | `get_triage`, `search_bel`, `get_function_evidence`, `read_pointers`, `walk_list`, `describe_address`, `trace_value`, … | Product surface |
| **B** python-tools | `bash` + `write_file` + `read_file` in scratch; harness provisions venv with `pefile`/`capstone` | Baseline without Windy |
| **C** windy-dump | `get_function_agent_text`, `read_va` only | Dump-style Windy (ablation) |

## Task families (gold from `eval/grand`)

| Family | Question | Gold |
|--------|----------|------|
| **Locate** | VA for source name? | Tracked manifest `function_map` entry with `status=present` |
| **Abstain** | Same for optimized-away or foreign names | **refuse** for `folded`/`inlined_only`/`missing`, plus names absent from the target program |
| Enumerate / triage / provenance | Structured list / ranking / value origin | C source + tracked manifest (live only) |

`eval/grand/manifest.json` is the clean-checkout ground truth. Its
`function_map` is frozen from MSVC linker MAP callable symbols, but the ignored
adjacent `.map` files are neither required nor opened by the harness.
`eval/grand/identity_maps` is **not** ground truth (known wrong). Because true
P0/P1 inlining is rare, the abstain family deterministically adds real function
names borrowed from other programs and proven absent from the target program.
The committed `p0p1_tasks_12.json` fixture is checked against this loader.

## Token accounting

Anthropic `usage.input_tokens` is the **uncached remainder only**. Report:

```text
prompt_tokens = input_tokens
              + cache_creation_input_tokens
              + cache_read_input_tokens
```

Each arm has a different tool set (cache prefix). Comparing `input_tokens`
alone manufactures cost differences that are pure caching artifacts.

## Local Arm A policy (Phase 1)

`--local` Arm A spawns `windy serve-mcp`, then runs a deterministic MCP v2
ladder over HTTP:

1. `target_open`, then poll `server_status`
2. `target_triage`
3. `evidence_search` (substring)
4. `capability_search` only when a specialized name query is required
5. `function_inspect` on the best evidence-ranked candidate (if any)

PEs are staged **without** adjacent `.map`, `.pdb`, `.obj`, or JSON files so name
recovery is not reading the answer key. On this corpus that means Arm A
typically **refuses** locate when no recovered symbol matches — honest
measurement, not a harness bug. Product
Name-substring ranking was **not** confirmed as causing wrong VAs under this
ladder (empty name lists when the map is stripped).

## Expected headline

- **P0 (staged, no map)**: locate is hard for both arms without symbols; Arm A should
  multi-tool and refuse rather than invent VAs; Arm B may confabulate entry for `main`.
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
