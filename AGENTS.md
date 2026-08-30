# Agent Surface Guide

This file is written for LLM agents and developers using `windy` as a
**pure MCP reverse-engineering substrate**. Windy does not plan or chat —
external agents (OpenCode, Claude, Cursor, Grok, …) own planning. Windy
answers tight questions and commits durable state.

Legacy model experiments are not part of the public tree. Prefer native
decompile and evidence tools. Do not add a first-party model client.

## Verification Gate

Before any change is declared complete:

```bash
cargo build
cargo clippy -- -D warnings
cargo test
python -m unittest discover eval/microbench
```

All four must pass. No exceptions, no skipped smoke tests.

## Terminal MCP host

```bash
# Both commands bind 127.0.0.1:8765 by default.
windy
windy serve-mcp
windy serve-mcp --bind 127.0.0.1:8765
```

The terminal is a read-only statistics display. It never opens or reopens a
target; the MCP agent owns all target lifecycle. Deep BEL indexing is also
demand-driven rather than an automatic open stage.

MCP endpoint: `http://127.0.0.1:8765/mcp` (streamable HTTP).

### Connect your agent

Point your MCP client at the streamable HTTP URL above. Recommended tool ladder:

1. `investigation_start` with a path or target id, intent, question and budget.
2. Execute only returned tickets through `investigation_step`.
3. Use `evidence_read` only for a returned immutable cursor.
4. Commit a returned proposal through `change_commit` with its exact revision
   and idempotency arguments.
5. Use `windy_status` for jobs, targets, investigations, cache and metrics.
6. `target_close` flushes annotations and releases the target.

The public surface is intentionally six tools. Specialized dump, workspace,
decompiler, SSA, type, xref, provenance, vtable, memory, history and deep-index
operations are internal Evidence Query VM operators reached through action
tickets, not separately advertised schemas.

Prefer evidence tools over freeform C. Never dump whole image bytes unless the
user asked for hex (`read_va` / `get_fragment` capped at 512 bytes).

### Contracts

- Evidence Card v2: `docs/contracts/evidence_card_v2.md`
- Evidence Card v1: `docs/contracts/evidence_card_v1.md`
- Claim & edge registry v1: `docs/contracts/claim_edge_registry_v1.md`

### North-star metric

Agent-loop task success plus honest abstention, measured with bounded calls and
visible context. The compact v0.3 harness is under `eval/microbench`; the larger
`eval/agent-bench` client remains external to the Windy binary.

```bash
python -m unittest discover eval/microbench
cargo test -p agent-bench
cargo test eval_metrics
cargo test decomp_scorecard
```

## Module Responsibilities

| Module | What it owns | Agent relevance |
|---|---|---|
| `project/` | Loaded PE, symbols, comments, types, PDB info, frames | read-only source of truth |
| `analysis/` | Functions, CFG, code index, xrefs, signatures, indirect edges | structural answers |
| `ir/` | Export formats (`to_llm_text`, `to_agent_text`), operand annotation | token-efficient function text |
| `llm/query.rs` | Tool-like context queries | used by agents to avoid whole-image dumps |
| `project/op.rs` | undoable mutation ops | all durable agent edits |
| `mcp.rs` | MCP tool surface | primary external agent API |

## Export Formats

- **LLM4Decompile** — `Project::function_llm_text(va)` returns the exact
  `<name>:\nmnemonic operands\n...` format. Do not change this format.
- **Agent compact** — `Project::function_agent_text(va)` and
  `Project::function_context_text(va)`. Human-readable signature header,
  `block_0x...` labels, type-annotated operands, and context summaries.

## Entity IDs (write-back)

Call `get_function_entities` before renaming. Stable targets for
`apply_rename_batch`:

| target | fields | effect |
|---|---|---|
| `function` | `new_name` | rename function symbol |
| `arg` | `index`, `new_name`, optional `data_type` | rename/retype signature param |
| `local` | `stack_offset` (e.g. `-0x10`), `new_name`, optional `data_type` | rename/retype stack slot |
| `address` | `va`, `new_name`, optional `data_type` | rename/retype global |
| `address_comment` | optional `va`, `new_name` as text | address comment |
| `function_comment` | `new_name` as text | function comment |

Stack offsets are signed frame-pointer displacements (negative = locals).
Edits are journaled `Op`s and reversible via `undo_last` / `redo_last`.

## Context Queries (token-bounded)

Library helpers live in `llm/query.rs` (list caps ≤ 32). MCP tools wrap these
and add pagination / broader triage:

**Per-function**

- `get_function_evidence` — **preferred** one-shot evidence pack (+ `memory` if set)
- `get_triage` — first-minute ranked functions (deterministic fixed-point scores)
- `get_function_summary` — compact structural stats (not agent purpose)
- `get_function_memory` / `set_function_memory` / `list_function_memory` — durable cards
- `get_function_entities` — args + stack locals with stable IDs
- `verify_claims` — static support/contradict/unknown (logs to `.claims.jsonl`)
- `get_function_consistency` — auto pass/warn checks (frame, SigDB, SSA, callers, memory)
- `get_alias_history` — rename lineage (old→new)
- `get_fragment` — bounded VA excerpt with cite (same caps as `read_va`)
- `read_pointers` / `walk_list` / `read_struct_array` / `describe_address` — resolved bulk reads
- `trace_value` — interprocedural provenance (`died`: depth_cap|inlined|indirect|…)
- `get_function_agent_text` / `get_function_json` / `get_function_context`
- `function_callers` / `function_callees` / `callers_with_args`
- `strings_in_function` / `apis_called` / `xrefs_to`
- `get_function_ssa_optimized` / `get_function_ssa_suggestions`
- `get_function_types` / `apply_type_recovery`
- `get_function_dataflow` / `get_call_sites` / `get_function_points_to`
- `get_function_decompilation_structured` / `decompile_function_native`
- `get_vtable_calls`

### `verify_claims` kinds (v1)

| kind | required fields | check |
|---|---|---|
| `calls_api` | `api` | callees / import APIs |
| `has_string` | `string` | strings referenced by function |
| `local_name` | `stack_offset`, `name` | frame local name |
| `local_type` | `stack_offset` + `data_type` or `type_str` | frame local type |
| `param_count` | `count` | signature arity exact match |
| `signature_arity` | optional `count` | recovered arity vs callers |

**Project triage**

- `list_functions` — `pattern`, `offset`, `limit` (max 128)
- `search_bel` — exact/prefix/substring/numeric/regex/token/relationship/motif/ontology/multi-evidence; provenance + stable cursors; hit rows (VA, kind, display) are embedded in the response text
- `decompile_function` — `max_instructions` (default 1000, raise to force large functions; above the cap returns structured `too_complex` guidance) and `deadline_ms` (default 30000; overruns finish in the background and are cached — retry returns instantly)
- `list_imports` / `list_exports` / `list_strings` / `list_sections`
- `search_summary` / `functions_named`
- `list_api_signatures` / `list_vtable_signatures`
- `read_va` — hex dump, max 512 bytes

**Mutations**

- `rename_symbol`, `set_comment`, `retype_global`, `set_function_signature`
- `apply_rename_batch`, `apply_ssa_suggestions`, `apply_type_recovery`
- `set_focus`, `undo_last`, `redo_last`

**Workspaces / cross-binary**

- `create_workspace`, `add_files_to_workspace`, `open_workspace`, …
- `get_cross_project_calls`, `get_cross_project_exports`, `get_cross_project_dataflow`
- `get_cross_project_similar` — fingerprint similarity beyond name matching

## Type Annotations

The agent text uses inline type annotations where available:

- PDB-typed globals: `[rip+g_count:uint32]`
- Import slots: `[__imp_CreateFileW:HANDLE(*)(...)]`
- Recovered stack locals: `[rbp-0x10:buffer:uint8[64]]`

When type information is missing the operand falls back to plain disassembly.
After `apply_rename_batch` on locals/args, re-read agent text to see updates.

## Updating State

Agents must not mutate `Project` fields directly. Route edits through
`project_edit`; discover uncommon mutation/history operations only when needed.

- `apply_rename_batch` — preferred batch path for names + types
- `rename_symbol` / `set_comment` / `retype_global` / `set_function_signature`
- `apply_type_recovery` / `apply_ssa_suggestions`
- `undo_last` / `redo_last` — per-client stacks (`client_id` defaults to `"mcp"`)

## Architecture Rules

1. Do not leak whole image bytes or raw PE structures unless the user explicitly
   asked for hex (`read_va` is the controlled path).
2. Prefer summary / evidence queries; only request full function text after a
   summary indicates the target is relevant.
3. Treat recovered types and signatures as best-effort; operators can override.
4. Keep `to_llm_text` frozen; extend agent-oriented formatting through
   `to_agent_text` and new query/MCP tools.
5. **Pure MCP** — no first-party planner loop inside windy.
6. **Static analysis only** for now — no emulation / debugger bridge.
7. Token budgets and pagination are features, not limitations.

Model/training experiments are evaluation-only and must connect over MCP.
Never add a first-party planner or model client back to the Windy product.
