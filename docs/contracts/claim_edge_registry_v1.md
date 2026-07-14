# Claim & Edge Registry v1

**Status:** frozen
**Version:** 1
**Surface:** MCP `verify_claims` / `llm::verify`

## Design

- Unit of agent hypothesis = **claim**
- Verdicts: `supported` | `contradicted` | `unknown` (unknown/insufficient is first-class)
- Gatherers are deterministic; LLMs must not invent verdicts
- Every evaluation should be loggable for calibration

## Claim kinds (closed set)

| kind | Required fields | Meaning |
|---|---|---|
| `calls_api` | `api` | Function calls named import/API |
| `has_string` | `string` | Function references substring (ascii/utf16) |
| `local_name` | `stack_offset`, `name` | Stack slot has this name |
| `local_type` | `stack_offset` + `data_type` or `type_str` | Stack slot type |
| `param_count` | `count` | Signature arity exact |
| `signature_arity` | optional `count` | Recovered arity vs callers |
| `calls_edge` | `target_va` | Direct call edge to VA |
| `imports_dll` | `dll` | Calls an API from this DLL basename (best-effort via name) |
| `xref_count_min` | `count` | At least N xrefs *to* function entry |
| `memory_purpose_set` | â€” | Function memory card has non-empty purpose |
| `callee_arity` | `count`, optional `api` | A callee (or named API) has this many params in SigDB/signature |

Anything outside this table is **not** a claim kind: put it in `set_function_memory` notes/tags until the registry is deliberately revised (governance, not drive-by PR).

## Edge kinds (program graph, conceptual)

Closed vocabulary for future graph objects / evidence cites:

| edge | Meaning |
|---|---|
| `calls` | code â†’ code/import |
| `xref` | general cross-reference |
| `imports` | module â†’ external API |
| `exports` | module â†’ export |
| `data_ref` | code â†’ data/string |
| `part_of` | local/param â†’ function |
| `same_as` | cross-module identity (workspace) |
| `documented_in` | entity â†’ comment/memory |

## Write path policy (v1 soft)

1. Prefer `verify_claims` before durable renames when uncertain
2. `apply_rename_batch` may carry optional `evidence` strings (activity log)
3. Hard claim-gating (reject unsupported applies) is **v2**

## Evaluation log

Each `verify_claims` batch may append JSONL records under the projectâ€™s claim journal for offline calibration (verdict, kind, checker version).
