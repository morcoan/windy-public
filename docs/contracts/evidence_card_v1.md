# Evidence Card Contract v1

**Status:** frozen
**Version:** 1
**Surface:** MCP `get_function_evidence` / `llm::query::function_evidence`

## North star

Agents receive **compact, citable facts**, not table dumps.
Every list field carries a `cite` locator so claims can be re-checked.

## Required sections

| Key | Required | Notes |
|---|---|---|
| `summary` | yes | Structural card (name, va, size, blocks, â€¦) |
| `apis` | yes | Array of `{ name, cite }` |
| `strings` | yes | Array of `{ va, value, encoding, cite }` |
| `call_sites` | yes | Truncated; prefer sites that already carry `call_va` |
| `points_to` | yes | `{ entries, count, truncated? }` with per-entry instruction cite |
| `constants` | yes | SSA constants with defining `va` cite |
| `entities` | yes | Rename/retype targets |
| `callers` / `callees` | yes | `{ va, name, cite }` |
| `memory` | yes | Durable agent card or `null` |
| `open_questions` | yes | Short strings the agent should resolve next |
| `resolve_hint` | yes | Suggested next tool(s) |
| `contract` | yes | `{ "name": "evidence_card", "version": 1 }` |
| `agent_text` | no | Only if `include_agent_text` |

## Citation shape

```json
{ "kind": "call|data|insn|symbol|stack|summary", "va": "0xâ€¦", "note": "optional" }
```

- `kind=call` â€” call-site or callee edge
- `kind=data` â€” string / global data VA
- `kind=insn` â€” instruction defining a constant or points-to
- `kind=symbol` â€” symbol table entry
- `kind=stack` â€” stack offset (use `note` for offset)
- `kind=summary` â€” derived aggregate with no single VA

## Caps

- Default `max_items` = 32, hard max 64 per list section
- Optional agent_text: default max 64 instructions
- Implementers should keep typical cards well under ~2â€“4k tokens

## Open questions

Populate when:

- locals exist with `Unknown` types
- callees include unresolved / `unknown` targets
- memory card missing but function has â‰¥1 import API
- points-to has only `HeapUnknown`

`resolve_hint` names the preferred tool ladder step (e.g. `get_function_dataflow`, `apply_type_recovery`, `set_function_memory`).

## Compatibility

Additive fields are allowed. Removing/renaming required keys is a **v2** bump.
