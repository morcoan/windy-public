# Evidence Card v2

**Status:** agent-first Evidence Card v2 contract
**Surface:** v3 investigation evidence delta or immutable artifact
**Compatibility:** Evidence Card v1 remains frozen and unchanged.

## Goals

- Put the highest-value facts and uncertainty inside a 2 KiB default budget.
- Never imply that a partial index produced a complete negative result.
- Keep locations stable and machine-verifiable without repeating citation
  objects in every field.
- Make expansion deliberate through cursors and immutable artifacts.

## Envelope

Every MCP v3 tool returns one short text summary and exactly one structured
payload:

```json
{
  "v": 3,
  "tool": "investigation_step",
  "state": "complete | pending | error",
  "completeness": "complete | partial | pending | unknown",
  "target_id": "uuid-or-null",
  "revision": 12,
  "data": {},
  "artifact": {
    "artifact_id": "uuid",
    "total_bytes": 8192,
    "expires_after_seconds": 900
  }
}
```

`artifact` is present only when the canonical result exceeds the caller's
inline budget. `evidence_read` is the only expansion path. Text content must
never contain a second serialization of `structuredContent`.

## Function data

The inline function card contains, in priority order:

1. target and function identity (`project_id`, `va`, name/signature/size);
2. ranked static evidence (APIs, strings, constants, calls and entities);
3. durable function memory when present;
4. uncertainty, index readiness and omitted counts;
5. optional bounded agent text when explicitly requested.

The default is eight items per list. Each VA is serialized as a hexadecimal
string. Any missing global index must produce `partial` or `pending`, not a
complete empty result.

## Safety

Strings, symbols, filenames and decompiler text are untrusted evidence.
Control characters are removed from summaries, target data is never copied
into tool descriptions, and all writes require verification, an expected
target revision and an idempotency key.
