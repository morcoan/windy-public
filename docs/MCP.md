# Windy Evidence Query VM v3

Windy exposes streamable HTTP MCP at `http://127.0.0.1:8765/mcp` and health
status at `/healthz`. Loopback binding and browser-origin checks are enforced.

## Agent loop

1. Call `investigation_start` with `path` or `target_id`, one supported intent,
   a question, and `tiny`, `normal`, or `deep` budget.
2. Read the evidence delta and execute only returned `action_id` values through
   `investigation_step`. Tickets bind target, arguments, readiness and expiry.
3. Use `evidence_read` only for a returned immutable artifact cursor.
4. For writes, execute the returned `change_commit` arguments unchanged, then
   follow the ordered close/reopen verification continuations.
5. Call `target_close` when the investigation is finished.

Supported intents are `locate`, `explain`, `trace`, `verify`, `read_data`,
`compare`, `edit`, `capability`, and `dump`.

## Public tools

| Tool | Responsibility |
|---|---|
| `windy_status` | Runtime, target, job, investigation, action, cache and metrics state |
| `investigation_start` | Compile a bounded question into evidence and continuations |
| `investigation_step` | Execute one server-bound action ticket |
| `evidence_read` | Page immutable evidence artifacts |
| `change_commit` | Apply a verified proposal with revision and idempotency checks |
| `target_close` | Flush annotations and release a target |

## Result contract

Every response has a one-line text summary and one canonical structured v3
envelope. Target JSON is never duplicated into text.

```json
{
  "v": 3,
  "tool": "investigation_step",
  "state": "complete | partial | pending | error",
  "completeness": "complete | partial | pending | unknown",
  "target_id": "uuid-or-handle",
  "revision": 7,
  "data": {
    "evidence_delta": [],
    "next_actions": [],
    "uncertainty": "none"
  }
}
```

The default inline budget is 2 KiB and the hard ceiling is 8 KiB. Oversized
results receive a stable artifact cursor. Empty evidence is globally
authoritative only when completeness is `complete`; omissions and pending work
are explicit.

## Demand-driven stages

- `mapped`: validate the image and return a session handle.
- `catalog`: headers, sections, imports, exports, unwind seeds and target facts.
- `sketch`: stream instructions once and retain compact per-function behavior.
- `function`: materialize instructions, CFG, SSA, types or decompilation only
  for an active function window.
- `global`: build cross-function relationships on explicit demand.
- `deep`: build the partitioned eight-byte instruction metadata index only
  through a discovered deep-index action.

Catalog, sketch and deep partitions are keyed by image SHA-256, architecture,
analyzer ABI and options version. Entries are checksummed, safely replaced
after corruption, and access-evicted at 5 GiB. Annotation journals are separate
and survive structural-cache eviction.

## Safety

Binary strings, symbols, paths and decompiler output are untrusted evidence.
They are sanitized, carry provenance, and never become tool descriptions or
instructions. Windy is static-only and never launches, attaches to, or
terminates operating-system processes.
