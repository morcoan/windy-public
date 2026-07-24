# Windy MCP contract

Windy v0.1 serves MCP Streamable HTTP at `http://127.0.0.1:8765/mcp` by default and advertises protocol `2025-11-25`. `GET /healthz` returns identity/channel, protocol, idle/busy state, active operation, elapsed time, open-project count, and a human message. `get_server_status` additionally reports recent-project reopen hints and per-project BEL readiness/stats.

## Security boundary

- Bind addresses must be loopback (`127.0.0.0/8` or `::1`). Windy rejects `0.0.0.0`, LAN, and public addresses before listening.
- Requests without `Origin` are accepted. `localhost` and literal loopback origins are accepted. Other origins receive HTTP 403.
- Unsupported `GET /mcp` streams and `DELETE /mcp` session deletion return HTTP 405.
- Windy v0.1 has no remote authentication layer. Do not proxy it onto a network.

This implements the DNS-rebinding protections required by the [MCP Streamable HTTP transport specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

## Result shape

Successful JSON tool output is returned twice for compatibility:

- `content[0].text`: compact JSON text
- `structuredContent`: the identical JSON value

Tool/runtime failures use a normal MCP tool result with `isError: true`:

```json
{
  "error": {
    "code": "PROJECT_NOT_FOUND",
    "message": "project not found",
    "details": {},
    "retryable": false
  }
}
```

JSON-RPC errors are reserved for malformed protocol requests and unknown methods.

## Recommended tool ladder

1. `list_projects` / `open_project`
2. `get_triage` for first-minute ranked focus
3. Triage: `list_imports`, `list_exports`, `list_strings`, `list_sections`, `search_bel`
4. `list_functions` with `offset` and `limit`
5. `get_function_evidence` as the default one-shot pack
6. Structured reads: `read_pointers`, `walk_list`, `read_struct_array`, `describe_address` (prefer over hex dumps)
7. `trace_value` for interprocedural provenance (reports where the chain died)
8. `apply_rename_batch`, `apply_type_recovery`, or `set_comment`
9. `verify_claims` and/or `get_function_consistency`
10. `set_function_memory`
11. Re-read evidence and confirm annotations and memory
12. `get_cross_project_similar` for multi-binary workspaces
13. Full agent text or pseudocode only when the bounded evidence pack is insufficient

Read-only tool annotations are set only on genuine queries. Opening projects, annotations, memory, focus, undo/redo, claim verification, and workspace additions are stateful but non-destructive. Only actual workspace removal is marked destructive. `verify_claims` is stateful because it appends to the claim journal.

## Binary Evidence Lattice search

`search_bel` is the authoritative whole-project search API. It accepts `query`,
`mode`, optional `evidence`/`quorum`, `relationship_depth`, entity `kinds`,
`limit`, opaque `cursor`, and `deadline_ms`. It returns scored hits with exact
provenance, `total_kind` (`exact` or `lower_bound`), a stable next cursor,
truncation/deadline state, candidate estimate, strategy, and refinement advice.

`search_summary` remains a compatibility view over BEL. It keeps shallow offset
pagination and human messages but omits full provenance. Deep pagination uses
`search_bel` cursors. Full architecture and correctness rules are in
[BEL.md](BEL.md).

## Structured memory reads

Prefer these over `read_va` when enumerating tables or lists:

| Tool | Purpose |
|------|---------|
| `read_pointers` | N machine pointers at a VA, each **resolved** (function/import/string) |
| `walk_list` | Follow `next` at `next_offset`; cycle-safe; optional field layout |
| `read_struct_array` | Decode an array given stride + field layout |
| `describe_address` | Section, symbol, function, string, or pointer target |

Bounds are element/node counts (not a 512-byte hex dump). List walks report
`died`: `null` | `cycle` | `node_cap` | `unmapped`.

## First-minute triage and provenance

- `get_triage(project_id, limit)` — deterministic fixed-point ranking (export,
  entry, call degree, imports, strings, size, BEL ontology/motifs when ready).
- `trace_value(project_id, va, site, direction, depth)` — interprocedural
  walk; always returns a `died` reason (`depth_cap`, `inlined`, `indirect`,
  `origin`, …) and `exact` vs `may` confidence.

## Native decompilation

`decompile_function` is canonical. `decompile_function_native` is a deprecated v0.1 alias with the same schema.

Inputs:

- `project_id`: UUID returned by `open_project`
- `va`: hexadecimal or decimal function entry address
- `policy`: `product` (default), `pure_v2`, or `legacy`
- `max_tokens`: optional output bound

Outputs include `project_id`, `va`, `status`, `pseudocode`, `engine`, `policy`, `truncated`, `check_report`, optional `fallback_reason`, and `contract_fingerprint`.

- `product`: V2 is authoritative; checker/validator rejection may explicitly fall back to legacy.
- `pure_v2`: never falls back. Rejection returns `status: "omitted"` and diagnostics.
- `legacy`: frozen comparison path.

The aggregate serialized return contract remains compatible. The checker additionally tracks block-specific return value classes so one exit cannot borrow a richer expression from another.

## Durable state

All mutable state is rooted at the resolved Windy home:

1. CLI `--data-dir`
2. `WINDY_HOME`
3. `%USERPROFILE%\.windy`

Project IDBs and journals are keyed by image SHA-256. Operations are serialized, journaled, reversible per client, and replayed on reopen. Use an isolated `--data-dir` for tests and automation.

## Bounded output

Lists are paginated and capped. `read_va` and `get_fragment` are capped at 512 bytes. Prefer evidence and summaries over whole-image bytes or free-form pseudocode.
