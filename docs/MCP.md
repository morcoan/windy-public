# Windy MCP contract

Windy v0.1 serves MCP Streamable HTTP at `http://127.0.0.1:8765/mcp` by default and advertises protocol `2025-11-25`. `GET /healthz` returns the server name, Cargo version, status, and supported protocol.

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
2. Triage: `list_imports`, `list_exports`, `list_strings`, `list_sections`, `search_summary`
3. `list_functions` with `offset` and `limit`
4. `get_function_evidence` as the default one-shot pack
5. `apply_rename_batch`, `apply_type_recovery`, or `set_comment`
6. `verify_claims` and/or `get_function_consistency`
7. `set_function_memory`
8. Re-read evidence and confirm annotations and memory
9. `get_cross_project_similar` for multi-binary workspaces
10. Full agent text or pseudocode only when the bounded evidence pack is insufficient

Read-only tool annotations are set only on genuine queries. Opening projects, annotations, memory, focus, undo/redo, claim verification, and workspace additions are stateful but non-destructive. Only actual workspace removal is marked destructive. `verify_claims` is stateful because it appends to the claim journal.

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
