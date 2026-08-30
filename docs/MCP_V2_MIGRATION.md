# MCP v2 migration

Windy 0.2 intentionally replaces the wide v0.1 tool surface. There is no
legacy profile and direct calls to old names return `UNKNOWN_TOOL`.

| v0.1 operation | MCP v2 route |
|---|---|
| `get_server_status`, `list_projects` | `server_status` |
| `open_project`, `open_dump_module` | `target_open`; discover module operations when needed |
| project/dump close | `target_close` |
| `get_triage` | `target_triage` |
| `search_bel`, `search_summary`, name/list searches | `evidence_search` or a discovered capability |
| `get_function_evidence` | `function_inspect` |
| `read_va`, `read_pointers`, `walk_list`, `read_struct_array`, `describe_address` | `data_read` |
| `verify_claims`, consistency checks | `claim_verify` or a discovered capability |
| `apply_rename_batch` and focused writes | `project_edit` |
| decompile, SSA, type, dump, workspace, cross-project, vtable and history tools | `capability_search` then `capability_execute` |

## Lifecycle

`target_open` returns an open-job id immediately. Poll
`server_status({"job_id":"..."})` until it returns `target_id`. Windy never
opens or reopens a target from CLI state.

## Large results

Normal responses are capped at 4 KiB. When `completeness` is `partial` and an
`artifact` is present, request only the required page with `artifact_read`.

## Mutations

`project_edit` requires:

- `expected_revision` from a recent read;
- a caller-generated `idempotency_key` reused for retries;
- the existing batch `renames` representation and supporting evidence.

A stale revision returns `REVISION_CONFLICT`. Repeating a successful key
returns the original result without applying the operation again.
