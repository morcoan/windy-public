# Windy v0.2 to v0.3 migration

Windy v0.3 is a clean break. There are no v0.2 runtime aliases or full-tool
profile. Advanced operations remain reachable as typed Evidence Query VM
operators returned as bound action tickets.

| v0.2 tool or operation | v0.3 route |
|---|---|
| `server_status` | `windy_status` |
| `target_open`, `target_triage` | `investigation_start` with `locate` or `explain` |
| evidence, name, API, string, motif and relationship search | start an investigation and execute ranked verification actions |
| function evidence, SSA, types, decompile and CFG | execute a bounded function action |
| `data_read`, pointers, structures, arrays and lists | `investigation_start` with `read_data` |
| claims, consistency and provenance | `investigation_start` with `verify` or `trace` |
| edits, signatures, comments and memory writes | `investigation_start` with `edit`, then returned `change_commit` arguments |
| `artifact_read` | `evidence_read` with the returned cursor |
| capability search and execution | `investigation_start` with `capability`, then its action ticket |
| dumps, modules, threads, stacks and regions | `investigation_start` with `dump` |
| workspaces and cross-project queries | `investigation_start` with `compare` or `capability` |
| cache/index inspect, warm, cancel and prune | `investigation_start` with `capability` |
| project or dump close | `target_close` |

Clients no longer assemble specialized arguments. `investigation_step` accepts
only a returned investigation id and action id for common actions. Mutations use
the exact proposal id, expected revision and idempotency key returned by Windy.
