# Quickstart

Start Windy without a target:

```powershell
.\windy.exe
# custom state directory
.\windy.exe --data-dir D:\windy-state serve-mcp
```

Configure the MCP client with `http://127.0.0.1:8765/mcp`. The terminal is a
read-only status surface and must remain open.

Ask the agent to:

```text
Open C:\samples\target.exe with target_open. Poll server_status until the
target is ready. Run target_triage, inspect the highest-ranked function, and
verify every claim before applying any project_edit. Close the target when
finished.
```

For a minidump, open the `.dmp` the same way, then use
`capability_search("dump modules threads stack")` to retrieve only the needed
dump operations. Open an individual module before function analysis; never
build a BEL over the whole process.

If a result contains an artifact handle, use `artifact_read` with a small
page. Do not request the entire artifact unless the task truly needs it.

Troubleshooting:

- `/healthz` confirms the host without creating an MCP session.
- `server_status` reports open jobs, active targets, BEL readiness, memory and
  request statistics.
- Windy refuses non-loopback bind addresses and non-loopback browser origins.
- A target is never reopened automatically; the agent must call
  `target_open` after every fresh host start.
