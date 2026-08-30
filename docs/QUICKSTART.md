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
Start a tiny locate investigation for C:\samples\target.exe and describe the
behavior I ask about. Execute only the returned action tickets, cite Windy's
evidence IDs, verify uncertain claims, and close the target when finished.
```

The agent should call `investigation_start` with `path`, `intent`, `question`,
and `budget`, then pass returned `action_id` values to `investigation_step`.
`evidence_read` accepts only immutable cursors returned by Windy. Edits use the
exact proposal, revision, and idempotency arguments returned by the server.

For a minidump, use the `dump` intent. Windy can inspect user-mode dump metadata
and modules but never launches, attaches to, or terminates a process.

Troubleshooting:

- `/healthz` confirms the host without creating an MCP session.
- `windy_status` reports targets, investigations, jobs, cache, and metrics.
- Windy refuses non-loopback bind addresses and non-loopback browser origins.
- Targets are never reopened automatically after a fresh host start.
