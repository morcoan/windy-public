# Windy v0.2 for Windows x64

Windy is a portable, terminal-hosted MCP server for agent-driven static PE and
user-mode minidump analysis. This release removes the GUI and embedded model
runner, advertises twelve budgeted MCP tools, and makes deep indexing
demand-driven.

```powershell
.\windy.exe doctor
.\windy.exe
# or: .\windy.exe serve-mcp
```

Configure the MCP client for `http://127.0.0.1:8765/mcp`. The terminal only
shows server statistics; the agent opens targets with `target_open` and closes
them with `target_close`. The server is intentionally loopback-only.

See `SETUP.md`, `docs/MCP.md`, and `docs/MCP_V2_MIGRATION.md`. Dependency and
license metadata is in `windy.cdx.json` and `THIRD_PARTY_NOTICES.md`.
