# Windy five-minute setup

This guide assumes the release ZIP has been extracted and `windy.exe` is available. No external decompiler service is required.

## 1. Verify and start Windy

```powershell
.\windy.exe doctor
.\windy.exe serve-mcp --open C:\samples\target.exe
```

Keep the second terminal open. Windy prints:

```text
Windy MCP listening on http://127.0.0.1:8765/mcp
```

To use a different state directory:

```powershell
.\windy.exe --data-dir D:\windy-state serve-mcp --open C:\samples\target.exe
```

`agent` is a shorter alias for `serve-mcp`. Add `--reopen-last` to restore the
most recent PE. Windy also writes the exact URL to
`<data-dir>\agent-endpoint.txt`.

Check a running endpoint at any time:

```powershell
.\windy.exe doctor --endpoint http://127.0.0.1:8765/mcp
```

## 2. Connect an MCP client

### Codex desktop, CLI, and IDE extension

The ChatGPT desktop app, Codex CLI, and Codex IDE extension share `~/.codex/config.toml` on the same Codex host. Add:

```toml
[mcp_servers.windy]
url = "http://127.0.0.1:8765/mcp"
enabled = true
default_tools_approval_mode = "writes"
startup_timeout_sec = 20
tool_timeout_sec = 120
```

In the desktop app, the equivalent setup is Settings → MCP servers → Add server → Streamable HTTP. Enter `windy` and `http://127.0.0.1:8765/mcp`, save, then restart. Use `/mcp` to confirm the connection.

This follows the official [Codex MCP configuration guidance](https://learn.chatgpt.com/docs/extend/mcp).

### Claude Code

From the project where you want Windy available:

```powershell
claude mcp add --transport http windy http://127.0.0.1:8765/mcp
claude mcp get windy
```

Add `--scope user` before the URL to make it available across projects, or `--scope project` to write a shareable `.mcp.json`. Claude Code documents HTTP as its preferred request/response MCP transport in the [official MCP guide](https://code.claude.com/docs/en/mcp).

### Cursor

Create `.cursor/mcp.json` in a project, or `%USERPROFILE%\.cursor\mcp.json` for global use:

```json
{
  "mcpServers": {
    "windy": {
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

Restart Cursor and verify Windy under Settings → Tools & Integrations → MCP Tools. Cursor supports Streamable HTTP and documents both project and global `mcp.json` locations in its [MCP documentation](https://docs.cursor.com/context/model-context-protocol).

### OpenCode

Add this to the project `opencode.json` or the global OpenCode configuration:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "windy": {
      "type": "remote",
      "url": "http://127.0.0.1:8765/mcp",
      "enabled": true,
      "timeout": 120000,
      "oauth": false
    }
  }
}
```

Run `opencode mcp list` to verify it. See the official [OpenCode MCP server guide](https://opencode.ai/docs/mcp-servers).

## 3. First useful prompt

```text
Use Windy. Check get_server_status, list open projects, triage
imports/exports/strings, use search_bel for a selective query, then inspect the
largest interesting function with get_function_evidence. Do not rename anything
until you can cite evidence. Verify claims, write a concise function memory card,
and re-read the evidence to confirm persistence.
```

If no project was opened on startup, ask the client to call `open_project` with an absolute PE path.

## Troubleshooting

- `connection refused`: keep `serve-mcp` running and check Windows Firewall or another process using port 8765.
- an empty project list: the server is healthy but no PE is open; call `open_project`, pass `--open`, or use `--reopen-last`.
- `doctor` reports the port is busy: either use the existing Windy endpoint or start with `--bind 127.0.0.1:<another-port>` and update the client URL.
- a search reports a lower bound: its deadline or safety cardinality was reached; refine the query, use exact/token mode, or continue with the BEL guidance.
- tools do not appear: restart the client after editing its MCP configuration, then run its MCP list/status command.
- a browser-origin request gets HTTP 403: only absent, `localhost`, or loopback origins are accepted in v0.1.
- state appears in the wrong place: run `windy.exe doctor --data-dir <DIR>` and check the printed resolver result.
