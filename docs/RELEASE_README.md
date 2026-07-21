# Windy v0.1.1 for Windows x64

Windy is a portable static PE reverse-engineering GUI and local MCP server. No installer or external decompiler service is required.

```powershell
.\windy.exe doctor
.\windy.exe C:\path\to\target.exe
.\windy.exe serve-mcp --open C:\path\to\target.exe
```

Configure your MCP client for `http://127.0.0.1:8765/mcp`. The server is intentionally loopback-only. Full setup and usage documentation is available in the project README at https://github.com/morcoan/windy.

See `SETUP.md` in this archive for verified Codex, Claude Code, Cursor, and OpenCode configuration examples.

The archive checksum is published beside the ZIP. Dependency and license metadata is in `windy.cdx.json` and `THIRD_PARTY_NOTICES.md`.
