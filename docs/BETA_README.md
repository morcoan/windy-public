# Windy private beta

The beta channel uses the same agent-first MCP v2 contract as the public
binary. It may enable experimental native-analysis optimizations, but it must
not add a GUI, embedded planner, automatic target reopen, or a second tool
surface.

```powershell
.\windy-beta.exe
```

Connect to `http://127.0.0.1:8765/mcp`, open targets through `target_open`, and
follow `docs/MCP.md`. Beta changes must pass the same build, clippy, test,
schema-budget, payload-budget, and packaged MCP smoke gates before packaging.
