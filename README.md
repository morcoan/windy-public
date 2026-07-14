# Windy

Windy is a portable Windows x64 reverse-engineering workbench and local MCP server for static PE analysis. It gives external agents compact evidence, native checked pseudocode, and durable write-back without a model service, Python, Java, or Ghidra at runtime.

Windy v0.1 is local-only and static-only. It analyzes Windows PE files (`.exe`, `.dll`, and `.sys`); it does not emulate code, attach a debugger, or expose an unauthenticated remote service.

## Five-minute start

1. Extract the release ZIP.
2. Check the executable:

   ```powershell
   .\windy.exe --version
   .\windy.exe doctor
   ```

3. Open the GUI by double-clicking `windy.exe`, dragging a PE onto it, or running:

   ```powershell
   .\windy.exe C:\path\to\program.exe
   ```

4. For an agent session, keep this terminal open:

   ```powershell
   .\windy.exe serve-mcp --open C:\path\to\program.exe
   ```

   The stable endpoint is `http://127.0.0.1:8765/mcp`. The GUI also starts an ephemeral endpoint and provides a copy button, but persistent client configuration should use `serve-mcp`.

5. Follow the [client setup guide](docs/QUICKSTART.md) for Codex, Claude Code, Cursor, or OpenCode.

## What agents should do

Use an evidence-first loop:

1. `list_projects` / `open_project`
2. `list_imports`, `list_exports`, `list_strings`, `list_sections`, `search_summary`
3. `list_functions`
4. `get_function_evidence`
5. `apply_rename_batch`, `apply_type_recovery`, or `set_comment`
6. `verify_claims` / `get_function_consistency`
7. `set_function_memory`
8. Re-read the evidence and confirm that durable annotations survived

`decompile_function` is the canonical native decompiler tool. Its default `product` policy uses V2 output when the structural validator and semantic checker accept it, with an explicit legacy fallback only on rejection. `pure_v2` never falls back; `legacy` is available for comparison.

See [MCP.md](docs/MCP.md) for the protocol and tool contracts.

## Data and privacy

Windy stores IDBs, reversible operation journals, activity and claim journals, function memory, workspaces, and optional signature overlays under one data directory:

1. `--data-dir <DIR>`
2. `WINDY_HOME`
3. `%USERPROFILE%\.windy`

MCP v0.1 refuses non-loopback bind addresses and rejects non-loopback browser origins. Analysis stays on the local machine.

## Build from source

Rust 1.92 or newer and the MSVC Windows toolchain are required.

```powershell
cargo build
cargo clippy -- -D warnings
cargo test
```

## License

Windy is dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
