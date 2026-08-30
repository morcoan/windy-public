# Windy

Windy is a lightweight, agent-first MCP server for static Windows binary and
user-mode minidump analysis. It has no GUI, embedded planner, model service,
debugger, or emulation runtime. External agents own planning and target
lifecycle; Windy returns bounded evidence and durable, reversible write-back.

## Start

```powershell
windy
# equivalent explicit form
windy serve-mcp
```

The server binds `http://127.0.0.1:8765/mcp`. The terminal is a read-only
status display; it cannot open targets or perform RE. Use Ctrl+C to stop it.

Point an MCP client at the endpoint, then use:

1. `investigation_start` with a target path, intent, question, and budget.
2. Execute only returned opaque actions with `investigation_step`.
3. Page deliberately requested evidence with `evidence_read`.
4. Commit only server-issued proposals with `change_commit`.
5. Inspect runtime state with `windy_status`.
6. Flush and release the target with `target_close`.

Only six tools are advertised. Evidence deltas default to 2 KiB with an 8 KiB
hard inline limit. See [MCP v3](docs/MCP.md), the
[v0.2 to v0.3 migration guide](docs/MCP_V3_MIGRATION.md), and
[Evidence Card v2](docs/contracts/evidence_card_v2.md).

## Runtime behavior

- Targets are never opened or reopened from CLI history.
- Analysis advances through mapped, catalog, sketch, function, global, and
  deep stages only when an investigation requires them.
- Structural partitions are SHA-addressed, checksummed, ABI-versioned, and
  bounded by a 5 GiB LRU.
- PE, DLL, SYS, user-mode MDMP, dump-module, and multi-binary workspace
  analysis remain supported.
- Addresses are returned as hexadecimal strings and incomplete indexes are
  reported as partial or pending rather than complete negatives.
- Target-derived strings and decompiler output are treated as untrusted data.
- MCP binds to loopback and rejects non-loopback browser origins.

Windy stores analysis caches, IDBs, reversible operation journals, claims,
function memory, and workspaces under:

1. `--data-dir <DIR>`
2. `WINDY_HOME`
3. `%USERPROFILE%\.windy`

## Build

Rust 1.85 or newer and the MSVC Windows toolchain are required.

```powershell
cargo build
cargo clippy -- -D warnings
cargo test
python -m unittest discover eval/microbench
```

The external agent benchmark remains the `eval/agent-bench` workspace crate.
Archived GCLSD authoring is available only with `--features gclsd-archive`.

## License

Windy is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
