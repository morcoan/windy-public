# Windy

Windy is a lightweight, agent-first MCP server for static Windows binary and
user-mode minidump analysis. It gives external agents bounded, verifiable
evidence without shipping a GUI, embedded planner, model service, debugger, or
emulation runtime.

The v0.3 Evidence Query VM reduces the public surface to six tools. It compiles
an investigation into server-bound continuation tickets, retains state and
deduplicated evidence server-side, and materializes expensive analysis only
when a question requires it.

## Start

```powershell
windy
# equivalent explicit form
windy serve-mcp
```

The server binds `http://127.0.0.1:8765/mcp`. The terminal is a read-only
status display; it cannot open targets or perform RE. Use Ctrl+C to stop it.

Point an MCP client at the endpoint, then use this loop:

1. `investigation_start` with a target path, intent, question, and budget.
2. Execute only returned opaque actions with `investigation_step`.
3. Page deliberately requested evidence with `evidence_read`.
4. Commit only server-issued proposals with `change_commit`.
5. Inspect runtime state with `windy_status`.
6. Flush and release the target with `target_close`.

Only six tools are advertised. Evidence deltas default to 2 KiB with an 8 KiB
hard inline limit.

| Public tool | Purpose |
|---|---|
| `windy_status` | Inspect runtime, target, job, cache, and investigation state |
| `investigation_start` | Compile a bounded question into evidence and actions |
| `investigation_step` | Execute an opaque server-issued action ticket |
| `evidence_read` | Page an immutable evidence artifact |
| `change_commit` | Commit a verified edit with revision and idempotency checks |
| `target_close` | Flush annotations and release a target |

See the [MCP v3 contract](docs/MCP.md), [quickstart](docs/QUICKSTART.md),
[v0.2 to v0.3 migration guide](docs/MCP_V3_MIGRATION.md), and
[Evidence Card v2](docs/contracts/evidence_card_v2.md).

## Runtime behavior

- Targets are never opened or reopened from CLI history.
- Analysis advances through mapped, catalog, sketch, function, global, and
  deep stages only when an investigation requires them.
- Structural partitions are SHA-addressed, checksummed, ABI-versioned, and
  bounded by a 5 GiB LRU.
- Huge PE images use a bounded resident sketch shortlist plus a streamed,
  disk-backed whole-executable instruction index; they never promote to the
  legacy whole-image decoded graph.
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

The external agent benchmark remains the `eval/agent-bench` workspace crate;
models and agent loops are deliberately not linked into the server. See
[Benchmarks](docs/BENCHMARKS.md) for the active evaluation paths and
[the v0.3 release report](docs/benchmarks/v0.3.0-local-review.md) for measured
results and limitations.

## Repository map

| Path | Contents |
|---|---|
| `src/` | MCP host, Evidence Query VM, analysis, project, and decompiler code |
| `docs/` | Protocol contracts, architecture notes, report, and paper |
| `eval/microbench/` | Compact deterministic agent evaluation harness |
| `eval/agent-bench/` | External MCP agent-loop client |
| `eval/fixtures/pe/` | Small authored PE and source-gold fixtures |
| `eval/grand/` | Larger checked-in decompiler evaluation corpus |
| `scripts/` | Release, smoke, benchmark, and documentation tooling |

The accompanying paper is available as
[Evidence-Carrying Continuations for Small-Model Binary Analysis](docs/paper/Windy_Evidence_Carrying_Continuations.pdf).

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for development expectations and
[SECURITY.md](SECURITY.md) for private vulnerability reporting.

## License

Windy is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
