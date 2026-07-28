# windy-beta (edge build of **0.1.2**)

This archive is the private, local-only Windy edge channel for trusted
development teams. It is not a GitHub release and is not connected to a tag,
push, pull request, Actions check, or public update feed.

The executable is `windy-beta.exe`. Feature set matches public **v0.1.2**
(agent substrate, BEL, dumps). Edge packaging only changes product identity:
MCP name `windy-beta`, channel `private-beta`, version string
`0.1.2-beta.local`.

## What’s in 0.1.2 (this drop)

Not a small dump patch. Relative to pre-0.1.2 public main this is a **full
agent substrate**:

| Layer | What agents get |
|---|---|
| **Version** | **`0.1.2`** (edge: `0.1.2-beta.local`) |
| **MCP** | Single loopback server (`serve-mcp` / `agent` → `:8765/mcp`) |
| **BEL** | Evidence lattice search (`search_bel`) with provenance |
| **PE RE** | Triage, evidence packs, structured reads, `trace_value`, memory cards |
| **Dumps** | User-mode MDMP sessions + `open_dump_module` PE pipeline on the **same** server |
| **Harness** | `eval/agent-bench` + free local / Grok A-vs-B reports |

See `CHANGELOG.md` section **0.1.2** for the full notes.

## Start for agents

```powershell
.\windy-beta.exe doctor
.\windy-beta.exe agent --open C:\path\target.exe
# User-mode crash dumps (MDMP), including multi-GB full-memory dumps:
.\windy-beta.exe agent --open C:\path\process_2026-07-26_22-08-20.dmp
.\windy-beta.exe dump-info C:\path\process.dmp
```

`agent` is an alias for `serve-mcp`. The stable endpoint is:

```text
http://127.0.0.1:8765/mcp
```

The exact endpoint is printed and written to
`<Windy data directory>\agent-endpoint.txt`. Use `--reopen-last` to restore the
most recent PE. `get_server_status` and `/healthz` report idle/busy state,
current work, open projects, recent projects, and BEL readiness.

If port 8765 is already owned, windy-beta reports the PID in plain language.
Attach to that Windy or stop it; do not run competing servers on the same port.

## Search

This beta includes the Binary Evidence Lattice. Prefer `search_bel` for exact,
prefix, substring, numeric, regex, token, relationship, motif, ontology, and
multi-evidence search with provenance and stable cursors. See `BEL.md`.

Large PEs build BEL eagerly once after open. Status and progress remain visible;
an arriving search shares the same single-flight build. Broad work has a hard
cooperative deadline, and a partial result is labeled as a lower bound. No
query work survives a deadline return.

Recommended first minute (PE):

1. `get_server_status`
2. `list_projects` or `open_project`
3. `list_imports`, `list_exports`, and `list_strings`
4. `search_bel` with an exact/token/selective substring query
5. `list_functions`, then `get_function_evidence`

Recommended first minute (**user-mode `.dmp`** — same MCP port `8765`):

1. `open_project` on the `.dmp` → `kind: dump_session`
2. `get_dump_triage` — exception (if any), primary module, top threads
3. `list_dump_modules` / `list_dump_threads` / `get_thread_stack` / `list_memory_regions`
4. `open_dump_module` with module name or `0x` base → `kind: dump_module` project_id
5. Same PE tools: `get_triage` → `list_functions` → `get_function_evidence` / decompile

All dump tools share the single headless `serve-mcp` / `agent` server. Do **not**
BEL or linear-decode the whole multi-GB process — only modules you open.

Treat dumps like live process memory (secrets). Kernel dumps are rejected.
Avoid one-character searches on a huge PE. BEL will enter safety mode, but a
specific API, field name, string fragment, motif, or two-clause evidence query
is both faster and more useful.

## Symbols and privacy

The beta does not attempt public symbol downloads for likely non-Microsoft/game
binaries by default. It prints one quiet line and continues without a PDB. Set
`WINDY_SYMBOL_DOWNLOAD=always` to restore public symbol-server attempts or
`WINDY_SYMBOL_DOWNLOAD=never` to disable them explicitly.

All PE bytes, indexes, annotations, journals, and benchmarks stay local. The
MCP server refuses non-loopback binds. This ZIP has no installer or updater.

## Verification provenance

`BUILD-MANIFEST.json` records the exact commit, dirty-worktree state, build
time, target, and local verification commands. `BEL-BENCHMARK.json` records the
packaged executable's smoke benchmark. `Cargo.lock` freezes dependency
resolution. The ZIP's SHA-256 is stored beside it locally.

The packaging gate runs `cargo build`, `cargo clippy -- -D warnings`,
`cargo test`, beta BEL tests, a release build, and an MCP/BEL smoke test. It
skips GitHub infrastructure—not local verification.
