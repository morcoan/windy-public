# Windy v0.3 microbench

This is the small, private, model-facing evaluation loop for Windy v0.3. It
does not load `eval/grand` or `eval/dataset-curator` and uses only Python's
standard library.

```powershell
python -m eval.microbench.microbench --root . init
python -m eval.microbench.microbench --root . issue --split canary --endpoint http://127.0.0.1:8765/mcp
python -m eval.microbench.microbench --root . ingest --run-id v03-cycle-1 --variant v03 --sidecars target/v03-microbench/sidecars
python -m eval.microbench.microbench --root . summary --run-id v03-cycle-1
```

`init` compiles six stripped, neutrally named PE targets from three generated
programs (P0 and P2). Sources, linker maps, gold, and trajectories stay under
ignored directories. A model-facing packet contains only a staged PE, a task,
the actual MCP schemas, and hard call/byte limits. It never contains an oracle.

Luna runs are valid only when the agent uses Windy MCP calls and does not read
the repository, generated sources, maps, database, or another task's output.
