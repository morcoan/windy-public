# Contributing

Windy is a pure MCP, static-analysis project. External agents own planning; Windy provides bounded evidence and durable reversible state.

Before opening a change:

```powershell
cargo fmt -- --check
cargo build
cargo clippy -- -D warnings
cargo test
```

Do not change the frozen LLM4Decompile text format, legacy output, or static-only architecture without an explicit compatibility proposal. Prefer evidence tools over whole-image dumps. Route all mutations through MCP operations or `ProjectManager::apply_op`.

New decompiler behavior needs a focused regression and checker/contract coverage where relevant. New MCP behavior needs Streamable HTTP coverage using an isolated data directory.

Never commit proprietary binaries, credentials, generated reverse-engineering databases, or scratch reports. Authored PE fixtures must include their source and build provenance.
