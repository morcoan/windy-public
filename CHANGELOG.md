# Changelog

All notable changes will be documented here.

## 0.1.0 - release candidate

- Added a portable Windows x64 GUI and headless Streamable HTTP MCP mode with no external decompiler service.
- Promoted checked native V2 decompilation to the product path with explicit legacy fallback and pure-V2 diagnostics.
- Added block-specific exit-value recovery and checker coverage for divergent returns.
- Added structured MCP results/errors, accurate tool annotations, health checks, origin validation, and loopback-only binding.
- Unified IDBs, journals, memory, workspaces, signatures, and vtables under one data-directory resolver.
- Added `doctor`, release smoke tests, packaging automation, SBOM/checksum output, and client setup documentation.
