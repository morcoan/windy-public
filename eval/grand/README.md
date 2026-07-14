# Grand benchmark fixture provenance

The Grand suite is an authored Windy evaluation corpus, not a collection of
third-party programs. Its C sources are under `src/`, its source/pack inventory
is `inventory.json`, and its source-gold and graph-gold records are under
`gold/` and `graph_gold/`.

`build_all.ps1` builds each program for Windows x64 with the Visual Studio 2022
MSVC toolchain in four documented profiles:

- P0: `/Od /Ob0`
- P1: `/O1`
- P2: `/O2 /Ob2`
- P3: `/O2 /GL` with `/LTCG`

The resulting PEs are retained under `bin/P0` through `bin/P3` because strict
scorecard reproduction requires the exact analyzed bytes. `manifest.json`
records every PE's profile, relative path, SHA-256 digest, and exact source
function VAs captured from the linker MAP. The v0.1 release-candidate corpus
was rebuilt with MSVC compiler `19.44.35228` and linker `14.44.35228.0`; the
checked-in hashes remain the authoritative binary identity.

Ghidra comparison JSON was exported from Ghidra `11.3.2_PUBLIC` with Temurin
OpenJDK `17.0.13+11` and `ExportDecomp.java`. Run
`export_ghidra_profiles.ps1 -Batch` after rebuilding. It performs normal full
analysis and then `prune_ghidra_exports.py` retains only linker-allowlisted,
Windy-authored target functions; statically linked MSVC runtime pseudocode is
not a release input. No Ghidra installation or project database is included.

Strict scoring reads the exact-address identities embedded in `manifest.json`.
The strict lane never calls a gold-aware picker. Each manifest entry records
present, folded, inlined-only, or missing status explicitly so omissions remain
fail-closed.

All authored sources, binaries, gold data, manifest identities, and export records in this
fixture corpus are distributed under Windy's repository license. Regenerate
the manifest and comparison exports whenever a source, compiler profile, or PE
hash changes.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\eval\grand\build_all.ps1
$env:GHIDRA_HOME = 'D:\tools\ghidra_11.3.2_PUBLIC'
$env:JAVA_HOME = 'D:\tools\jdk-17.0.13+11'
powershell -NoProfile -ExecutionPolicy Bypass -File .\eval\grand\export_ghidra_profiles.ps1 -Batch
cargo run -- bench grand --suite v2-strict --output .\artifacts\strict-v2.json
```
