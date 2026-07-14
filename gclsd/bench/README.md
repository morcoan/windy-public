# Authored smoke and quality fixtures

`sample.c` and `complex.c` are Windy-authored Windows x64 benchmark programs.
Their matching PE files and source-gold records are retained so the native
decompiler scorecards can run without a compiler or Ghidra installation.
They are distributed under Windy's repository license; they are not
third-party binaries.

The PEs were built with the Visual Studio 2022 MSVC toolchain. The original
fixture authoring session did not record the compiler patch version, so these
SHA-256 values are their authoritative identities:

| Fixture | SHA-256 |
|---|---|
| `sample.exe` | `bf6481d42c68332b911761f2342bf5e70a8917415d21a4635316508b75abccc0` |
| `complex.exe` | `b90895e8a793f09c502f499181b7e9507376bef131a2525a4182c0fba97be2bc` |

The checked-in `ghidra_output.json` and `complex_ghidra_output.json` files were
exported from the matching binaries with Ghidra `11.3.2_PUBLIC` and
`decompile_to_file.py`. Re-export them whenever either PE changes.

Archived GCLSD model experiments remain in this directory for reproducibility,
but the public Windy executable neither compiles nor calls a model client.
