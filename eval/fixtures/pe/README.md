# Authored PE fixtures

`sample` is the compact smoke target; `complex` exercises the native
decompiler's known quality gaps. Each target includes authored C source, a
checked-in Windows PE, and an allowlisted Ghidra export. Scoring contracts live
under `eval/gold/`.

These binaries are test inputs, not distributable Windy builds. If a fixture is
rebuilt, update its source-gold provenance and all pinned hashes in the same
change.
