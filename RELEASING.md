# Preparing a Windy release candidate

Publishing is separate from preparation. The manual workflow defaults to a dry
run and never publishes on a push or tag.

## Mandatory gate

```powershell
cargo fmt -- --check
cargo build
cargo clippy -- -D warnings
cargo test
python -m unittest discover eval/microbench
```

Confirm that the default dependency graph contains no GUI or GPU stack:

```powershell
$tree = cargo tree --locked
if ($tree -match '(?im)^.*\b(eframe|egui|egui_dock|egui_extras|rfd|winit|wgpu)\b') {
    throw 'GUI/GPU dependency found in default build'
}
```

Record runtime/context benchmark results according to
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md). Do not promote a diagnostic report
without source identity, target hashes, repetitions, and hardware context.

## Package

```powershell
cargo install cargo-cyclonedx --locked
.\scripts\package-release.ps1 -Version 0.3.0
```

The script builds the locked MSVC release binary, generates a CycloneDX SBOM,
runs the packaged MCP smoke, and creates
`dist\windy-v0.3.0-windows-x64.zip` plus its SHA-256 file. The archive contains
the executable, README, setup guide, licenses, third-party notice, and SBOM.

Code signing is opt-in through `-Sign`, `WINDY_SIGN_CERT_SHA1`, and optionally
`WINDY_SIGN_TIMESTAMP_URL`. The checksum is mandatory for signed and unsigned
artifacts.

## GitHub workflow

Run **Release Candidate** manually. Leave `publish` false while reviewing the
artifact. Setting it true is an explicit authorization to create a draft
release, not a public final release.
