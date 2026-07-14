# Preparing a Windy release candidate

Publishing is intentionally separate from preparation. Do not push, tag, create a release, or change repository visibility while following the dry-run path.

## Local gate

```powershell
cargo fmt -- --check
cargo build
cargo clippy -- -D warnings
cargo test
cargo run -- bench grand --suite v2-strict --output docs\benchmarks\v0.1.0-rc-strict-v2.json
```

Record the manifest SHA-256 and source identity beside the strict report. Compare it with the hash-pinned exact-address baseline in `docs/benchmarks/v0.1.0-baseline.json` using the criteria in `docs/BENCHMARKS.md`. The archived approximate pre-change summary is non-comparable and must not drive acceptance.

Read `docs/benchmarks/v0.1.0-rc/provenance.json` before packaging or
publishing. A `release_acceptance.status` other than `pass` is a hard stop for
publication, even when the executable and packaging smoke tests succeed.

## Package

Install `cargo-cyclonedx`, then run:

```powershell
cargo install cargo-cyclonedx --locked
.\scripts\package-release.ps1
```

The script builds the default-feature MSVC release binary, runs the packaged executable smoke test, and creates `dist\windy-v0.1.0-windows-x64.zip` plus a SHA-256 file. The archive contains the executable, short README, offline setup guide, both licenses, third-party notice, and CycloneDX SBOM.

Code signing is disabled by default. A maintainer can explicitly opt into the
prepared hook with `-Sign` after placing a code-signing certificate in the
Windows certificate store and setting `WINDY_SIGN_CERT_SHA1` (and optionally
`WINDY_SIGN_TIMESTAMP_URL`). The unsigned checksum remains mandatory.

## GitHub workflow

The manual Release Candidate workflow defaults to a dry run and uploads a CI artifact only. Its `publish` input must remain false during preparation. A future, explicit publish authorization may set it true to create a draft release; that path is never triggered by pushes or tags.
