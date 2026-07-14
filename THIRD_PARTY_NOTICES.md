# Third-party notices

Windy includes open-source Rust dependencies. Their names, versions, package URLs, checksums, and declared license identifiers are recorded in the `windy.cdx.json` CycloneDX SBOM shipped with each release archive.

The source of truth for dependency resolution is `Cargo.lock`. Run `cargo deny check advisories licenses sources` before packaging. A dependency's own license and notice files govern that dependency; the Windy dual license applies only to Windy-authored code and assets.

Windy does not bundle Ghidra, GCLSD, a Python runtime, a Java runtime, or an external model in the release executable.
