[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [string]$OutputDirectory = "",
    [switch]$SkipBuild,
    [switch]$Sign
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$dist = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Join-Path $root "dist"
} else {
    [System.IO.Path]::GetFullPath($OutputDirectory)
}
$target = "x86_64-pc-windows-msvc"
$archiveBase = "windy-v$Version-windows-x64"
$stage = Join-Path $dist $archiveBase
$zip = Join-Path $dist "$archiveBase.zip"
$checksum = "$zip.sha256"

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw "Version must be a semantic version without path separators: $Version"
}
$cargoToml = Get-Content -LiteralPath (Join-Path $root "Cargo.toml") -Raw
$packageVersionMatch = [regex]::Match($cargoToml, '(?ms)^\[package\]\s*.*?^version\s*=\s*"([^"]+)"')
if (-not $packageVersionMatch.Success -or $packageVersionMatch.Groups[1].Value -ne $Version) {
    throw "Requested version $Version does not match Cargo package version $($packageVersionMatch.Groups[1].Value)"
}
$rootPrefix = $root.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
if (-not $dist.StartsWith($rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Output directory must stay inside the repository: $dist"
}
New-Item -ItemType Directory -Path $dist -Force | Out-Null
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
if (Test-Path -LiteralPath $checksum) { Remove-Item -LiteralPath $checksum -Force }
New-Item -ItemType Directory -Path $stage | Out-Null

Push-Location $root
try {
    if (-not $SkipBuild) {
        cargo build --locked --release --target $target
        if ($LASTEXITCODE -ne 0) { throw "release build failed" }
    }

    $exe = Join-Path $root "target\$target\release\windy.exe"
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
        throw "release executable not found: $exe"
    }

    cargo cyclonedx --version | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "cargo-cyclonedx is required; run: cargo install cargo-cyclonedx --locked"
    }
    # cargo-cyclonedx accepts a filename prefix, not a path. Generate at the
    # manifest root, then move the verified result into the staging directory.
    $sbomGenerated = Join-Path $root "windy.json"
    if (Test-Path -LiteralPath $sbomGenerated) {
        Remove-Item -LiteralPath $sbomGenerated -Force
    }
    cargo cyclonedx --format json --target $target --override-filename windy
    if ($LASTEXITCODE -ne 0) { throw "SBOM generation failed" }
    if (-not (Test-Path -LiteralPath $sbomGenerated -PathType Leaf)) {
        throw "SBOM was not produced at $sbomGenerated"
    }
    Move-Item -LiteralPath $sbomGenerated -Destination (Join-Path $stage "windy.cdx.json")

    $stagedExe = Join-Path $stage "windy.exe"
    Copy-Item -LiteralPath $exe -Destination $stagedExe
    Copy-Item -LiteralPath (Join-Path $root "docs\RELEASE_README.md") -Destination (Join-Path $stage "README.md")
    Copy-Item -LiteralPath (Join-Path $root "docs\QUICKSTART.md") -Destination (Join-Path $stage "SETUP.md")
    Copy-Item -LiteralPath (Join-Path $root "LICENSE-MIT") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $root "LICENSE-APACHE") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $root "THIRD_PARTY_NOTICES.md") -Destination $stage

    if ($Sign) {
        if ([string]::IsNullOrWhiteSpace($env:WINDY_SIGN_CERT_SHA1)) {
            throw "-Sign requires WINDY_SIGN_CERT_SHA1 for a certificate in the Windows certificate store"
        }
        $signTool = Get-Command signtool.exe -ErrorAction SilentlyContinue
        if (-not $signTool) { throw "-Sign requires signtool.exe on PATH" }
        $timestamp = if ($env:WINDY_SIGN_TIMESTAMP_URL) {
            $env:WINDY_SIGN_TIMESTAMP_URL
        } else {
            "http://timestamp.digicert.com"
        }
        & $signTool.Source sign /sha1 $env:WINDY_SIGN_CERT_SHA1 /fd SHA256 /tr $timestamp /td SHA256 $stagedExe
        if ($LASTEXITCODE -ne 0) { throw "Authenticode signing failed" }
    }

    & (Join-Path $root "scripts\smoke-release.ps1") `
        -ExePath $stagedExe `
        -FixturePath (Join-Path $root "tests\fixtures\sample.exe")
    if ($LASTEXITCODE -ne 0) { throw "packaged executable smoke test failed" }

    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText($checksum, "$hash *$([System.IO.Path]::GetFileName($zip))`n", [System.Text.UTF8Encoding]::new($false))
    Write-Host "Prepared $zip"
    Write-Host "SHA-256 $hash"
}
finally {
    Pop-Location
}
