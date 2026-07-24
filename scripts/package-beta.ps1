[CmdletBinding()]
param(
    [string]$Version = "0.1.1-beta.local",
    [string]$OutputDirectory = ""
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$artifactsRoot = Join-Path $root ".artifacts"
$output = if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    Join-Path $artifactsRoot "windy-beta"
} else {
    [System.IO.Path]::GetFullPath($OutputDirectory)
}
$target = "x86_64-pc-windows-msvc"
$archiveBase = "windy-beta-v$Version-windows-x64"
$stage = [System.IO.Path]::GetFullPath((Join-Path $output $archiveBase))
$zip = [System.IO.Path]::GetFullPath((Join-Path $output "$archiveBase.zip"))
$checksum = "$zip.sha256"

if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$') {
    throw "Version must be a semantic version without path separators: $Version"
}
$artifactPrefix = [System.IO.Path]::GetFullPath($artifactsRoot).TrimEnd('\', '/') +
    [System.IO.Path]::DirectorySeparatorChar
if (-not $output.StartsWith($artifactPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Private beta output must stay under $artifactsRoot (resolved: $output)"
}
if (-not $stage.StartsWith($artifactPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing unsafe staging path: $stage"
}

New-Item -ItemType Directory -Path $output -Force | Out-Null
if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force }
if (Test-Path -LiteralPath $checksum) { Remove-Item -LiteralPath $checksum -Force }
New-Item -ItemType Directory -Path $stage | Out-Null

Push-Location $root
try {
    # Required repository verification gate. This deliberately replaces
    # GitHub checks with local checks; it does not bypass quality checks.
    cargo build
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    cargo clippy -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw "cargo clippy failed" }
    cargo test
    if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }

    # Beta-only feature coverage is additional to the frozen gate.
    cargo test --features beta analysis::bel
    if ($LASTEXITCODE -ne 0) { throw "BEL beta tests failed" }

    cargo build --locked --release --features beta --target $target
    if ($LASTEXITCODE -ne 0) { throw "windy-beta release build failed" }
    $builtExe = Join-Path $root "target\$target\release\windy.exe"
    if (-not (Test-Path -LiteralPath $builtExe -PathType Leaf)) {
        throw "release executable not found: $builtExe"
    }

    $stagedExe = Join-Path $stage "windy-beta.exe"
    Copy-Item -LiteralPath $builtExe -Destination $stagedExe
    Copy-Item -LiteralPath (Join-Path $root "docs\BETA_README.md") -Destination (Join-Path $stage "README.md")
    Copy-Item -LiteralPath (Join-Path $root "docs\QUICKSTART.md") -Destination (Join-Path $stage "SETUP.md")
    Copy-Item -LiteralPath (Join-Path $root "docs\BEL.md") -Destination (Join-Path $stage "BEL.md")
    Copy-Item -LiteralPath (Join-Path $root "Cargo.lock") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $root "LICENSE-MIT") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $root "LICENSE-APACHE") -Destination $stage
    Copy-Item -LiteralPath (Join-Path $root "THIRD_PARTY_NOTICES.md") -Destination $stage

    $gitCommit = (git rev-parse HEAD).Trim()
    $gitDirty = [bool](git status --porcelain)
    $manifest = [ordered]@{
        product = "windy-beta"
        version = $Version
        channel = "private-beta"
        visibility = "local-private"
        github_release = $false
        github_checks_used = $false
        local_verification_skipped = $false
        target = $target
        git_commit = $gitCommit
        git_dirty = $gitDirty
        built_utc = [DateTime]::UtcNow.ToString("o")
        verification = @(
            "cargo build",
            "cargo clippy -- -D warnings",
            "cargo test",
            "cargo test --features beta analysis::bel",
            "packaged MCP/BEL smoke test"
        )
    }
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $stage "BUILD-MANIFEST.json") -Encoding utf8

    & (Join-Path $root "scripts\smoke-release.ps1") -ExePath $stagedExe -ExpectedProductName "windy-beta"
    if ($LASTEXITCODE -ne 0) { throw "packaged windy-beta smoke test failed" }

    # Windows PowerShell 5 promotes native stderr progress lines to error
    # records when ErrorActionPreference=Stop. Capture both streams directly
    # so normal BEL progress cannot abort an otherwise successful benchmark.
    $benchFixture = Join-Path $root "gclsd\bench\sample.exe"
    $benchStart = [System.Diagnostics.ProcessStartInfo]::new()
    $benchStart.FileName = $stagedExe
    $benchStart.Arguments = "bench bel --pe `"$benchFixture`" --iterations 20"
    $benchStart.WorkingDirectory = $root
    $benchStart.UseShellExecute = $false
    $benchStart.CreateNoWindow = $true
    $benchStart.RedirectStandardOutput = $true
    $benchStart.RedirectStandardError = $true
    $benchProcess = [System.Diagnostics.Process]::Start($benchStart)
    $benchStdout = $benchProcess.StandardOutput.ReadToEnd()
    $benchStderr = $benchProcess.StandardError.ReadToEnd()
    $benchProcess.WaitForExit()
    if ($benchProcess.ExitCode -ne 0) {
        throw "packaged BEL benchmark failed: $benchStderr"
    }
    [System.IO.File]::WriteAllText(
        (Join-Path $stage "BEL-BENCHMARK.json"),
        $benchStdout.TrimEnd() + [Environment]::NewLine,
        [System.Text.UTF8Encoding]::new($false)
    )

    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal
    $hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
    [System.IO.File]::WriteAllText(
        $checksum,
        "$hash *$([System.IO.Path]::GetFileName($zip))`n",
        [System.Text.UTF8Encoding]::new($false)
    )

    # The distributable is the ZIP. Remove only the validated private staging
    # child so no unpacked executable is mistaken for a public release.
    if (Test-Path -LiteralPath $stage) {
        Remove-Item -LiteralPath $stage -Recurse -Force
    }
    Write-Host "Prepared private local beta: $zip"
    Write-Host "SHA-256 $hash"
    Write-Host "No GitHub API, release, tag, push, or remote check was used."
}
finally {
    Pop-Location
}
