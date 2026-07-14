# Build all Grand Bench programs under P0–P3 (MSVC x64).
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot))
)
$ErrorActionPreference = "Stop"
$Grand = Join-Path $Root "eval\grand"
$Bin = Join-Path $Grand "bin"
$Inv = Join-Path $Grand "inventory.json"
New-Item -ItemType Directory -Force -Path $Bin | Out-Null

$vs = @(
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat",
    "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vs) { throw "vcvars64.bat not found" }

$inventory = Get-Content $Inv -Raw | ConvertFrom-Json
# The profile flags intentionally use documented MSVC switches only. Earlier
# versions passed Intel's /Qvec- spelling, which MSVC ignored with D9002.
$profiles = @(
    @{ name = "P0"; cflags = "/Od /Ob0"; linkextra = "" },
    @{ name = "P1"; cflags = "/O1"; linkextra = "" },
    @{ name = "P2"; cflags = "/O2 /Ob2"; linkextra = "" },
    @{ name = "P3"; cflags = "/O2 /GL"; linkextra = "/LTCG" }
)

$manifest = @{
    binaries       = @()
    profiles       = @("P0", "P1", "P2", "P3")
    program_count  = $inventory.count
    binary_count   = 0
}

function Get-Sha256([string]$Path) {
    (Get-FileHash -Algorithm SHA256 -Path $Path).Hash.ToLowerInvariant()
}

function Resolve-Sources($prog) {
    $list = @()
    if ($prog.PSObject.Properties.Name -contains "sources" -and $prog.sources) {
        foreach ($s in $prog.sources) {
            $rel = ($s -replace '/', '\')
            $list += (Join-Path $Root $rel)
        }
    } else {
        $srcRel = $prog.source -replace '/', '\'
        $list += (Join-Path $Root $srcRel)
    }
    return $list
}

function Resolve-Includes($prog) {
    $incs = @()
    if ($prog.PSObject.Properties.Name -contains "includes" -and $prog.includes) {
        foreach ($i in $prog.includes) {
            $rel = ($i -replace '/', '\')
            $incs += ("/I`"{0}`"" -f (Join-Path $Root $rel))
        }
    }
    return ($incs -join " ")
}

foreach ($prog in $inventory.programs) {
    $srcList = Resolve-Sources $prog
    $missing = $srcList | Where-Object { -not (Test-Path $_) }
    if ($missing) {
        Write-Warning "missing source $($prog.program_id): $($missing -join ', ')"
        continue
    }
    $incFlags = Resolve-Includes $prog
    $srcQuoted = ($srcList | ForEach-Object { "`"$_`"" }) -join " "
    foreach ($pr in $profiles) {
        $outDir = Join-Path $Bin $pr.name
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
        $exe = Join-Path $outDir ($prog.program_id + ".exe")
        $map = Join-Path $outDir ($prog.program_id + ".map")
        # Remove stale PE so OK is not false-positive when cl fails.
        if (Test-Path $exe) { Remove-Item -Force $exe }
        $cflags = $pr.cflags
        $linkextra = $pr.linkextra
        # Multi-file: let cl place objs next to sources is messy; use cwd obj names.
        # Avoid /Fo"dir\" — trailing backslash escapes the closing quote (D8003).
        $cmd = @"
call `"$vs`" >nul && cd /d `"$outDir`" && cl /nologo /TC /W3 $cflags $incFlags /Fe:`"$exe`" $srcQuoted /link /nologo /MAP:`"$map`" $linkextra
"@
        cmd /c $cmd | Out-Null
        if (-not (Test-Path $exe)) {
            Write-Warning "build failed $($prog.program_id) $($pr.name)"
            continue
        }
        $sha = Get-Sha256 $exe
        $ghidra = Join-Path $outDir ($prog.program_id + "_ghidra.json")
        $ghidraRel = $null
        if ((Test-Path $ghidra) -and
            ((Get-Item $ghidra).Length -gt 200) -and
            ((Get-Item $ghidra).LastWriteTimeUtc -ge (Get-Item $exe).LastWriteTimeUtc)) {
            $ghidraRel = ("eval/grand/bin/{0}/{1}_ghidra.json" -f $pr.name, $prog.program_id)
        }
        $manifest.binaries += [ordered]@{
            program_id    = $prog.program_id
            profile       = $pr.name
            pe_path       = ("eval/grand/bin/{0}/{1}.exe" -f $pr.name, $prog.program_id)
            sha256        = $sha
            pack_tags     = @($prog.pack_tags)
            kind          = $prog.kind
            gold_path     = ($prog.gold -replace '\\', '/')
            ghidra_export = $ghidraRel
        }
        Write-Host "OK $($prog.program_id) $($pr.name)"
    }
}

$manifest.binary_count = $manifest.binaries.Count
# Prefer Python JSON (ConvertTo-Json has historically corrupted deep tables).
$fixPy = Join-Path $Grand "fix_manifest.py"
if (Test-Path $fixPy) {
    python $fixPy
} else {
    $manPath = Join-Path $Grand "manifest.json"
    ($manifest | ConvertTo-Json -Depth 6) | Set-Content -Path $manPath -Encoding UTF8
    Write-Host "Wrote $manPath with $($manifest.binary_count) binaries"
}
