# Export Ghidra decompilations for P0–P3 (same-profile honesty).
param(
    [string]$Root = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [string[]]$Profiles = @("P0", "P1", "P2", "P3"),
    [string[]]$Programs = @(),
    [int]$Limit = 0,
    [switch]$Force,
    [switch]$Batch,
    [switch]$SkipManifestRefresh,
    [ValidateRange(1, 64)]
    [int]$MaxCpu = 2,
    [string]$GhidraHome = $(if ($env:GHIDRA_HOME) { $env:GHIDRA_HOME } else { "D:\tools\ghidra_11.3.2_PUBLIC" }),
    [string]$JavaHome = $(if ($env:JAVA_HOME) { $env:JAVA_HOME } else { "D:\tools\jdk-17.0.13+11" })
)
$ErrorActionPreference = "Stop"
$Headless = Join-Path $GhidraHome "support\analyzeHeadless.bat"
$Script = Join-Path $Root "eval\grand\ExportDecomp.java"
$ProjDir = Join-Path $Root "eval\grand\ghidra_proj"
$BinRoot = Join-Path $Root "eval\grand\bin"
$Inv = Get-Content (Join-Path $Root "eval\grand\inventory.json") -Raw | ConvertFrom-Json
$Manifest = Get-Content (Join-Path $Root "eval\grand\manifest.json") -Raw | ConvertFrom-Json

if (-not (Test-Path $Headless)) { throw "Ghidra headless not found: $Headless" }
if (-not (Test-Path $JavaHome)) { throw "JDK not found: $JavaHome" }
New-Item -ItemType Directory -Force -Path $ProjDir | Out-Null
$env:JAVA_HOME = $JavaHome
$env:PATH = "$JavaHome\bin;" + $env:PATH
$Programs = @($Programs | ForEach-Object { $_ -split ',' } | Where-Object { $_ })

function Test-FreshExport([string]$Json, [string]$Exe) {
    (Test-Path $Json) -and
        ((Get-Item $Json).Length -gt 200) -and
        ((Get-Item $Json).LastWriteTimeUtc -ge (Get-Item $Exe).LastWriteTimeUtc)
}

function Complete-Export([string]$TempJson, [string]$Json, [string]$Label, [string]$Log) {
    if (-not (Test-Path $TempJson) -or (Get-Item $TempJson).Length -le 200) {
        throw "Ghidra produced no usable export for $Label; see $Log"
    }
    try {
        $parsed = Get-Content -LiteralPath $TempJson -Raw | ConvertFrom-Json
    } catch {
        throw "Ghidra produced invalid JSON for $Label; see $Log"
    }
    if (@($parsed).Count -eq 0) {
        throw "Ghidra export was empty for $Label; see $Log"
    }
    Move-Item -LiteralPath $TempJson -Destination $Json -Force
    Write-Host "  wrote $Json ($((Get-Item $Json).Length) bytes)"
}

function Write-TargetFile([string]$Program, [string]$Profile, [string]$OutDir) {
    $binary = $Manifest.binaries | Where-Object {
        $_.program_id -eq $Program -and $_.profile -eq $Profile
    } | Select-Object -First 1
    if (-not $binary -or -not $binary.function_map) {
        throw "No linker-derived function map for $Program $Profile; run build_all.ps1 first"
    }
    $targets = @($binary.function_map | Where-Object {
        $_.status -eq "present" -and $_.entry_va
    } | ForEach-Object { [string]$_.entry_va })
    if ($targets.Count -eq 0) {
        throw "No present linker targets for $Program $Profile"
    }
    $path = Join-Path $OutDir ($Program + "_ghidra_targets.txt")
    [System.IO.File]::WriteAllLines($path, $targets, [System.Text.UTF8Encoding]::new($false))
}

$n = 0
:profileLoop
foreach ($pr in $Profiles) {
    $outDir = Join-Path $BinRoot $pr
    if ($Batch) {
        $pending = @()
        foreach ($prog in $Inv.programs) {
            if ($Programs.Count -gt 0 -and $prog.program_id -notin $Programs) { continue }
            $exe = Join-Path $outDir ($prog.program_id + ".exe")
            $json = Join-Path $outDir ($prog.program_id + "_ghidra.json")
            if (-not (Test-Path $exe)) {
                Write-Warning "missing $exe"
                continue
            }
            if (-not $Force -and (Test-FreshExport $json $exe)) {
                Write-Host "skip fresh $pr $($prog.program_id)"
                continue
            }
            Write-TargetFile $prog.program_id $pr $outDir
            $pending += [pscustomobject]@{ Program = $prog.program_id; Exe = $exe; Json = $json }
            if ($Limit -gt 0 -and ($n + $pending.Count) -ge $Limit) { break }
        }
        if ($pending.Count -eq 0) { continue }

        $projName = "grand_{0}_batch" -f $pr
        $log = Join-Path $ProjDir ($projName + ".log")
        Write-Host "Ghidra $pr batch ($($pending.Count) programs) ..."
        $ghidraArgs = @($ProjDir, $projName, "-import")
        $ghidraArgs += @($pending | ForEach-Object { $_.Exe })
        $ghidraArgs += @(
            "-overwrite",
            "-deleteProject",
            "-max-cpu", "$MaxCpu",
            "-scriptPath", (Join-Path $Root "eval\grand"),
            "-postScript", "ExportDecomp.java", $outDir
        )
        & $Headless @ghidraArgs *> $log
        if ($LASTEXITCODE -ne 0) {
            throw "Ghidra batch failed for $pr; see $log"
        }
        foreach ($item in $pending) {
            $tempJson = "$($item.Json).tmp"
            Complete-Export $tempJson $item.Json "$($item.Program) $pr" $log
            $n++
        }
        if ($Limit -gt 0 -and $n -ge $Limit) {
            Write-Host "Limit $Limit reached"
            break profileLoop
        }
        continue
    }

    foreach ($prog in $Inv.programs) {
        if ($Programs.Count -gt 0 -and $prog.program_id -notin $Programs) {
            continue
        }
        $exe = Join-Path $outDir ($prog.program_id + ".exe")
        $json = Join-Path $outDir ($prog.program_id + "_ghidra.json")
        if (-not (Test-Path $exe)) {
            Write-Warning "missing $exe"
            continue
        }
        $isFresh = Test-FreshExport $json $exe
        if (-not $Force -and $isFresh) {
            Write-Host "skip fresh $pr $($prog.program_id)"
            continue
        }
        $projName = "grand_{0}_{1}" -f $pr, $prog.program_id
        $tempJson = "$json.tmp"
        $log = Join-Path $ProjDir ($projName + ".log")
        Write-TargetFile $prog.program_id $pr $outDir
        Write-Host "Ghidra $pr $($prog.program_id) ..."
        & $Headless $ProjDir $projName `
            -import $exe `
            -overwrite `
            -deleteProject `
            -max-cpu $MaxCpu `
            -scriptPath (Join-Path $Root "eval\grand") `
            -postScript ExportDecomp.java $tempJson *> $log
        if ($LASTEXITCODE -ne 0) {
            throw "Ghidra failed for $($prog.program_id) $pr; see $log"
        }
        Complete-Export $tempJson $json "$($prog.program_id) $pr" $log
        $n++
        if ($Limit -gt 0 -and $n -ge $Limit) {
            Write-Host "Limit $Limit reached"
            break profileLoop
        }
    }
}
if (-not $SkipManifestRefresh) {
    $pruneExports = Join-Path $Root "eval\grand\prune_ghidra_exports.py"
    python $pruneExports
    if ($LASTEXITCODE -ne 0) { throw "Ghidra export pruning failed" }
    $fixManifest = Join-Path $Root "eval\grand\fix_manifest.py"
    python $fixManifest
    if ($LASTEXITCODE -ne 0) { throw "manifest refresh failed" }
}
Write-Host "Done exports processed=$n"
