[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ExePath,
    [string]$TargetPath = "",
    [int]$MaxWaitSeconds = 120,
    [switch]$CatalogOnly,
    [switch]$WarmReopen
)

$ErrorActionPreference = "Stop"
$exe = [System.IO.Path]::GetFullPath($ExePath)
$target = if ($TargetPath) { [System.IO.Path]::GetFullPath($TargetPath) } else { $exe }
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "Windy executable not found: $exe" }
if (-not (Test-Path -LiteralPath $target -PathType Leaf)) { throw "Target not found: $target" }

function Convert-McpContent([string]$Content) {
    $line = ($Content -split "`r?`n" | Where-Object { $_ -match '^data:' } | Select-Object -Last 1)
    if ($line) { return ($line -replace '^data:\s*', '') | ConvertFrom-Json }
    return $Content | ConvertFrom-Json
}

function Invoke-Mcp([string]$Endpoint, [object]$Body, [string]$Session = "") {
    $headers = @{ Accept = "application/json, text/event-stream"; "MCP-Protocol-Version" = "2025-11-25" }
    if ($Session) { $headers["Mcp-Session-Id"] = $Session }
    $response = Invoke-WebRequest -UseBasicParsing -Method Post -Uri $Endpoint -Headers $headers `
        -ContentType "application/json" -Body ($Body | ConvertTo-Json -Depth 30 -Compress)
    return [pscustomobject]@{ Response = $response; Json = Convert-McpContent $response.Content }
}

$benchRoot = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetTempPath()) ("windy-open-bench-" + [guid]::NewGuid())))
$dataDir = Join-Path $benchRoot "state"
$stdout = Join-Path $benchRoot "stdout.log"
$stderr = Join-Path $benchRoot "stderr.log"
New-Item -ItemType Directory -Path $benchRoot -Force | Out-Null

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$endpoint = "http://127.0.0.1:$port/mcp"
$health = "http://127.0.0.1:$port/healthz"
$process = Start-Process -FilePath $exe -ArgumentList @(
    "--data-dir", ('"' + $dataDir + '"'), "serve-mcp", "--bind", "127.0.0.1:$port"
) -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr

try {
    $ready = $false
    for ($attempt = 0; $attempt -lt 100; $attempt++) {
        if ($process.HasExited) { throw "Windy exited early: $(Get-Content -LiteralPath $stderr -Raw)" }
        try { $null = Invoke-RestMethod -Method Get -Uri $health; $ready = $true; break } catch { Start-Sleep -Milliseconds 50 }
    }
    if (-not $ready) { throw "Windy did not become ready" }

    $initialize = Invoke-Mcp $endpoint @{
        jsonrpc = "2.0"; id = 1; method = "initialize"; params = @{
            protocolVersion = "2025-11-25"; capabilities = @{};
            clientInfo = @{ name = "windy-open-bench"; version = "0.2.0" }
        }
    }
    $session = [string]$initialize.Response.Headers["Mcp-Session-Id"]
    $null = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; method = "notifications/initialized" } $session

    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $opened = Invoke-Mcp $endpoint @{
        jsonrpc = "2.0"; id = 2; method = "tools/call";
        params = @{ name = "investigation_start"; arguments = @{
            path = $target; intent = "locate"; question = "Catalog the target and locate its entry point"; budget = "tiny"
        } }
    } $session
    $handleMs = $clock.ElapsedMilliseconds
    $jobId = [string]$opened.Json.result.structuredContent.data.job_id
    $investigationId = [string]$opened.Json.result.structuredContent.data.investigation_id
    $actionId = [string]$opened.Json.result.structuredContent.data.next_actions[0].execute.arguments.action_id
    if (-not $jobId -or -not $investigationId -or -not $actionId) { throw "investigation_start returned no continuation" }

    $peakRss = 0L
    $catalogMs = 0L
    $targetId = ""
    $sketchMs = 0L
    $deadline = [DateTime]::UtcNow.AddSeconds($MaxWaitSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        $process.Refresh()
        if ($process.WorkingSet64 -gt $peakRss) { $peakRss = $process.WorkingSet64 }
        $status = Invoke-Mcp $endpoint @{
            jsonrpc = "2.0"; id = 3; method = "tools/call";
            params = @{ name = "windy_status"; arguments = @{ id = $jobId } }
        } $session
        $job = $status.Json.result.structuredContent.data.job
        if ($job.state -eq "partial" -and $job.stage -eq "catalog ready") {
            $catalogMs = $clock.ElapsedMilliseconds
            break
        }
        if ($job.state -eq "complete") { $targetId = [string]$job.target_id; break }
        if ($job.state -eq "error") { throw "catalog failed: $($job.error)" }
        Start-Sleep -Milliseconds 100
    }
    if (-not $catalogMs -and -not $targetId) { throw "catalog exceeded $MaxWaitSeconds seconds" }

    if (-not $targetId -and -not $CatalogOnly) {
        $null = Invoke-Mcp $endpoint @{
            jsonrpc = "2.0"; id = 4; method = "tools/call";
            params = @{ name = "investigation_step"; arguments = @{ investigation_id = $investigationId; action_id = $actionId } }
        } $session
        while ([DateTime]::UtcNow -lt $deadline) {
            $process.Refresh()
            if ($process.WorkingSet64 -gt $peakRss) { $peakRss = $process.WorkingSet64 }
            $status = Invoke-Mcp $endpoint @{
                jsonrpc = "2.0"; id = 5; method = "tools/call";
                params = @{ name = "windy_status"; arguments = @{ id = $jobId } }
            } $session
            $job = $status.Json.result.structuredContent.data.job
            if ($job.state -eq "partial" -and $job.stage -eq "sketch ready") {
                $sketchMs = $clock.ElapsedMilliseconds
                break
            }
            if ($job.state -eq "complete") { $targetId = [string]$job.target_id; break }
            if ($job.state -eq "error") { throw "analysis failed: $($job.error)" }
            Start-Sleep -Milliseconds 100
        }
    }
    if (-not $targetId -and -not $sketchMs -and -not $CatalogOnly) { throw "sketch exceeded $MaxWaitSeconds seconds" }

    $warmHandleMs = $null
    $warmCatalogMs = $null
    $warmSketchMs = $null
    if ($WarmReopen -and -not $CatalogOnly) {
        $null = Invoke-Mcp $endpoint @{
            jsonrpc = "2.0"; id = 6; method = "tools/call";
            params = @{ name = "target_close"; arguments = @{ target_id = $jobId } }
        } $session
        $warmClock = [System.Diagnostics.Stopwatch]::StartNew()
        $warmOpen = Invoke-Mcp $endpoint @{
            jsonrpc = "2.0"; id = 7; method = "tools/call";
            params = @{ name = "investigation_start"; arguments = @{
                path = $target; intent = "locate"; question = "Catalog the target and locate its entry point"; budget = "tiny"
            } }
        } $session
        $warmHandleMs = $warmClock.ElapsedMilliseconds
        $warmJobId = [string]$warmOpen.Json.result.structuredContent.data.job_id
        $warmInvestigationId = [string]$warmOpen.Json.result.structuredContent.data.investigation_id
        $warmActionId = [string]$warmOpen.Json.result.structuredContent.data.next_actions[0].execute.arguments.action_id
        $warmDeadline = [DateTime]::UtcNow.AddSeconds($MaxWaitSeconds)
        while ([DateTime]::UtcNow -lt $warmDeadline) {
            $process.Refresh()
            if ($process.WorkingSet64 -gt $peakRss) { $peakRss = $process.WorkingSet64 }
            $status = Invoke-Mcp $endpoint @{
                jsonrpc = "2.0"; id = 8; method = "tools/call";
                params = @{ name = "windy_status"; arguments = @{ id = $warmJobId } }
            } $session
            $job = $status.Json.result.structuredContent.data.job
            if ($job.state -eq "partial" -and $job.stage -eq "catalog ready") {
                $warmCatalogMs = $warmClock.ElapsedMilliseconds
                break
            }
            if ($job.state -eq "error") { throw "warm catalog failed: $($job.error)" }
            Start-Sleep -Milliseconds 20
        }
        $null = Invoke-Mcp $endpoint @{
            jsonrpc = "2.0"; id = 9; method = "tools/call";
            params = @{ name = "investigation_step"; arguments = @{
                investigation_id = $warmInvestigationId; action_id = $warmActionId
            } }
        } $session
        while ([DateTime]::UtcNow -lt $warmDeadline) {
            $process.Refresh()
            if ($process.WorkingSet64 -gt $peakRss) { $peakRss = $process.WorkingSet64 }
            $status = Invoke-Mcp $endpoint @{
                jsonrpc = "2.0"; id = 10; method = "tools/call";
                params = @{ name = "windy_status"; arguments = @{ id = $warmJobId } }
            } $session
            $job = $status.Json.result.structuredContent.data.job
            if ($job.state -eq "partial" -and $job.stage -eq "sketch ready") {
                $warmSketchMs = $warmClock.ElapsedMilliseconds
                break
            }
            if ($job.state -eq "error") { throw "warm sketch failed: $($job.error)" }
            Start-Sleep -Milliseconds 20
        }
        if (-not $warmCatalogMs -or -not $warmSketchMs) { throw "warm reopen exceeded $MaxWaitSeconds seconds" }
    }

    [pscustomobject]@{
        target = $target
        immediate_handle_ms = $handleMs
        catalog_complete_ms = $catalogMs
        sketch_complete_ms = if ($sketchMs) { $sketchMs } else { $null }
        full_project_complete_ms = if ($targetId) { $clock.ElapsedMilliseconds } else { $null }
        warm_handle_ms = $warmHandleMs
        warm_catalog_ms = $warmCatalogMs
        warm_sketch_ms = $warmSketchMs
        peak_rss_mib = [math]::Round($peakRss / 1MB, 1)
        target_id = $targetId
    } | ConvertTo-Json
}
finally {
    if ($process -and -not $process.HasExited) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
    $tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    if ($benchRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $benchRoot)) {
        Remove-Item -LiteralPath $benchRoot -Recurse -Force
    }
}
