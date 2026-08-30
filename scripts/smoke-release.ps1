[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [string]$FixturePath = "",

    [string]$ExpectedProductName = "windy"
)

$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$exe = [System.IO.Path]::GetFullPath($ExePath)
$fixture = if ([string]::IsNullOrWhiteSpace($FixturePath)) {
    Join-Path $root "gclsd\bench\sample.exe"
} else {
    [System.IO.Path]::GetFullPath($FixturePath)
}
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw "Windy executable not found: $exe"
}
if (-not (Test-Path -LiteralPath $fixture -PathType Leaf)) {
    throw "Authored smoke fixture not found: $fixture"
}

function Assert-True([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

function Convert-McpContent([string]$Content) {
    $trimmed = $Content.Trim()
    if ($trimmed.StartsWith("data:") -or $trimmed.Contains("`ndata:")) {
        $data = $trimmed -split "`r?`n" | ForEach-Object {
            if ($_ -match '^data:\s*(\S.*)$') { $Matches[1] }
        } | Select-Object -First 1
        if (-not $data) { throw "MCP response contained no SSE data" }
        return $data | ConvertFrom-Json
    }
    return $trimmed | ConvertFrom-Json
}

function Invoke-Mcp(
    [string]$Endpoint,
    [object]$Body,
    [string]$Session = "",
    [switch]$AllowEmpty
) {
    $headers = @{
        Accept = "application/json, text/event-stream"
        "MCP-Protocol-Version" = "2025-11-25"
    }
    if ($Session) { $headers["Mcp-Session-Id"] = $Session }
    $response = Invoke-WebRequest -UseBasicParsing -Method Post -Uri $Endpoint `
        -Headers $headers -ContentType "application/json" `
        -Body ($Body | ConvertTo-Json -Depth 100 -Compress)
    $json = $null
    if ($response.Content -and -not $AllowEmpty) {
        $json = Convert-McpContent $response.Content
    }
    return [pscustomobject]@{ Response = $response; Json = $json }
}

& $exe --help | Out-Null
if ($LASTEXITCODE -ne 0) { throw "windy --help failed" }
& $exe --version | Out-Null
if ($LASTEXITCODE -ne 0) { throw "windy --version failed" }

$tempRoot = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetTempPath()) ("windy-release-smoke-" + [guid]::NewGuid())))
$dataDir = Join-Path $tempRoot "state"
$stdout = Join-Path $tempRoot "server.stdout.log"
$stderr = Join-Path $tempRoot "server.stderr.log"
New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
$listener.Start()
$port = ([System.Net.IPEndPoint]$listener.LocalEndpoint).Port
$listener.Stop()
$endpoint = "http://127.0.0.1:$port/mcp"
$health = "http://127.0.0.1:$port/healthz"
$process = $null

try {
    $argumentList = @(
        "--data-dir", ('"' + $dataDir + '"'),
        "serve-mcp", "--bind", "127.0.0.1:$port"
    )
    $process = Start-Process -FilePath $exe -ArgumentList $argumentList -PassThru `
        -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr

    $ready = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {
        if ($process.HasExited) {
            throw "Windy server exited early with code $($process.ExitCode): $(Get-Content -LiteralPath $stderr -Raw)"
        }
        try {
            $status = Invoke-RestMethod -Method Get -Uri $health
            if ($status.name -eq $ExpectedProductName -and $status.status -eq "ok") {
                $ready = $true
                break
            }
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    Assert-True $ready "Windy health endpoint did not become ready"

    $initialize = Invoke-Mcp $endpoint @{
        jsonrpc = "2.0"; id = 1; method = "initialize"; params = @{
            protocolVersion = "2025-11-25"; capabilities = @{}; clientInfo = @{
                name = "windy-release-smoke"; version = "0.2.0"
            }
        }
    }
    Assert-True ($initialize.Json.result.serverInfo.name -eq $ExpectedProductName) "Unexpected MCP identity"
    $session = [string]$initialize.Response.Headers["Mcp-Session-Id"]
    Assert-True ([bool]$session) "MCP session header missing"
    Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; method = "notifications/initialized" } $session -AllowEmpty | Out-Null

    $tools = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 2; method = "tools/list"; params = @{} } $session
    Assert-True ($tools.Json.result.tools.Count -eq 12) "MCP tools/list did not return the v2 surface"
    Assert-True ($tools.Response.Content.Length -le 12288) "MCP tools/list exceeded the 12 KiB release budget"

    $open = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 3; method = "tools/call"; params = @{
        name = "target_open"; arguments = @{ path = $fixture }
    }} $session
    $jobId = [string]$open.Json.result.structuredContent.data.job_id
    Assert-True ([bool]$jobId) "target_open returned no job_id"
    $projectId = ""
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        $job = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 30; method = "tools/call"; params = @{
            name = "server_status"; arguments = @{ job_id = $jobId }
        }} $session
        $jobData = $job.Json.result.structuredContent.data.job
        if ($jobData.state -eq "complete") {
            $projectId = [string]$jobData.target_id
            break
        }
        if ($jobData.state -eq "error") { throw "target_open failed: $($jobData.error)" }
        Start-Sleep -Milliseconds 100
    }
    Assert-True ([bool]$projectId) "target_open job did not complete"

    $bel = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 7; method = "tools/call"; params = @{
        name = "evidence_search"; arguments = @{
            target_id = $projectId; query = "mov"; mode = "token"; limit = 2; deadline_ms = 120000
        }
    }} $session
    Assert-True (-not $bel.Json.result.isError) "evidence_search failed"
    Assert-True ([bool]$bel.Json.result.structuredContent.data.total_kind) "BEL total contract missing"

    $functions = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 4; method = "tools/call"; params = @{
        name = "capability_execute"; arguments = @{
            capability_id = "list_functions"; arguments = @{ target_id = $projectId; limit = 16 }
        }
    }} $session
    $va = [string]$functions.Json.result.structuredContent.data.functions[0].va
    Assert-True ([bool]$va) "list_functions returned no function"

    $evidence = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 5; method = "tools/call"; params = @{
        name = "function_inspect"; arguments = @{ target_id = $projectId; va = $va; max_items = 2 }
    }} $session
    Assert-True (-not $evidence.Json.result.isError) "function_inspect failed"
    Assert-True ([bool]$evidence.Json.result.structuredContent) "evidence structuredContent missing"
    Assert-True ($evidence.Response.Content.Length -le 65536) "function_inspect exceeded the hard inline budget"
    $evidenceText = [string]$evidence.Json.result.content[0].text
    Assert-True (-not $evidenceText.Contains('"data"')) "function_inspect duplicated structured JSON into text"

    $decompile = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 6; method = "tools/call"; params = @{
        name = "capability_execute"; arguments = @{
            capability_id = "decompile_function"; arguments = @{
                target_id = $projectId; va = $va; policy = "product"; max_tokens = 256
            }
        }
    }} $session
    Assert-True (-not $decompile.Json.result.isError) "native decompilation failed"
    Assert-True (@("ok", "omitted", "pending") -contains [string]$decompile.Json.result.structuredContent.data.status) "Unexpected decompile status"

    $close = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 8; method = "tools/call"; params = @{
        name = "target_close"; arguments = @{ target_id = $projectId }
    }} $session
    Assert-True (-not $close.Json.result.isError) "target_close failed"

    & $exe doctor --endpoint $endpoint --open $fixture --data-dir $dataDir | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "windy doctor endpoint probe failed" }
    Write-Host "Packaged $ExpectedProductName smoke test passed ($projectId $va; tools/list=$($tools.Response.Content.Length) bytes; function_inspect=$($evidence.Response.Content.Length) bytes)."
}
finally {
    if ($process -and -not $process.HasExited) {
        Stop-Process -Id $process.Id -Force
        $process.WaitForExit()
    }
    $tempBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd('\', '/') +
        [System.IO.Path]::DirectorySeparatorChar
    $isTempChild = $tempRoot.StartsWith($tempBase, [System.StringComparison]::OrdinalIgnoreCase)
    if ($isTempChild -and (Test-Path -LiteralPath $tempRoot)) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
