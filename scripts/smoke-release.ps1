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
    Join-Path $root "eval\fixtures\pe\sample.exe"
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
                name = "windy-release-smoke"; version = "0.3.1"
            }
        }
    }
    Assert-True ($initialize.Json.result.serverInfo.name -eq $ExpectedProductName) "Unexpected MCP identity"
    $session = [string]$initialize.Response.Headers["Mcp-Session-Id"]
    Assert-True ([bool]$session) "MCP session header missing"
    Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; method = "notifications/initialized" } $session -AllowEmpty | Out-Null

    $tools = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 2; method = "tools/list"; params = @{} } $session
    Assert-True ($tools.Json.result.tools.Count -eq 6) "MCP tools/list did not return the v3 surface"
    Assert-True ($tools.Response.Content.Length -le 4096) "MCP tools/list exceeded the 4 KiB release budget"

    $start = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 3; method = "tools/call"; params = @{
        name = "investigation_start"; arguments = @{
            path = $fixture
            intent = "locate"
            question = "locate a NUL-terminated byte-counting loop"
            budget = "tiny"
        }
    }} $session
    Assert-True (-not $start.Json.result.isError) "investigation_start failed"
    $startData = $start.Json.result.structuredContent.data
    $actionId = [string]$startData.next_actions[0].execute.arguments.action_id
    Assert-True ([bool]$actionId) "investigation_start returned no action ticket"

    $targetId = ""
    $functionVa = ""
    $stepBytes = 0
    for ($attempt = 0; $attempt -lt 200; $attempt++) {
        $step = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 4; method = "tools/call"; params = @{
            name = "investigation_step"; arguments = @{ action_id = $actionId }
        }} $session
        Assert-True (-not $step.Json.result.isError) "investigation_step failed"
        $stepBytes = $step.Response.Content.Length
        $stepData = $step.Json.result.structuredContent.data
        if ($stepData.stage -eq "sketch" -and $stepData.state -ne "pending") {
            $targetId = [string]$stepData.target_id
            if ($stepData.answer.address) { $functionVa = [string]$stepData.answer.address }
            elseif ($stepData.evidence_delta.Count -gt 0) { $functionVa = [string]$stepData.evidence_delta[0].address }
            break
        }
        Start-Sleep -Milliseconds 25
    }
    Assert-True ([bool]$targetId) "investigation did not reach the sketch stage"
    Assert-True ([bool]$functionVa) "investigation returned no evidence address"
    Assert-True ($stepBytes -le 8192) "evidence delta exceeded the 8 KiB hard inline budget"

    $edit = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 5; method = "tools/call"; params = @{
        name = "investigation_start"; arguments = @{
            target_id = $targetId
            intent = "edit"
            question = "attach the function comment 'v3 packaged smoke marker' to $functionVa"
            budget = "tiny"
        }
    }} $session
    $editData = $edit.Json.result.structuredContent.data
    $editAction = [string]$editData.next_actions[0].execute.arguments.action_id
    Assert-True ([bool]$editAction) "edit investigation returned no action ticket"
    $proposal = $null
    for ($attempt = 0; $attempt -lt 200; $attempt++) {
        $editStep = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 6; method = "tools/call"; params = @{
            name = "investigation_step"; arguments = @{ action_id = $editAction }
        }} $session
        Assert-True (-not $editStep.Json.result.isError) "edit investigation_step failed"
        $editStepData = $editStep.Json.result.structuredContent.data
        if ($editStepData.proposal) { $proposal = $editStepData.proposal; break }
        Start-Sleep -Milliseconds 25
    }
    Assert-True ($null -ne $proposal) "edit investigation returned no verified proposal"

    $commit = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 7; method = "tools/call"; params = @{
        name = "change_commit"; arguments = @{
            proposal_id = [string]$proposal.proposal_id
            expected_revision = [int64]$proposal.expected_revision
            idempotency_key = "packaged-smoke-0001"
        }
    }} $session
    Assert-True (-not $commit.Json.result.isError) "change_commit failed"

    $close = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 8; method = "tools/call"; params = @{
        name = "target_close"; arguments = @{ target_id = $targetId }
    }} $session
    Assert-True (-not $close.Json.result.isError) "target_close failed"

    & $exe doctor --endpoint $endpoint --open $fixture --data-dir $dataDir | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "windy doctor endpoint probe failed" }
    Write-Host "Packaged $ExpectedProductName smoke test passed ($targetId $functionVa; tools/list=$($tools.Response.Content.Length) bytes; evidence=$stepBytes bytes)."
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
