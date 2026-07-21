[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [string]$FixturePath = ""
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
    & $exe --data-dir $dataDir doctor --open $fixture | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "windy doctor failed" }

    $argumentList = @(
        "--data-dir", ('"' + $dataDir + '"'),
        "serve-mcp", "--bind", "127.0.0.1:$port",
        "--open", ('"' + $fixture + '"')
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
            if ($status.name -eq "windy" -and $status.status -eq "ok") {
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
                name = "windy-release-smoke"; version = "0.1.1"
            }
        }
    }
    Assert-True ($initialize.Json.result.serverInfo.name -eq "windy") "Unexpected MCP identity"
    $session = [string]$initialize.Response.Headers["Mcp-Session-Id"]
    Assert-True ([bool]$session) "MCP session header missing"
    Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; method = "notifications/initialized" } $session -AllowEmpty | Out-Null

    $tools = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 2; method = "tools/list"; params = @{} } $session
    Assert-True ($tools.Json.result.tools.Count -ge 60) "MCP tools/list returned an incomplete surface"

    $open = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 3; method = "tools/call"; params = @{
        name = "open_project"; arguments = @{ path = $fixture }
    }} $session
    $projectId = [string]$open.Json.result.structuredContent.project_id
    Assert-True ([bool]$projectId) "open_project returned no project_id"

    $functions = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 4; method = "tools/call"; params = @{
        name = "list_functions"; arguments = @{ project_id = $projectId; limit = 16 }
    }} $session
    $va = [string]$functions.Json.result.structuredContent.functions[0].va
    Assert-True ([bool]$va) "list_functions returned no function"

    $evidence = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 5; method = "tools/call"; params = @{
        name = "get_function_evidence"; arguments = @{ project_id = $projectId; va = $va }
    }} $session
    Assert-True (-not $evidence.Json.result.isError) "get_function_evidence failed"
    Assert-True ([bool]$evidence.Json.result.structuredContent) "evidence structuredContent missing"

    $decompile = Invoke-Mcp $endpoint @{ jsonrpc = "2.0"; id = 6; method = "tools/call"; params = @{
        name = "decompile_function"; arguments = @{ project_id = $projectId; va = $va; policy = "product" }
    }} $session
    Assert-True (-not $decompile.Json.result.isError) "native decompilation failed"
    Assert-True (@("ok", "omitted") -contains [string]$decompile.Json.result.structuredContent.status) "Unexpected decompile status"

    & $exe doctor --endpoint $endpoint --data-dir $dataDir | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "windy doctor endpoint probe failed" }
    Write-Host "Packaged Windy smoke test passed ($projectId $va)."
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
