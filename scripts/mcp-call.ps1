<#
.SYNOPSIS
One-shot Windy MCP tool call. Stateless: initializes, calls the tool, exits.

.DESCRIPTION
Lets an external agent drive Windy's MCP surface without implementing the
JSON-RPC handshake. Each invocation is one logical tool call, which is also the
unit agent-bench counts.

.EXAMPLE
./scripts/mcp-call.ps1 -Endpoint http://127.0.0.1:8765/mcp -Tool windy_status
./scripts/mcp-call.ps1 -Endpoint http://127.0.0.1:8765/mcp -Tool investigation_start -Arguments '{"path":"C:\\x.exe","intent":"locate","question":"locate the main parser","budget":"tiny"}'
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Endpoint,
    [Parameter(Mandatory = $true)][string]$Tool,
    [string]$Arguments = "{}"
)

$ErrorActionPreference = "Stop"

function Convert-McpContent([string]$Content) {
    if (-not $Content) { return $null }
    # Streamable HTTP may answer as SSE; take the last data: line.
    if ($Content -match "(?m)^data:") {
        $line = ($Content -split "`n" | Where-Object { $_ -match "^data:" } | Select-Object -Last 1)
        $Content = $line -replace "^data:\s*", ""
    }
    return $Content | ConvertFrom-Json
}

function Invoke-Rpc([object]$Body, [string]$Session) {
    $headers = @{
        Accept                 = "application/json, text/event-stream"
        "MCP-Protocol-Version" = "2025-11-25"
    }
    if ($Session) { $headers["Mcp-Session-Id"] = $Session }
    return Invoke-WebRequest -UseBasicParsing -Method Post -Uri $Endpoint `
        -Headers $headers -ContentType "application/json" `
        -Body ($Body | ConvertTo-Json -Depth 100 -Compress)
}

$init = Invoke-Rpc @{
    jsonrpc = "2.0"; id = 1; method = "initialize"
    params  = @{
        protocolVersion = "2025-11-25"
        capabilities    = @{}
        clientInfo      = @{ name = "mcp-call"; version = "1" }
    }
} ""
$session = [string]$init.Headers["Mcp-Session-Id"]
if (-not $session) { throw "server returned no Mcp-Session-Id" }

Invoke-Rpc @{ jsonrpc = "2.0"; method = "notifications/initialized" } $session | Out-Null

try { $argObj = $Arguments | ConvertFrom-Json } catch { throw "-Arguments is not valid JSON: $Arguments" }

$resp = Invoke-Rpc @{
    jsonrpc = "2.0"; id = 2; method = "tools/call"
    params  = @{ name = $Tool; arguments = $argObj }
} $session

$json = Convert-McpContent $resp.Content
if ($json.error) { throw "MCP error: $($json.error | ConvertTo-Json -Depth 20 -Compress)" }

# Prefer structuredContent; fall back to the text block.
$result = $json.result
if ($null -ne $result.structuredContent) {
    $result.structuredContent | ConvertTo-Json -Depth 60
}
elseif ($result.content) {
    ($result.content | Where-Object { $_.type -eq "text" } | Select-Object -First 1).text
}
else {
    $result | ConvertTo-Json -Depth 60
}
