# ─────────────────────────────────────────────────────────────────
# OC3 2025 Demo Script (PowerShell)
# "Securing AI's New Attack Surface: MCP Servers in TEEs"
#
# Usage:  .\scripts\demo.ps1
# ─────────────────────────────────────────────────────────────────

$ErrorActionPreference = "Continue"

$ResourceGroup = if ($env:RESOURCE_GROUP) { $env:RESOURCE_GROUP } else { "oc3-demo" }
$ContainerName = if ($env:CONTAINER_NAME) { $env:CONTAINER_NAME } else { "mcp-tee-server" }
$ServerUrl     = if ($env:SERVER_URL) { $env:SERVER_URL } else { "http://mcp-tee-server.eastus.azurecontainer.io:8080" }
$McpUrl        = "$ServerUrl/mcp"

function Banner($text) {
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  $text" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
}

function Step($text) {
    Write-Host "▶ $text" -ForegroundColor Green
}

function Pause-Demo {
    Write-Host ""
    Write-Host "  ── press ENTER to continue ──" -ForegroundColor DarkGray
    Read-Host | Out-Null
}

# ─────────────────────────────────────────────────────────────────
Banner "OC3 2025: MCP Servers Need Trusted Execution Environments"
Write-Host "  This demo shows an MCP server running inside an Azure"
Write-Host "  Confidential Container (AMD SEV-SNP) with:"
Write-Host ""
Write-Host "    • Hardware-enforced memory encryption"
Write-Host "    • Remote attestation via Microsoft Azure Attestation"
Write-Host "    • Secrets released only inside the verified TEE"
Write-Host "    • Envelope encryption — private key never leaves enclave"
Write-Host ""

Pause-Demo

# ─────────────────────────────────────────────────────────────────
Banner "STEP 1: Container Startup Logs — The Attestation Flow"

Step "Fetching container logs (shows TEE detection → attestation → key release)..."
Write-Host ""
$logs = az container logs -g $ResourceGroup -n $ContainerName --container-name mcp-server 2>$null
($logs -split "`n") | Select-Object -First 30 | ForEach-Object { Write-Host "  $_" }
Write-Host ""
Write-Host "  ↑ Notice the 4-phase startup:" -ForegroundColor Yellow
Write-Host "    1. TEE Detection    — /dev/sev-guest found ✅"
Write-Host "    2. Managed Identity — token acquired from IMDS"
Write-Host "    3. Key Release      — SKR sidecar: SNP report → MAA → KV"
Write-Host "    4. Secret Decrypt   — RSA-OAEP in-memory, never on disk"

Pause-Demo

# ─────────────────────────────────────────────────────────────────
Banner "STEP 2: SKR Sidecar — The Attestation Sidecar"

Step "Checking SKR sidecar status..."
Write-Host ""
$skrLogs = az container logs -g $ResourceGroup -n $ContainerName --container-name skr-sidecar 2>$null
($skrLogs -split "`n") | Select-Object -Last 10 | ForEach-Object { Write-Host "  $_" }
Write-Host ""
Write-Host "  The SKR sidecar (mcr.microsoft.com/aci/skr:2.9) provides:"
Write-Host "    • /key/release   — attestation + key release from Key Vault"
Write-Host "    • /attest/maa    — raw MAA token for custom attestation"
Write-Host "    • /attest/raw    — raw SNP attestation report"

Pause-Demo

# ─────────────────────────────────────────────────────────────────
Banner "STEP 3: MCP Protocol — Initialize Session"

Step "Sending MCP initialize request..."
Write-Host ""
Write-Host "  POST $McpUrl" -ForegroundColor DarkGray
Write-Host '  {"jsonrpc":"2.0","id":1,"method":"initialize",...}' -ForegroundColor DarkGray
Write-Host ""

$headers = @{
    "Content-Type" = "application/json"
    "Accept"       = "application/json, text/event-stream"
}
$initBody = @{
    jsonrpc = "2.0"
    id      = 1
    method  = "initialize"
    params  = @{
        protocolVersion = "2024-11-05"
        capabilities    = @{}
        clientInfo      = @{ name = "oc3-demo"; version = "1.0" }
    }
} | ConvertTo-Json -Depth 5

$resp = Invoke-WebRequest -Uri $McpUrl -Method POST -Headers $headers -Body $initBody -UseBasicParsing
$sessionId = $resp.Headers["Mcp-Session-Id"]
Write-Host "  Session ID: $sessionId" -ForegroundColor Green
Write-Host ""

# Parse SSE data line
$dataLine = ($resp.Content -split "`n" | Where-Object { $_ -match "^data:" }) -replace "^data: ", ""
try {
    $parsed = $dataLine | ConvertFrom-Json
    Write-Host "  Protocol : $($parsed.result.protocolVersion)"
    Write-Host "  Server   : $($parsed.result.serverInfo.name)"
    $toolNames = ($parsed.result.capabilities.tools | ConvertTo-Json -Compress)
    Write-Host "  Tools    : enabled"
} catch {
    Write-Host "  $dataLine"
}
Write-Host ""
Write-Host "  ↑ Server reports tools: github_search_issues, query_database," -ForegroundColor Yellow
Write-Host "    send_notification, attestation_status" -ForegroundColor Yellow

Pause-Demo

# ─────────────────────────────────────────────────────────────────
Banner "STEP 4: attestation_status — Proof of TEE + Secrets"

Step "Calling attestation_status tool via MCP protocol..."
Write-Host ""

$attestBody = @{
    jsonrpc = "2.0"
    id      = 2
    method  = "tools/call"
    params  = @{
        name      = "attestation_status"
        arguments = @{}
    }
} | ConvertTo-Json -Depth 5

$headers["Mcp-Session-Id"] = $sessionId
$resp2 = Invoke-WebRequest -Uri $McpUrl -Method POST -Headers $headers -Body $attestBody -UseBasicParsing
$dataLine2 = ($resp2.Content -split "`n" | Where-Object { $_ -match "^data:" }) -replace "^data: ", ""

try {
    $result = ($dataLine2 | ConvertFrom-Json).result.structuredContent
    Write-Host "  ┌─────────────────────────────────────────────┐"
    Write-Host "  │  running_in_tee : $($result.running_in_tee)                  │" -ForegroundColor Green
    Write-Host "  │  tee_type       : $($result.tee_type)             │" -ForegroundColor Green
    Write-Host "  │                                             │"
    foreach ($key in @("GITHUB_TOKEN", "DB_CONNECTION_STRING", "WEBHOOK_URL")) {
        $loaded = $result.secrets_loaded.$key
        $source = $result.secrets_source.$key
        $icon = if ($loaded) { "🔓" } else { "🔒" }
        $status = if ($loaded) { "LOADED" } else { "NOT LOADED" }
        $padded = "$icon $key".PadRight(35)
        Write-Host "  │  $padded $status │" -ForegroundColor $(if ($loaded) { "Green" } else { "Red" })
        Write-Host "  │    source: $source" -ForegroundColor DarkGray
    }
    Write-Host "  │                                             │"
    Write-Host "  │  timestamp: $($result.timestamp)  │" -ForegroundColor DarkGray
    Write-Host "  └─────────────────────────────────────────────┘"
} catch {
    Write-Host "  $dataLine2"
}

Write-Host ""
Write-Host "  Key takeaways:" -ForegroundColor Green
Write-Host "    • running_in_tee: true       — hardware-enforced, not trust-me software"
Write-Host "    • tee_type: AMD SEV-SNP      — memory encrypted by CPU, not hypervisor"
Write-Host "    • secrets_source: skr+envelope — released only after attestation verified"
Write-Host "    • Secrets loaded: true        — all 3 credentials available to MCP tools"

Pause-Demo

# ─────────────────────────────────────────────────────────────────
Banner "STEP 5: The Threat Model — What Root CAN'T Do"

Write-Host "  Even with root access on the host, an attacker " -NoNewline
Write-Host "cannot:" -ForegroundColor Red
Write-Host ""
Write-Host "    ❌  Read container memory (encrypted by AMD SEV-SNP hardware)"
Write-Host "    ❌  Intercept secrets at rest (envelope-encrypted, key in TEE only)"
Write-Host "    ❌  Forge attestation (SNP report signed by AMD CPU, verified by MAA)"
Write-Host "    ❌  Replay a stolen key (release policy binds to exact container hash)"
Write-Host "    ❌  Swap the container image (different hash → attestation fails)"
Write-Host ""
Write-Host "  What they " -NoNewline
Write-Host "can" -ForegroundColor Green -NoNewline
Write-Host " see:"
Write-Host ""
Write-Host "    ✅  Container is running (but not what's inside)"
Write-Host "    ✅  Network traffic metadata (use TLS for payload protection)"
Write-Host "    ✅  Resource usage (CPU, memory — side-channel mitigation is ongoing)"

Pause-Demo

# ─────────────────────────────────────────────────────────────────
Banner "STEP 6: Key Vault Release Policy — Cryptographic Binding"

Step "Showing the key release policy bound to this container..."
Write-Host ""

$kvName = az keyvault list -g $ResourceGroup --query "[0].name" -o tsv 2>$null
if ($kvName) {
    $policy = az keyvault key show --vault-name $kvName --name mcp-envelope-key --query "releasePolicy.encodedPolicy" -o tsv 2>$null
    if ($policy) {
        $policy | ConvertFrom-Json | ConvertTo-Json -Depth 5 | Write-Host
    }
} else {
    Get-Content "infra\key-release-policy.json" | Write-Host
}

Write-Host ""
Write-Host "  ↑ The 'x-ms-sevsnpvm-hostdata' must match the SHA-256 of the" -ForegroundColor Yellow
Write-Host "    container's CCE policy. Any image change → different hash → no key." -ForegroundColor Yellow

Pause-Demo

# ─────────────────────────────────────────────────────────────────
Banner "DEMO COMPLETE"

Write-Host "  ✅ Confidential MCP server running in AMD SEV-SNP TEE" -ForegroundColor Green
Write-Host "  ✅ Secrets delivered via envelope encryption + attestation" -ForegroundColor Green
Write-Host "  ✅ MCP tools functional with TEE-protected credentials" -ForegroundColor Green
Write-Host ""
Write-Host "  Repository: https://github.com/pkhandavilli/mcp-tee-sample"
Write-Host "  (Reference only — not an official Microsoft product)" -ForegroundColor DarkGray
Write-Host ""
Write-Host "  Thank you! Questions?" -ForegroundColor Cyan
Write-Host ""
