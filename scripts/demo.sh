#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# OC3 2025 Demo Script
# "Securing AI's New Attack Surface: MCP Servers in TEEs"
#
# Prerequisites:
#   - Azure CLI logged in (az login)
#   - Container group already deployed (scripts/deploy.sh)
#   - jq installed (for pretty-printing JSON)
#
# Usage:  bash scripts/demo.sh
# ─────────────────────────────────────────────────────────────────

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-oc3-demo}"
CONTAINER_NAME="${CONTAINER_NAME:-mcp-tee-server}"
SERVER_URL="${SERVER_URL:-http://mcp-tee-server.eastus.azurecontainer.io:8080}"
MCP_URL="${SERVER_URL}/mcp"

BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
DIM="\033[2m"
RESET="\033[0m"

pause() {
  echo ""
  echo -e "${DIM}  ── press ENTER to continue ──${RESET}"
  read -r
}

banner() {
  echo ""
  echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
  echo -e "${BOLD}${CYAN}  $1${RESET}"
  echo -e "${BOLD}${CYAN}═══════════════════════════════════════════════════════════════${RESET}"
  echo ""
}

step() {
  echo -e "${BOLD}${GREEN}▶ $1${RESET}"
}

info() {
  echo -e "  ${DIM}$1${RESET}"
}

# ─────────────────────────────────────────────────────────────────
banner "OC3 2025: MCP Servers Need Trusted Execution Environments"
echo -e "  This demo shows an MCP server running inside an Azure"
echo -e "  Confidential Container (AMD SEV-SNP) with:"
echo -e ""
echo -e "    • Hardware-enforced memory encryption"
echo -e "    • Remote attestation via Microsoft Azure Attestation"
echo -e "    • Secrets released only inside the verified TEE"
echo -e "    • Envelope encryption — private key never leaves enclave"
echo ""

pause

# ─────────────────────────────────────────────────────────────────
banner "STEP 1: Container Startup Logs — The Attestation Flow"

step "Fetching container logs (shows TEE detection → attestation → key release)..."
echo ""
az container logs -g "$RESOURCE_GROUP" -n "$CONTAINER_NAME" --container-name mcp-server 2>/dev/null | head -30
echo ""
echo -e "${YELLOW}  ↑ Notice the 4-phase startup:${RESET}"
echo -e "    1. TEE Detection    — /dev/sev-guest found ✅"
echo -e "    2. Managed Identity — token acquired from IMDS"
echo -e "    3. Key Release      — SKR sidecar: SNP report → MAA → KV"
echo -e "    4. Secret Decrypt   — RSA-OAEP in-memory, never on disk"

pause

# ─────────────────────────────────────────────────────────────────
banner "STEP 2: SKR Sidecar — The Attestation Sidecar"

step "Checking SKR sidecar status..."
echo ""
az container logs -g "$RESOURCE_GROUP" -n "$CONTAINER_NAME" --container-name skr-sidecar 2>/dev/null | tail -10
echo ""
echo -e "  The SKR sidecar (mcr.microsoft.com/aci/skr:2.9) provides:"
echo -e "    • /key/release   — attestation + key release from Key Vault"
echo -e "    • /attest/maa    — raw MAA token for custom attestation"
echo -e "    • /attest/raw    — raw SNP attestation report"

pause

# ─────────────────────────────────────────────────────────────────
banner "STEP 3: MCP Protocol — Initialize Session"

step "Sending MCP initialize request..."
echo ""
echo -e "  ${DIM}POST ${MCP_URL}${RESET}"
echo -e '  {"jsonrpc":"2.0","id":1,"method":"initialize",...}'
echo ""

INIT_RESPONSE=$(curl -s -D - "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"oc3-demo","version":"1.0"}}}')

SESSION_ID=$(echo "$INIT_RESPONSE" | grep -i "mcp-session-id" | tr -d '\r' | awk '{print $2}')
echo -e "  ${GREEN}Session ID: ${SESSION_ID}${RESET}"
echo ""
echo "$INIT_RESPONSE" | tail -n +$(echo "$INIT_RESPONSE" | grep -n "^$" | tail -1 | cut -d: -f1) | grep "data:" | sed 's/data: //' | python3 -m json.tool 2>/dev/null || echo "$INIT_RESPONSE" | tail -5
echo ""
echo -e "${YELLOW}  ↑ Server reports its tools: github_search_issues, query_database,${RESET}"
echo -e "${YELLOW}    send_notification, attestation_status${RESET}"

pause

# ─────────────────────────────────────────────────────────────────
banner "STEP 4: attestation_status — Proof of TEE + Secrets"

step "Calling attestation_status tool via MCP protocol..."
echo ""

ATTEST_RESPONSE=$(curl -s "$MCP_URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "Mcp-Session-Id: ${SESSION_ID}" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"attestation_status","arguments":{}}}')

echo "$ATTEST_RESPONSE" | grep "data:" | sed 's/data: //' | python3 -m json.tool 2>/dev/null || echo "$ATTEST_RESPONSE"
echo ""
echo -e "${GREEN}  Key takeaways:${RESET}"
echo -e "    • running_in_tee: true       — hardware-enforced, not trust-me software"
echo -e "    • tee_type: AMD SEV-SNP      — memory encrypted by CPU, not hypervisor"
echo -e "    • secrets_source: skr+envelope — released only after attestation verified"
echo -e "    • Secrets loaded: true        — all 3 credentials available to MCP tools"

pause

# ─────────────────────────────────────────────────────────────────
banner "STEP 5: The Threat Model — What Root CAN'T Do"

echo -e "  Even with root access on the host, an attacker ${RED}cannot${RESET}:"
echo ""
echo -e "    ❌  Read container memory (encrypted by AMD SEV-SNP hardware)"
echo -e "    ❌  Intercept secrets at rest (envelope-encrypted, key in TEE only)"
echo -e "    ❌  Forge attestation (SNP report signed by AMD CPU, verified by MAA)"
echo -e "    ❌  Replay a stolen key (release policy binds to exact container hash)"
echo -e "    ❌  Swap the container image (different hash → attestation fails)"
echo ""
echo -e "  What they ${GREEN}can${RESET} see:"
echo ""
echo -e "    ✅  Container is running (but not what's inside)"
echo -e "    ✅  Network traffic metadata (use TLS for payload protection)"
echo -e "    ✅  Resource usage (CPU, memory — side-channel mitigation is ongoing)"

pause

# ─────────────────────────────────────────────────────────────────
banner "STEP 6: Key Vault Release Policy — Cryptographic Binding"

step "Showing the key release policy bound to this container..."
echo ""
az keyvault key show \
  --vault-name "$(az keyvault list -g "$RESOURCE_GROUP" --query "[0].name" -o tsv 2>/dev/null)" \
  --name mcp-envelope-key \
  --query "releasePolicy.encodedPolicy" -o tsv 2>/dev/null | python3 -m json.tool 2>/dev/null || \
  cat infra/key-release-policy.json
echo ""
echo -e "${YELLOW}  ↑ The 'x-ms-sevsnpvm-hostdata' must match the SHA-256 of the${RESET}"
echo -e "${YELLOW}    container's CCE policy. Any image change → different hash → no key.${RESET}"

pause

# ─────────────────────────────────────────────────────────────────
banner "DEMO COMPLETE"

echo -e "  ${GREEN}✅ Confidential MCP server running in AMD SEV-SNP TEE${RESET}"
echo -e "  ${GREEN}✅ Secrets delivered via envelope encryption + attestation${RESET}"
echo -e "  ${GREEN}✅ MCP tools functional with TEE-protected credentials${RESET}"
echo ""
echo -e "  Repository: https://github.com/pkhandavilli/mcp-tee-sample"
echo -e "  (Reference only — not an official Microsoft product)"
echo ""
echo -e "${BOLD}  Thank you! Questions?${RESET}"
echo ""
