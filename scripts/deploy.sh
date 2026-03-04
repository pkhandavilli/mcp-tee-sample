#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# deploy.sh — Build, generate policy, and deploy the MCP TEE server
#
# Prerequisites:
#   - Azure CLI (az) with confcom extension installed
#   - Docker (for building the image)
#   - An Azure Container Registry (ACR)
#   - A resource group for the deployment
#
# Usage:
#   ./scripts/deploy.sh \
#     --acr-name <your-acr> \
#     --resource-group <your-rg> \
#     --image-tag latest
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Pre-flight: Ensure Azure CLI is authenticated ────────────────
if ! az account show &>/dev/null; then
  echo "ERROR: Not logged into Azure CLI. Run 'az login' first."
  exit 1
fi

# ── Parse Arguments ──────────────────────────────────────────────
ACR_NAME=""
RESOURCE_GROUP=""
IMAGE_TAG="latest"

while [[ $# -gt 0 ]]; do
  case $1 in
    --acr-name)       ACR_NAME="$2";       shift 2 ;;
    --resource-group) RESOURCE_GROUP="$2";  shift 2 ;;
    --image-tag)      IMAGE_TAG="$2";       shift 2 ;;
    *) echo "Unknown argument: $1"; exit 1 ;;
  esac
done

if [[ -z "$ACR_NAME" || -z "$RESOURCE_GROUP" ]]; then
  echo "Usage: $0 --acr-name <acr> --resource-group <rg> [--image-tag <tag>]"
  exit 1
fi

IMAGE="${ACR_NAME}.azurecr.io/mcp-tee-server:${IMAGE_TAG}"

echo "═══════════════════════════════════════════════════════════"
echo "  MCP TEE Server — Confidential Container Deployment"
echo "═══════════════════════════════════════════════════════════"
echo "  ACR:            ${ACR_NAME}"
echo "  Resource Group: ${RESOURCE_GROUP}"
echo "  Image:          ${IMAGE}"
echo "═══════════════════════════════════════════════════════════"

# ── Step 1: Build and Push the Container Image ──────────────────
echo ""
echo "▶ Step 1: Building container image..."
docker build -t "mcp-tee-server:${IMAGE_TAG}" .

echo "▶ Step 1: Pushing to ACR..."
az acr login --name "${ACR_NAME}"
docker tag "mcp-tee-server:${IMAGE_TAG}" "${IMAGE}"
docker push "${IMAGE}"
echo "✓ Image pushed: ${IMAGE}"

# ── Step 2: Generate CCE Security Policy ────────────────────────
echo ""
echo "▶ Step 2: Generating CCE security policy..."
echo "  (This computes the expected container image measurement)"

# Install confcom extension if not present
az extension add --name confcom 2>/dev/null || true

# Generate the CCE policy from the container image
CCE_POLICY=$(az confcom acipolicy gen \
  --image "${IMAGE}" \
  --print-policy 2>/dev/null)

echo "✓ CCE policy generated (${#CCE_POLICY} chars, base64-encoded)"

# Compute the policy hash for the key-release policy
POLICY_HASH=$(echo -n "${CCE_POLICY}" | base64 -d | sha256sum | cut -d' ' -f1)
echo "✓ Policy hash: ${POLICY_HASH}"
echo ""
# Automatically update key-release-policy.json with the computed hash
POLICY_FILE="infra/key-release-policy.json"
if [[ -f "${POLICY_FILE}" ]]; then
  sed -i "s/<REPLACE_WITH_CCE_POLICY_HASH>/${POLICY_HASH}/g" "${POLICY_FILE}"
  echo "✓ Updated ${POLICY_FILE} with policy hash: ${POLICY_HASH}"
else
  echo "⚠ ${POLICY_FILE} not found — update it manually with hash: ${POLICY_HASH}"
fi
echo ""

# ── Step 3: Deploy Infrastructure ───────────────────────────────
echo "▶ Step 3: Deploying Bicep template..."
az deployment group create \
  --resource-group "${RESOURCE_GROUP}" \
  --template-file infra/main.bicep \
  --parameters \
    acrName="${ACR_NAME}" \
    imageTag="${IMAGE_TAG}" \
    ccePolicy="${CCE_POLICY}" \
  --output table

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ✓ Deployment complete"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Next steps:"
echo "  1. Import secrets as exportable keys with release policy:"
echo "     # Encode your secret as base64:"
echo "     TOKEN_B64=\$(echo -n '<your-github-pat>' | base64)"
echo ""
echo "     # Import each key with the release policy:"
echo "     az keyvault key import --vault-name <kv-name> --name github-token \\"
echo "       --kty oct-HSM --ops export --exportable true \\"
echo "       --policy infra/key-release-policy.json --value \$TOKEN_B64"
echo ""
echo "     az keyvault key import --vault-name <kv-name> --name db-connection-string \\"
echo "       --kty oct-HSM --ops export --exportable true \\"
echo "       --policy infra/key-release-policy.json --value <base64-connstr>"
echo ""
echo "     az keyvault key import --vault-name <kv-name> --name webhook-url \\"
echo "       --kty oct-HSM --ops export --exportable true \\"
echo "       --policy infra/key-release-policy.json --value <base64-url>"
echo ""
echo "  2. Verify attestation and secret retrieval:"
echo "     az container logs --resource-group ${RESOURCE_GROUP} --name mcp-tee-server"
echo ""
