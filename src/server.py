"""
MCP Server — Confidential Container Reference Implementation

A realistic multi-tool MCP server designed to run inside an Azure
Confidential Container on ACI (AMD SEV-SNP). Demonstrates the credential
aggregation problem and how TEE + attestation solves it.

Tools:
  1. github_search_issues  — Search GitHub issues (needs GITHUB_TOKEN)
  2. query_database         — Run read-only SQL queries (needs DB_CONNECTION_STRING)
  3. send_notification      — Post to a webhook/Slack (needs WEBHOOK_URL)

All secrets are fetched at startup via Azure Key Vault Premium (SKR) with a
Secure Key Release policy bound to this container's attestation measurement.
Secrets never leave the enclave, are never written to disk, and are
never visible to the host OS — even with root access.
"""

import os
import json
import logging
import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

# ── Logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mcp-tee-server")

# ── Secret Loading ──────────────────────────────────────────────
# In production, secrets are fetched from Azure Key Vault via the SKR
# (Secure Key Release) sidecar. The sidecar performs hardware attestation
# (AMD SEV-SNP → MAA token) and releases keys only when the key-release
# policy is satisfied.
#
# For local development, set env vars directly (never commit them).

SKR_ENDPOINT = os.environ.get("SKR_ENDPOINT", "http://localhost:9000")
MAA_ENDPOINT = os.environ.get("MAA_ENDPOINT", "sharedeus.eus.attest.azure.net")
AKV_ENDPOINT = os.environ.get("AKV_ENDPOINT", "")

# Secret names as they appear in Key Vault (key IDs for SKR)
_SECRET_KEY_MAP = {
    "GITHUB_TOKEN": "github-token",
    "DB_CONNECTION_STRING": "db-connection-string",
    "WEBHOOK_URL": "webhook-url",
}

GITHUB_TOKEN = ""
DB_CONNECTION_STRING = ""
WEBHOOK_URL = ""
_secrets_source: dict[str, str] = {}  # Tracks where each secret came from


async def _fetch_secret_from_skr(kid: str) -> str | None:
    """Fetch a secret from the SKR sidecar via hardware attestation.

    The sidecar obtains an attestation report from /dev/sev-guest, sends it
    to MAA, and uses the resulting token to release the key from AKV.
    """
    if not AKV_ENDPOINT:
        return None
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                f"{SKR_ENDPOINT}/key/release",
                json={
                    "maa_endpoint": MAA_ENDPOINT,
                    "akv_endpoint": AKV_ENDPOINT,
                    "kid": kid,
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("key", "")
    except Exception as e:
        logger.warning("SKR fetch failed for %s: %s", kid, e)
        return None


async def _load_secrets() -> None:
    """Load secrets from SKR sidecar, falling back to environment variables."""
    global GITHUB_TOKEN, DB_CONNECTION_STRING, WEBHOOK_URL

    secrets = {}
    for env_name, kid in _SECRET_KEY_MAP.items():
        # Try SKR sidecar first (production path)
        value = await _fetch_secret_from_skr(kid)
        if value:
            secrets[env_name] = value
            _secrets_source[env_name] = "skr"
            logger.info("Loaded %s via SKR sidecar", env_name)
        else:
            # Fall back to environment variable (local dev path)
            value = os.environ.get(env_name, "")
            secrets[env_name] = value
            _secrets_source[env_name] = "env" if value else "none"
            if value:
                logger.info("Loaded %s from environment variable", env_name)

    GITHUB_TOKEN = secrets.get("GITHUB_TOKEN", "")
    DB_CONNECTION_STRING = secrets.get("DB_CONNECTION_STRING", "")
    WEBHOOK_URL = secrets.get("WEBHOOK_URL", "")


def _check_secrets() -> dict[str, bool]:
    """Report which secrets are loaded (not their values)."""
    return {
        "GITHUB_TOKEN": bool(GITHUB_TOKEN),
        "DB_CONNECTION_STRING": bool(DB_CONNECTION_STRING),
        "WEBHOOK_URL": bool(WEBHOOK_URL),
    }


# ── MCP Server ──────────────────────────────────────────────────
# Allow connections from any host (the server runs behind ACI's public IP/FQDN)
_allowed_hosts = os.environ.get("MCP_ALLOWED_HOSTS", "*").split(",")
_transport_security = TransportSecuritySettings(
    enable_dns_rebinding_protection=(_allowed_hosts != ["*"]),
    allowed_hosts=_allowed_hosts if _allowed_hosts != ["*"] else [],
)

mcp = FastMCP(
    "mcp-tee-server",
    instructions=(
        "A reference MCP server running inside an Azure Confidential "
        "Container (ACI, AMD SEV-SNP). Demonstrates TEE-protected "
        "credential management with remote attestation."
    ),
    transport_security=_transport_security,
)


# ── Tool 1: GitHub Issue Search ─────────────────────────────────
@mcp.tool()
async def github_search_issues(
    query: str,
    repo: str = "",
    max_results: int = 10,
) -> dict[str, Any]:
    """
    Search GitHub issues. Optionally scope to a specific repo.

    Args:
        query: Search keywords (e.g., 'bug label:critical')
        repo: Optional owner/repo filter (e.g., 'opencontainers/runc')
        max_results: Max issues to return (1-50, default 10)

    Returns:
        Matching issues with title, number, state, and URL.
    """
    if not GITHUB_TOKEN:
        return {"error": "GITHUB_TOKEN not available — attestation may have failed"}

    max_results = min(max(1, max_results), 50)
    q = f"{query} repo:{repo}" if repo else query

    async with httpx.AsyncClient(timeout=15) as client:
        try:
            resp = await client.get(
                "https://api.github.com/search/issues",
                params={"q": q, "per_page": max_results, "sort": "updated"},
                headers={
                    "Authorization": f"Bearer {GITHUB_TOKEN}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPStatusError as e:
            logger.error("GitHub API request failed: %s", e)
            return {"error": f"GitHub API error: HTTP {e.response.status_code}"}
        except httpx.RequestError as e:
            logger.error("GitHub API request error: %s", e)
            return {"error": f"GitHub API request failed: {type(e).__name__}: {e}"}

    issues = [
        {
            "number": item["number"],
            "title": item["title"],
            "state": item["state"],
            "url": item["html_url"],
            "updated_at": item["updated_at"],
            "labels": [l["name"] for l in item.get("labels", [])],
        }
        for item in data.get("items", [])[:max_results]
    ]

    logger.info("github_search_issues: query=%r, results=%d", q, len(issues))
    return {
        "total_count": data.get("total_count", 0),
        "returned": len(issues),
        "issues": issues,
    }


# ── Tool 2: Database Query (read-only) ─────────────────────────
@mcp.tool()
async def query_database(
    sql: str,
    max_rows: int = 100,
) -> dict[str, Any]:
    """
    Execute a READ-ONLY SQL query against the configured PostgreSQL database.

    Args:
        sql: The SQL query to execute (SELECT only — writes are rejected)
        max_rows: Maximum rows to return (1-1000, default 100)

    Returns:
        Query results as a list of row dictionaries.
    """
    if not DB_CONNECTION_STRING:
        return {"error": "DB_CONNECTION_STRING not available — attestation may have failed"}

    # Safety: reject anything that isn't a SELECT
    sql_upper = sql.strip().upper()
    if not sql_upper.startswith("SELECT"):
        return {"error": "Only SELECT queries are permitted (read-only mode)"}

    forbidden = ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "CREATE", "TRUNCATE", "EXEC"]
    for keyword in forbidden:
        if keyword in sql_upper:
            return {"error": f"Query contains forbidden keyword: {keyword}"}

    # Reject multi-statement queries (semicolons followed by more SQL)
    stripped = sql.strip().rstrip(";")
    if ";" in stripped:
        return {"error": "Multi-statement queries are not permitted"}

    max_rows = min(max(1, max_rows), 1000)

    try:
        import asyncpg

        conn = await asyncpg.connect(DB_CONNECTION_STRING, timeout=10)
        try:
            # Use a read-only transaction to enforce SELECT-only at the database level
            async with conn.transaction(readonly=True):
                rows = await conn.fetch(sql)
            result = [dict(row) for row in rows[:max_rows]]
            logger.info("query_database: sql=%r, rows=%d", sql[:80], len(result))
            return {
                "row_count": len(result),
                "truncated": len(rows) > max_rows,
                "rows": result,
            }
        finally:
            await conn.close()
    except ImportError:
        return {"error": "asyncpg not installed — database queries require the asyncpg package"}
    except Exception as e:
        logger.error("query_database failed: %s", e)
        return {"error": f"Query failed: {type(e).__name__}: {e}"}


# ── Tool 3: Send Notification ──────────────────────────────────
@mcp.tool()
async def send_notification(
    message: str,
    channel: str = "general",
    urgency: str = "normal",
) -> dict[str, Any]:
    """
    Send a notification via the configured webhook (Slack-compatible).

    This is a WRITE action and should require explicit user confirmation
    in any agent workflow (per the MCP capability model).

    Args:
        message: The notification text to send
        channel: Target channel name (default: general)
        urgency: Priority level: 'low', 'normal', or 'high'

    Returns:
        Delivery status and timestamp.
    """
    if not WEBHOOK_URL:
        return {"error": "WEBHOOK_URL not available — attestation may have failed"}

    if urgency not in ("low", "normal", "high"):
        return {"error": "urgency must be 'low', 'normal', or 'high'"}

    payload = {
        "channel": f"#{channel}",
        "text": f"[{urgency.upper()}] {message}",
        "username": "mcp-tee-server",
        "icon_emoji": ":lock:" if urgency == "high" else ":robot_face:",
    }

    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(WEBHOOK_URL, json=payload)
            resp.raise_for_status()
        except httpx.HTTPStatusError as e:
            logger.error("Webhook request failed: %s", e)
            return {"error": f"Webhook error: HTTP {e.response.status_code}"}
        except httpx.RequestError as e:
            logger.error("Webhook request error: %s", e)
            return {"error": f"Webhook request failed: {type(e).__name__}: {e}"}

    logger.info(
        "send_notification: channel=%s, urgency=%s, length=%d",
        channel, urgency, len(message),
    )
    return {
        "status": "delivered",
        "channel": channel,
        "urgency": urgency,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Health / Attestation Status ─────────────────────────────────
@mcp.tool()
async def attestation_status() -> dict[str, Any]:
    """
    Report the server's attestation and secret-loading status.

    Returns which secrets were successfully loaded (not their values)
    and whether the server is running inside a hardware TEE.
    """
    tee_evidence = os.path.exists("/sys/kernel/security/tee")
    snp_evidence = os.path.exists("/dev/sev-guest") or os.path.exists("/dev/sev")

    return {
        "server": "mcp-tee-server",
        "version": "1.0.0",
        "running_in_tee": tee_evidence or snp_evidence,
        "tee_type": "AMD SEV-SNP" if snp_evidence else ("TEE detected" if tee_evidence else "none detected"),
        "secrets_loaded": _check_secrets(),
        "secrets_source": _secrets_source,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── Entry Point ─────────────────────────────────────────────────
if __name__ == "__main__":
    logger.info("Starting MCP TEE Server")
    logger.info(
        "TEE environment: /dev/sev-guest=%s",
        os.path.exists("/dev/sev-guest"),
    )

    # Load secrets from SKR sidecar (or env vars for local dev)
    asyncio.run(_load_secrets())

    secrets = _check_secrets()
    logger.info("Secrets loaded: %s", json.dumps(secrets))
    logger.info("Secrets source: %s", json.dumps(_secrets_source))

    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")
    if transport not in {"stdio", "streamable-http"}:
        logger.warning("Unknown MCP_TRANSPORT=%r, falling back to streamable-http", transport)
        transport = "streamable-http"
    logger.info("Transport: %s", transport)
    if transport == "stdio":
        mcp.run(transport="stdio")
    else:
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = 8080
        mcp.run(transport="streamable-http")
