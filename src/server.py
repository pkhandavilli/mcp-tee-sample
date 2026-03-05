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
import base64
import logging
import asyncio
from datetime import datetime, timezone
from typing import Any

import httpx
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from cryptography.hazmat.backends import default_backend

# ── Logging ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("mcp-tee-server")

# ── Secret Loading (Envelope Encryption via SKR) ────────────────
# In production, a single RSA-HSM key (the "envelope key") is created in
# Azure Key Vault Premium with a Secure Key Release (SKR) policy.
# Secrets are RSA-OAEP encrypted with the public key at provisioning
# time and passed to the container as ENC_* environment variables.
#
# At runtime the SKR sidecar performs hardware attestation (AMD SEV-SNP
# → MAA token) and releases the RSA private key. The server then
# decrypts the ENC_* env vars in memory — secrets never touch disk.
#
# For local development, set plain env vars directly (never commit them).

SKR_ENDPOINT = os.environ.get("SKR_ENDPOINT", "http://localhost:9000")
MAA_ENDPOINT = os.environ.get("MAA_ENDPOINT", "sharedeus.eus.attest.azure.net")
AKV_ENDPOINT = os.environ.get("AKV_ENDPOINT", "")
ENVELOPE_KEY_NAME = os.environ.get("ENVELOPE_KEY_NAME", "mcp-envelope-key")

# Map: secret name → encrypted env var holding the RSA-OAEP ciphertext
_ENCRYPTED_ENV_MAP = {
    "GITHUB_TOKEN": "ENC_GITHUB_TOKEN",
    "DB_CONNECTION_STRING": "ENC_DB_CONNECTION_STRING",
    "WEBHOOK_URL": "ENC_WEBHOOK_URL",
}

GITHUB_TOKEN = ""
DB_CONNECTION_STRING = ""
WEBHOOK_URL = ""
_secrets_source: dict[str, str] = {}  # Tracks where each secret came from


def _base64url_decode(data: str) -> bytes:
    """Decode a base64url string (used in JWK format)."""
    rem = len(data) % 4
    if rem:
        data += "=" * (4 - rem)
    return base64.urlsafe_b64decode(data)


def _jwk_to_private_key(jwk: dict):
    """Convert a JWK RSA private key dict to a cryptography RSAPrivateKey."""
    pub = RSAPublicNumbers(
        e=int.from_bytes(_base64url_decode(jwk["e"]), "big"),
        n=int.from_bytes(_base64url_decode(jwk["n"]), "big"),
    )
    priv = RSAPrivateNumbers(
        p=int.from_bytes(_base64url_decode(jwk["p"]), "big"),
        q=int.from_bytes(_base64url_decode(jwk["q"]), "big"),
        d=int.from_bytes(_base64url_decode(jwk["d"]), "big"),
        dmp1=int.from_bytes(_base64url_decode(jwk["dp"]), "big"),
        dmq1=int.from_bytes(_base64url_decode(jwk["dq"]), "big"),
        iqmp=int.from_bytes(_base64url_decode(jwk["qi"]), "big"),
        public_numbers=pub,
    )
    return priv.private_key(default_backend())


def _decrypt_secret(private_key, ciphertext_b64: str) -> str:
    """RSA-OAEP decrypt a base64-encoded ciphertext and return the plaintext string."""
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")


async def _fetch_envelope_key() -> dict | None:
    """Fetch the RSA envelope private key from the SKR sidecar.

    The sidecar obtains an attestation report from /dev/sev-guest, sends it
    to MAA, and uses the resulting token to release the key from AKV.
    Returns the JWK dict on success, None on failure.
    """
    if not AKV_ENDPOINT:
        return None

    # Acquire an access token for Key Vault via managed identity (IMDS).
    # User-assigned identities require the client_id parameter.
    access_token = None
    identity_client_id = os.environ.get("IDENTITY_CLIENT_ID", "")
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            params = {
                "api-version": "2018-02-01",
                "resource": "https://vault.azure.net",
            }
            if identity_client_id:
                params["client_id"] = identity_client_id
            resp = await client.get(
                "http://169.254.169.254/metadata/identity/oauth2/token",
                params=params,
                headers={"Metadata": "true"},
            )
            resp.raise_for_status()
            access_token = resp.json().get("access_token")
            logger.info("  ✅ Acquired managed identity token for Key Vault (token length: %d)", len(access_token or ""))
    except Exception as e:
        logger.warning("  ❌ Failed to acquire managed identity token: %s", e)

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            akv_host = AKV_ENDPOINT.rstrip("/").replace("https://", "").replace("http://", "")
            payload = {
                "maa_endpoint": MAA_ENDPOINT,
                "akv_endpoint": akv_host,
                "kid": ENVELOPE_KEY_NAME,
            }
            if access_token:
                payload["access_token"] = access_token
            logger.info("  → Calling SKR: POST %s/key/release", SKR_ENDPOINT)
            logger.info("    MAA authority : %s", MAA_ENDPOINT)
            logger.info("    Key Vault     : %s", akv_host)
            logger.info("    Key name      : %s", ENVELOPE_KEY_NAME)
            logger.info("    Flow: /dev/sev-guest → SNP report → MAA attestation → KV key release")
            resp = await client.post(
                f"{SKR_ENDPOINT}/key/release",
                json=payload,
            )
            if resp.status_code != 200:
                body = resp.text
                logger.warning("  ❌ SKR key/release returned %d: %s", resp.status_code, body[:500])
                return None
            logger.info("  ✅ SKR returned 200 — hardware attestation passed, key released!")
            data = resp.json()
            key = data.get("key")
            if isinstance(key, str):
                key = json.loads(key)
            key_type = key.get("kty", "unknown") if key else "unknown"
            key_size = len(_base64url_decode(key.get("n", ""))) * 8 if key and "n" in key else 0
            logger.info("  Key type: %s, size: %d-bit", key_type, key_size)
            return key
    except Exception as e:
        logger.warning("SKR envelope key fetch failed: %s", e)
        return None


async def _load_secrets() -> None:
    """Load secrets via envelope encryption (SKR) or plain env vars (local dev).

    Production path:
      1. SKR sidecar releases the RSA private key (attested by MAA)
      2. Decrypt each ENC_* env var with RSA-OAEP
    Local dev path:
      Fall back to plain GITHUB_TOKEN / DB_CONNECTION_STRING / WEBHOOK_URL
    """
    global GITHUB_TOKEN, DB_CONNECTION_STRING, WEBHOOK_URL

    secrets: dict[str, str] = {}

    # Try SKR envelope decryption first (production path)
    envelope_jwk = await _fetch_envelope_key()
    if envelope_jwk:
        try:
            private_key = _jwk_to_private_key(envelope_jwk)
            logger.info("  ✅ RSA private key reconstructed from JWK")
            logger.info("  Decrypting ENC_* environment variables with RSA-OAEP-256...")

            for env_name, enc_env_name in _ENCRYPTED_ENV_MAP.items():
                enc_value = os.environ.get(enc_env_name, "")
                if enc_value:
                    try:
                        secrets[env_name] = _decrypt_secret(private_key, enc_value)
                        _secrets_source[env_name] = "skr+envelope"
                        logger.info("  🔓 Decrypted %s (%d chars of ciphertext → plaintext in memory only)", env_name, len(enc_value))
                    except Exception as e:
                        logger.warning("  ❌ Failed to decrypt %s: %s", env_name, e)
                        _secrets_source[env_name] = "decrypt_failed"
                else:
                    _secrets_source[env_name] = "none (no ciphertext)"
        except Exception as e:
            logger.error("Failed to construct RSA key from JWK: %s", e)

    # Fall back to plain env vars for any secrets not yet loaded
    for env_name in _ENCRYPTED_ENV_MAP:
        if env_name not in secrets:
            value = os.environ.get(env_name, "")
            secrets[env_name] = value
            if env_name not in _secrets_source:
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


@mcp.tool()
async def debug_skr_status() -> dict[str, Any]:
    """
    Diagnostic tool: probe the SKR sidecar and report detailed status.
    Useful for troubleshooting attestation and key release issues.
    """
    result: dict[str, Any] = {
        "skr_endpoint": SKR_ENDPOINT,
        "maa_endpoint": MAA_ENDPOINT,
        "akv_endpoint": AKV_ENDPOINT,
        "envelope_key": ENVELOPE_KEY_NAME,
    }

    # Check ENC_* env var presence (not values)
    for name, enc_name in _ENCRYPTED_ENV_MAP.items():
        val = os.environ.get(enc_name, "")
        result[f"env_{enc_name}"] = f"present ({len(val)} chars)" if val else "EMPTY"

    # Check SKR sidecar health
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{SKR_ENDPOINT}/status")
            result["skr_status"] = {"code": resp.status_code, "body": resp.text[:200]}
    except Exception as e:
        result["skr_status"] = {"error": str(e)}

    # Try IMDS token
    identity_client_id = os.environ.get("IDENTITY_CLIENT_ID", "")
    result["identity_client_id"] = identity_client_id or "not set"
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            params = {"api-version": "2018-02-01", "resource": "https://vault.azure.net"}
            if identity_client_id:
                params["client_id"] = identity_client_id
            resp = await client.get(
                "http://169.254.169.254/metadata/identity/oauth2/token",
                params=params, headers={"Metadata": "true"},
            )
            result["imds_token"] = {"code": resp.status_code, "has_token": "access_token" in resp.text}
    except Exception as e:
        result["imds_token"] = {"error": str(e)}

    # Try SKR key release
    try:
        access_token = None
        async with httpx.AsyncClient(timeout=10) as client:
            params = {"api-version": "2018-02-01", "resource": "https://vault.azure.net"}
            if identity_client_id:
                params["client_id"] = identity_client_id
            resp = await client.get(
                "http://169.254.169.254/metadata/identity/oauth2/token",
                params=params, headers={"Metadata": "true"},
            )
            if resp.status_code == 200:
                access_token = resp.json().get("access_token")

        async with httpx.AsyncClient(timeout=30) as client:
            akv_host = AKV_ENDPOINT.rstrip("/").replace("https://", "").replace("http://", "")
            payload = {
                "maa_endpoint": MAA_ENDPOINT,
                "akv_endpoint": akv_host,
                "kid": ENVELOPE_KEY_NAME,
            }
            if access_token:
                payload["access_token"] = access_token
            resp = await client.post(f"{SKR_ENDPOINT}/key/release", json=payload)
            if resp.status_code == 200:
                data = resp.json()
                key = data.get("key")
                if isinstance(key, str):
                    key = json.loads(key)
                result["key_release"] = {"code": 200, "key_type": key.get("kty") if key else "unknown"}
            else:
                result["key_release"] = {"code": resp.status_code, "body": resp.text[:500]}
    except Exception as e:
        result["key_release"] = {"error": str(e)}

    return result


# ── Entry Point ─────────────────────────────────────────────────
_BANNER = """
╔══════════════════════════════════════════════════════════════════╗
║          MCP TEE Server — Confidential Container Demo           ║
║                      OC3 2025 Reference                         ║
╚══════════════════════════════════════════════════════════════════╝
"""

if __name__ == "__main__":
    print(_BANNER, flush=True)

    # ── Phase 1: TEE Detection ──────────────────────────────────
    logger.info("▶ Phase 1/4 — TEE Detection")
    sev_guest = os.path.exists("/dev/sev-guest")
    sev_dev = os.path.exists("/dev/sev")
    tee_sec = os.path.exists("/sys/kernel/security/tee")
    logger.info("  /dev/sev-guest : %s", "✅ FOUND" if sev_guest else "❌ not found")
    logger.info("  /dev/sev       : %s", "✅ FOUND" if sev_dev else "— not found")
    if sev_guest:
        logger.info("  ✅ Running inside AMD SEV-SNP Trusted Execution Environment")
    else:
        logger.info("  ⚠️  No TEE detected — running in plain container (dev mode)")

    # ── Phase 2: Managed Identity ───────────────────────────────
    logger.info("▶ Phase 2/4 — Managed Identity Token")
    identity_client_id = os.environ.get("IDENTITY_CLIENT_ID", "")
    if identity_client_id:
        logger.info("  Identity client ID: %s...%s", identity_client_id[:8], identity_client_id[-4:])
    else:
        logger.info("  No IDENTITY_CLIENT_ID set — will use system-assigned identity")

    # ── Phase 3: Secret Loading ─────────────────────────────────
    logger.info("▶ Phase 3/4 — Envelope Encryption & Secret Loading")
    logger.info("  SKR endpoint : %s", SKR_ENDPOINT)
    logger.info("  MAA endpoint : %s", MAA_ENDPOINT)
    logger.info("  AKV endpoint : %s", AKV_ENDPOINT[:40] + "..." if len(AKV_ENDPOINT) > 40 else AKV_ENDPOINT)
    logger.info("  Envelope key : %s", ENVELOPE_KEY_NAME)
    enc_count = sum(1 for v in _ENCRYPTED_ENV_MAP.values() if os.environ.get(v, ""))
    logger.info("  Encrypted env vars found: %d/%d", enc_count, len(_ENCRYPTED_ENV_MAP))
    logger.info("  Requesting SKR sidecar to perform attestation & key release...")

    asyncio.run(_load_secrets())

    secrets = _check_secrets()
    loaded = sum(1 for v in secrets.values() if v)
    logger.info("  ──────────────────────────────────────────────")
    for name, is_loaded in secrets.items():
        src = _secrets_source.get(name, "unknown")
        icon = "🔓" if is_loaded else "🔒"
        logger.info("  %s %s : %s (via %s)", icon, name, "LOADED" if is_loaded else "NOT LOADED", src)
    logger.info("  ──────────────────────────────────────────────")
    if loaded == len(secrets):
        logger.info("  ✅ All %d secrets decrypted inside TEE — never touched disk", loaded)
    else:
        logger.info("  ⚠️  %d/%d secrets loaded", loaded, len(secrets))

    # ── Phase 4: MCP Transport ──────────────────────────────────
    transport = os.environ.get("MCP_TRANSPORT", "streamable-http")
    if transport not in {"stdio", "streamable-http"}:
        logger.warning("Unknown MCP_TRANSPORT=%r, falling back to streamable-http", transport)
        transport = "streamable-http"
    logger.info("▶ Phase 4/4 — Starting MCP Transport")
    logger.info("  Transport : %s", transport)
    logger.info("  Tools     : github_search_issues, query_database, send_notification, attestation_status")
    if transport == "stdio":
        logger.info("  Ready for stdio connections")
        mcp.run(transport="stdio")
    else:
        mcp.settings.host = "0.0.0.0"
        mcp.settings.port = 8080
        logger.info("  Listening on http://0.0.0.0:8080/mcp")
        logger.info("══════════════════════════════════════════════════════════════════")
        mcp.run(transport="streamable-http")
