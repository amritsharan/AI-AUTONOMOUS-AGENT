"""
Classical Security Engine — Reconnaissance Module
Crawls the target application to build an application map.
All requests pass through the Policy Engine.
"""
import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin, urlparse

import httpx

from app.policy.engine import PolicyEngine, ScopeConfig

logger = logging.getLogger(__name__)


@dataclass
class ReconResult:
    """Application map built by reconnaissance."""
    target_url: str
    pages: list[str] = field(default_factory=list)
    apis: list[dict] = field(default_factory=list)
    forms: list[dict] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    authentication_mechanisms: list[str] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    security_headers: dict = field(default_factory=dict)
    tls_info: dict = field(default_factory=dict)
    cors_policy: dict = field(default_factory=dict)
    js_routes: list[str] = field(default_factory=list)
    api_schema: Optional[dict] = None
    metadata: dict = field(default_factory=dict)
    error: Optional[str] = None


TECH_FINGERPRINTS = {
    "Flask": ["Werkzeug", "flask"],
    "FastAPI": ["fastapi", "uvicorn"],
    "Django": ["Django", "csrftoken"],
    "Express": ["Express", "x-powered-by: express"],
    "Rails": ["X-Powered-By: Phusion Passenger", "X-Runtime"],
    "React": ["__react", "data-reactroot"],
    "Vue": ["__vue"],
    "Angular": ["ng-version"],
    "JWT": ["eyJ"],
    "PostgreSQL": ["postgresql"],
    "SQLite": ["sqlite"],
}

SECURITY_HEADERS_TO_CHECK = [
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "strict-transport-security",
    "x-xss-protection",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
]


async def run_recon(
    target_url: str,
    scope: ScopeConfig,
    policy: PolicyEngine,
    scan_id: str = "",
    event_callback=None,
) -> ReconResult:
    """Run full reconnaissance against a target."""
    result = ReconResult(target_url=target_url)

    async def emit(msg: str):
        logger.info(f"[RECON] {msg}")
        if event_callback:
            await event_callback("recon", msg)

    await emit(f"Starting reconnaissance on {target_url}")

    # Policy check
    decision = policy.validate("recon_crawl", target_url, scope, scan_id)
    if not decision.allowed:
        result.error = f"Policy denied: {decision.reason}"
        await emit(f"Reconnaissance blocked by policy: {decision.reason}")
        return result

    timeout = httpx.Timeout(10.0, connect=5.0)
    headers = {"User-Agent": "QuantumShield-SecurityScanner/1.0 (Authorized Lab Testing)"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        # 1. Fetch root page
        await emit("Fetching root page...")
        try:
            resp = await client.get(target_url, headers=headers)
            result.pages.append("/")
            _analyze_response_headers(resp, result)
            _detect_technologies(resp, result)
        except Exception as e:
            result.error = str(e)
            await emit(f"Error fetching root: {e}")
            return result

        # 2. Try common paths
        common_paths = [
            "/health", "/api", "/api/info", "/api/sitemap",
            "/login", "/dashboard", "/admin", "/api/auth/login",
            "/docs", "/openapi.json", "/swagger.json", "/api/v1",
            "/api/products", "/api/orders", "/api/users",
            "/api/debug", "/api/crypto/config",
        ]
        await emit(f"Probing {len(common_paths)} common paths...")
        for path in common_paths:
            decision = policy.validate("recon_crawl", urljoin(target_url, path), scope, scan_id)
            if not decision.allowed:
                continue
            try:
                r = await client.get(urljoin(target_url, path), headers=headers)
                if r.status_code < 500:
                    if path not in result.pages:
                        result.pages.append(path)
                await asyncio.sleep(0.1)  # Rate limiting courtesy
            except Exception:
                pass

        # 3. Fetch sitemap if available
        await emit("Fetching application sitemap...")
        try:
            sitemap_r = await client.get(urljoin(target_url, "/api/sitemap"), headers=headers)
            if sitemap_r.status_code == 200:
                sitemap = sitemap_r.json()
                for ep in sitemap.get("endpoints", []):
                    result.apis.append({
                        "path": ep.get("path"),
                        "methods": ep.get("methods", ["GET"]),
                        "auth_required": ep.get("auth", False),
                        "notes": ep.get("vuln", ""),
                    })
                await emit(f"Discovered {len(result.apis)} API endpoints from sitemap")
        except Exception as e:
            await emit(f"No sitemap available: {e}")

        # 4. Try OpenAPI/Swagger
        for schema_path in ["/openapi.json", "/docs/openapi.json", "/swagger.json"]:
            try:
                sr = await client.get(urljoin(target_url, schema_path), headers=headers)
                if sr.status_code == 200:
                    result.api_schema = sr.json()
                    await emit(f"Found API schema at {schema_path}")
                    _parse_openapi_schema(result.api_schema, result)
                    break
            except Exception:
                pass

        # 5. App info / metadata
        await emit("Fetching application metadata...")
        try:
            info_r = await client.get(urljoin(target_url, "/api/info"), headers=headers)
            if info_r.status_code == 200:
                info = info_r.json()
                result.metadata.update(info)
                _detect_technologies_from_metadata(info, result)
        except Exception:
            pass

        # 6. TLS info (basic check)
        parsed = urlparse(target_url)
        if parsed.scheme == "https":
            result.tls_info = {"tls": True, "host": parsed.netloc}
        else:
            result.tls_info = {"tls": False, "note": "HTTP only — no TLS"}

        # 7. Check CORS
        await emit("Checking CORS configuration...")
        try:
            cors_r = await client.options(
                urljoin(target_url, "/api/auth/login"),
                headers={**headers, "Origin": "https://evil.example.com"}
            )
            acao = cors_r.headers.get("access-control-allow-origin", "")
            acac = cors_r.headers.get("access-control-allow-credentials", "")
            result.cors_policy = {
                "access_control_allow_origin": acao,
                "access_control_allow_credentials": acac,
                "reflects_origin": acao == "https://evil.example.com" or acao == "*",
            }
        except Exception:
            result.cors_policy = {"error": "CORS check failed"}

        # 8. Check authentication mechanisms
        if any("jwt" in str(a).lower() for a in result.apis):
            result.authentication_mechanisms.append("JWT")
        if any("/auth/login" in str(a) for a in result.apis):
            result.authentication_mechanisms.append("Session/Token")

        # 9. Crypto config endpoint
        await emit("Fetching cryptographic configuration...")
        try:
            crypto_r = await client.get(urljoin(target_url, "/api/crypto/config"), headers=headers)
            if crypto_r.status_code == 200:
                result.metadata["crypto_config"] = crypto_r.json()
        except Exception:
            pass

    total_endpoints = len(result.pages) + len(result.apis)
    await emit(f"Reconnaissance complete: {total_endpoints} endpoints discovered, {len(result.technologies)} technologies detected")

    return result


def _analyze_response_headers(resp: httpx.Response, result: ReconResult):
    """Analyze HTTP response headers for security and tech info."""
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # Security headers presence check
    for h in SECURITY_HEADERS_TO_CHECK:
        result.security_headers[h] = headers_lower.get(h, "MISSING")

    # Server tech from headers
    server = headers_lower.get("server", "")
    if server:
        result.metadata["server_header"] = server
        if "werkzeug" in server.lower():
            if "Flask" not in result.technologies:
                result.technologies.append("Flask")
        if "uvicorn" in server.lower() or "fastapi" in server.lower():
            if "FastAPI" not in result.technologies:
                result.technologies.append("FastAPI")

    # X-Powered-By
    xpb = headers_lower.get("x-powered-by", "")
    if xpb:
        result.metadata["x_powered_by"] = xpb

    # Cookies
    for cookie in resp.cookies.jar:
        result.cookies.append({
            "name": cookie.name,
            "httponly": cookie.has_nonstandard_attr("HttpOnly"),
            "secure": cookie.secure,
            "samesite": cookie.get_nonstandard_attr("SameSite", "None"),
        })


def _detect_technologies(resp: httpx.Response, result: ReconResult):
    """Detect technologies from response body and headers."""
    body = resp.text[:5000]  # Limit analysis
    for tech, patterns in TECH_FINGERPRINTS.items():
        for pattern in patterns:
            if pattern.lower() in body.lower() or pattern.lower() in str(resp.headers).lower():
                if tech not in result.technologies:
                    result.technologies.append(tech)
                break


def _detect_technologies_from_metadata(info: dict, result: ReconResult):
    """Detect technologies from API metadata response."""
    framework = info.get("framework", "")
    if framework and framework not in result.technologies:
        result.technologies.append(framework)
    db = info.get("database", "")
    if db and db not in result.technologies:
        result.technologies.append(db)
    if info.get("debug"):
        result.metadata["debug_mode"] = True


def _parse_openapi_schema(schema: dict, result: ReconResult):
    """Extract endpoints from OpenAPI schema."""
    paths = schema.get("paths", {})
    for path, methods in paths.items():
        for method in methods:
            if method.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"):
                result.apis.append({
                    "path": path,
                    "methods": [method.upper()],
                    "auth_required": "security" in methods[method],
                    "notes": "",
                })
