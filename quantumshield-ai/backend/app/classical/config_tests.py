"""
Classical Security Engine — Configuration & Header Security Tests
Checks: security headers, CORS, debug mode, TLS, cookie flags, info disclosure.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from app.policy.engine import PolicyEngine, ScopeConfig

logger = logging.getLogger(__name__)

REQUIRED_SECURITY_HEADERS = {
    "x-frame-options": {"values": ["DENY", "SAMEORIGIN"], "severity": "MEDIUM"},
    "x-content-type-options": {"values": ["nosniff"], "severity": "LOW"},
    "content-security-policy": {"values": None, "severity": "MEDIUM"},
    "strict-transport-security": {"values": None, "severity": "MEDIUM"},
    "referrer-policy": {"values": None, "severity": "LOW"},
    "permissions-policy": {"values": None, "severity": "LOW"},
}


@dataclass
class ConfigTestResult:
    test_name: str
    endpoint: str
    status: str
    observation: str
    evidence: dict = field(default_factory=dict)
    confidence: float = 0.0
    severity: str = "LOW"


async def run_config_tests(
    target_url: str,
    scope: ScopeConfig,
    policy: PolicyEngine,
    scan_id: str = "",
    event_callback=None,
) -> list[ConfigTestResult]:
    """Run all configuration security tests."""
    results = []

    async def emit(msg: str):
        logger.info(f"[CONFIG] {msg}")
        if event_callback:
            await event_callback("config_test", msg)

    await emit("Starting configuration security tests...")
    timeout = httpx.Timeout(10.0)
    headers = {"User-Agent": "QuantumShield-SecurityScanner/1.0"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        # Test 1: Security headers
        await emit("Checking security headers...")
        decision = policy.validate("header_check", target_url, scope, scan_id)
        if decision.allowed:
            result = await _test_security_headers(client, target_url, headers)
            results.append(result)
            await emit(f"Security headers: {result.status}")

        # Test 2: CORS configuration
        await emit("Checking CORS configuration...")
        decision = policy.validate("cors_test", target_url, scope, scan_id)
        if decision.allowed:
            result = await _test_cors(client, target_url, headers)
            results.append(result)
            await emit(f"CORS test: {result.status} — {result.observation}")

        # Test 3: Information disclosure via debug endpoints
        await emit("Checking for information disclosure...")
        decision = policy.validate("config_test", urljoin(target_url, "/api/debug"), scope, scan_id)
        if decision.allowed:
            result = await _test_info_disclosure(client, target_url, headers)
            results.append(result)
            await emit(f"Info disclosure: {result.status}")

        # Test 4: Cookie security flags
        await emit("Checking cookie security flags...")
        decision = policy.validate("cookie_check", urljoin(target_url, "/api/auth/login"), scope, scan_id)
        if decision.allowed:
            result = await _test_cookie_security(client, target_url, headers)
            results.append(result)
            await emit(f"Cookie security: {result.status}")

        # Test 5: TLS/HTTPS check
        await emit("Checking TLS configuration...")
        result = _test_tls_config(target_url)
        results.append(result)
        await emit(f"TLS check: {result.status}")

        # Test 6: Server info disclosure
        await emit("Checking server version disclosure...")
        result = await _test_server_disclosure(client, target_url, headers)
        results.append(result)
        await emit(f"Server disclosure: {result.status}")

    await emit(f"Configuration tests complete: {len(results)} tests run")
    return results


async def _test_security_headers(client: httpx.AsyncClient, url: str, headers: dict) -> ConfigTestResult:
    try:
        resp = await client.get(url, headers=headers)
        resp_headers = {k.lower(): v for k, v in resp.headers.items()}

        missing_headers = []
        present_headers = []

        for header, config in REQUIRED_SECURITY_HEADERS.items():
            if header in resp_headers:
                present_headers.append(header)
            else:
                missing_headers.append({"header": header, "severity": config["severity"]})

        if missing_headers:
            critical_missing = [h for h in missing_headers if h["severity"] == "MEDIUM"]
            return ConfigTestResult(
                test_name="security_headers_test",
                endpoint=url,
                status="SUSPICIOUS",
                observation=f"Missing {len(missing_headers)} security headers: {[h['header'] for h in missing_headers]}",
                evidence={
                    "missing_headers": missing_headers,
                    "present_headers": present_headers,
                    "response_headers": dict(resp_headers),
                },
                confidence=0.98,
                severity="MEDIUM" if critical_missing else "LOW",
            )
        return ConfigTestResult(
            test_name="security_headers_test",
            endpoint=url,
            status="PASS",
            observation="All required security headers present.",
            evidence={"present_headers": present_headers},
            confidence=0.95,
        )
    except Exception as e:
        return ConfigTestResult(
            test_name="security_headers_test",
            endpoint=url,
            status="ERROR",
            observation=f"Test error: {e}",
        )


async def _test_cors(client: httpx.AsyncClient, url: str, headers: dict) -> ConfigTestResult:
    """Test CORS — check if arbitrary origin is reflected."""
    try:
        evil_origin = "https://evil.attacker.com"
        resp = await client.options(
            urljoin(url, "/api/auth/login"),
            headers={**headers, "Origin": evil_origin, "Access-Control-Request-Method": "POST"},
        )
        acao = resp.headers.get("access-control-allow-origin", "")
        acac = resp.headers.get("access-control-allow-credentials", "")

        if acao == evil_origin or acao == "*":
            if acac.lower() == "true":
                return ConfigTestResult(
                    test_name="cors_misconfiguration_test",
                    endpoint=url,
                    status="SUSPICIOUS",
                    observation=f"Critical CORS misconfiguration: Origin '{evil_origin}' is allowed AND credentials=true. This allows cross-origin credential theft.",
                    evidence={
                        "reflected_origin": acao,
                        "credentials_allowed": acac,
                        "tested_origin": evil_origin,
                    },
                    confidence=0.98,
                    severity="HIGH",
                )
            else:
                return ConfigTestResult(
                    test_name="cors_misconfiguration_test",
                    endpoint=url,
                    status="SUSPICIOUS",
                    observation=f"CORS allows any origin ('{acao}'). Without credentials it's lower risk but still misconfigured.",
                    evidence={"reflected_origin": acao, "credentials_allowed": acac},
                    confidence=0.85,
                    severity="MEDIUM",
                )
        return ConfigTestResult(
            test_name="cors_misconfiguration_test",
            endpoint=url,
            status="PASS",
            observation=f"CORS properly configured. Access-Control-Allow-Origin: '{acao}'",
            evidence={"acao": acao},
            confidence=0.9,
        )
    except Exception as e:
        return ConfigTestResult(
            test_name="cors_misconfiguration_test",
            endpoint=url,
            status="ERROR",
            observation=f"CORS test error: {e}",
        )


async def _test_info_disclosure(client: httpx.AsyncClient, url: str, headers: dict) -> ConfigTestResult:
    """Test for debug endpoints and info disclosure."""
    debug_paths = ["/api/debug", "/api/info", "/debug", "/.env", "/config", "/api/crypto/config"]
    findings = []
    for path in debug_paths:
        try:
            resp = await client.get(urljoin(url, path), headers=headers)
            if resp.status_code == 200:
                body = resp.text
                sensitive_keys = ["password", "secret", "key", "env", "token", "database"]
                found = [k for k in sensitive_keys if k.lower() in body.lower()]
                if found:
                    findings.append({
                        "path": path,
                        "status_code": 200,
                        "sensitive_keys_found": found,
                        "response_preview": body[:300],
                    })
            await asyncio.sleep(0.1)
        except Exception:
            pass

    if findings:
        return ConfigTestResult(
            test_name="info_disclosure_test",
            endpoint=url,
            status="SUSPICIOUS",
            observation=f"Information disclosure: {len(findings)} debug/config endpoints expose sensitive data.",
            evidence={"disclosure_findings": findings},
            confidence=0.92,
            severity="MEDIUM",
        )
    return ConfigTestResult(
        test_name="info_disclosure_test",
        endpoint=url,
        status="PASS",
        observation="No sensitive information disclosure detected.",
        evidence={"paths_tested": debug_paths},
        confidence=0.8,
    )


async def _test_cookie_security(client: httpx.AsyncClient, url: str, headers: dict) -> ConfigTestResult:
    """Test session cookie security flags."""
    try:
        resp = await client.post(
            urljoin(url, "/api/auth/login"),
            json={"username": "alice", "password": "Alice@123"},
            headers={**headers, "Content-Type": "application/json"},
        )
        issues = []
        cookie_info = {}
        for cookie in resp.cookies.jar:
            info = {
                "httponly": cookie.has_nonstandard_attr("HttpOnly"),
                "secure": cookie.secure,
                "samesite": cookie.get_nonstandard_attr("SameSite", "NOT_SET"),
            }
            cookie_info[cookie.name] = info
            if not info["httponly"]:
                issues.append(f"'{cookie.name}' missing HttpOnly")
            if not info["secure"]:
                issues.append(f"'{cookie.name}' missing Secure flag")
            if info["samesite"] == "NOT_SET":
                issues.append(f"'{cookie.name}' missing SameSite attribute")

        if issues:
            return ConfigTestResult(
                test_name="cookie_security_test",
                endpoint=urljoin(url, "/api/auth/login"),
                status="SUSPICIOUS",
                observation=f"Cookie security issues: {'; '.join(issues)}",
                evidence={"cookies": cookie_info, "issues": issues},
                confidence=0.95,
                severity="MEDIUM",
            )
        return ConfigTestResult(
            test_name="cookie_security_test",
            endpoint=url,
            status="PASS",
            observation="Cookie security flags properly configured.",
            evidence={"cookies": cookie_info},
            confidence=0.9,
        )
    except Exception as e:
        return ConfigTestResult(
            test_name="cookie_security_test",
            endpoint=url,
            status="ERROR",
            observation=f"Test error: {e}",
        )


def _test_tls_config(url: str) -> ConfigTestResult:
    """Check if TLS is used."""
    if url.startswith("https://"):
        return ConfigTestResult(
            test_name="tls_config_test",
            endpoint=url,
            status="PASS",
            observation="TLS/HTTPS is in use.",
            evidence={"tls": True},
            confidence=0.9,
        )
    return ConfigTestResult(
        test_name="tls_config_test",
        endpoint=url,
        status="SUSPICIOUS",
        observation="HTTP only — no TLS encryption. Lab environment only; would be critical in production.",
        evidence={"tls": False, "note": "Expected in lab environment"},
        confidence=0.95,
        severity="INFORMATIONAL",
    )


async def _test_server_disclosure(client: httpx.AsyncClient, url: str, headers: dict) -> ConfigTestResult:
    """Check if server version information is disclosed."""
    try:
        resp = await client.get(url, headers=headers)
        server_header = resp.headers.get("server", "")
        xpb = resp.headers.get("x-powered-by", "")

        issues = []
        if server_header:
            issues.append(f"Server header reveals: '{server_header}'")
        if xpb:
            issues.append(f"X-Powered-By reveals: '{xpb}'")

        if issues:
            return ConfigTestResult(
                test_name="server_disclosure_test",
                endpoint=url,
                status="SUSPICIOUS",
                observation=f"Server version disclosure: {'; '.join(issues)}",
                evidence={"server": server_header, "x_powered_by": xpb},
                confidence=0.9,
                severity="LOW",
            )
        return ConfigTestResult(
            test_name="server_disclosure_test",
            endpoint=url,
            status="PASS",
            observation="No server version disclosure detected.",
            evidence={},
            confidence=0.85,
        )
    except Exception as e:
        return ConfigTestResult(
            test_name="server_disclosure_test",
            endpoint=url,
            status="ERROR",
            observation=f"Test error: {e}",
        )
