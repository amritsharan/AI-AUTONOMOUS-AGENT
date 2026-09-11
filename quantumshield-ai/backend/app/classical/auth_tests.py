"""
Classical Security Engine — Authentication Tests
Tests for: rate limiting, lockout, enumeration, session, bypass indicators.
All tests are BOUNDED and NON-DESTRUCTIVE.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx

from app.policy.engine import PolicyEngine, ScopeConfig

logger = logging.getLogger(__name__)

# Hard bounded attempt limits for all brute-force style tests
MAX_AUTH_ATTEMPTS = 5
MAX_ENUM_ATTEMPTS = 8


@dataclass
class AuthTestResult:
    test_name: str
    endpoint: str
    status: str  # PASS | FAIL | SUSPICIOUS | ERROR
    observation: str
    evidence: dict = field(default_factory=dict)
    confidence: float = 0.0
    severity: str = "LOW"


async def run_auth_tests(
    target_url: str,
    scope: ScopeConfig,
    policy: PolicyEngine,
    scan_id: str = "",
    event_callback=None,
) -> list[AuthTestResult]:
    """Run all authentication security tests."""
    results = []

    async def emit(msg: str):
        logger.info(f"[AUTH] {msg}")
        if event_callback:
            await event_callback("auth_test", msg)

    await emit("Starting authentication security tests...")

    login_url = urljoin(target_url, "/api/auth/login")
    timeout = httpx.Timeout(10.0)
    headers = {"Content-Type": "application/json", "User-Agent": "QuantumShield-SecurityScanner/1.0"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        # Test 1: Rate limit on login
        await emit("Testing login rate limiting...")
        decision = policy.validate("auth_test", login_url, scope, scan_id)
        if decision.allowed:
            result = await _test_rate_limiting(client, login_url, headers)
            results.append(result)
            await emit(f"Rate limit test: {result.status} — {result.observation}")

        # Test 2: Username enumeration
        await emit("Testing username enumeration...")
        decision = policy.validate("auth_test", login_url, scope, scan_id)
        if decision.allowed:
            result = await _test_username_enumeration(client, login_url, headers)
            results.append(result)
            await emit(f"Enumeration test: {result.status} — {result.observation}")

        # Test 3: Account lockout
        await emit("Testing account lockout...")
        decision = policy.validate("auth_test", login_url, scope, scan_id)
        if decision.allowed:
            result = await _test_account_lockout(client, login_url, headers)
            results.append(result)
            await emit(f"Lockout test: {result.status} — {result.observation}")

        # Test 4: Weak credentials
        await emit("Testing weak credential acceptance...")
        decision = policy.validate("auth_test", login_url, scope, scan_id)
        if decision.allowed:
            result = await _test_weak_credentials(client, login_url, headers)
            results.append(result)
            await emit(f"Weak creds test: {result.status} — {result.observation}")

        # Test 5: Session token in cookie security
        await emit("Testing session/token security...")
        result = await _test_session_security(client, login_url, headers)
        results.append(result)
        await emit(f"Session test: {result.status} — {result.observation}")

        # Test 6: Authentication bypass indicators
        await emit("Testing authentication bypass indicators...")
        bypass_url = urljoin(target_url, "/api/admin/stats")
        decision = policy.validate("auth_test", bypass_url, scope, scan_id)
        if decision.allowed:
            result = await _test_auth_bypass(client, bypass_url, headers)
            results.append(result)
            await emit(f"Auth bypass test: {result.status} — {result.observation}")

    await emit(f"Authentication tests complete: {len(results)} tests run")
    return results


async def _test_rate_limiting(client: httpx.AsyncClient, login_url: str, headers: dict) -> AuthTestResult:
    """Test if the login endpoint rate-limits repeated failed attempts."""
    responses = []
    for i in range(MAX_AUTH_ATTEMPTS):
        try:
            resp = await client.post(
                login_url,
                json={"username": f"nonexistent_user_{i}", "password": "wrongpass"},
                headers=headers,
            )
            responses.append(resp.status_code)
            await asyncio.sleep(0.2)
        except Exception as e:
            return AuthTestResult(
                test_name="rate_limit_test",
                endpoint=login_url,
                status="ERROR",
                observation=f"Request failed: {e}",
                confidence=0.0,
            )

    # Check if any response was 429 or there's a lockout indicator
    rate_limited = any(sc == 429 for sc in responses)
    all_same = len(set(responses)) == 1

    if rate_limited:
        return AuthTestResult(
            test_name="rate_limit_test",
            endpoint=login_url,
            status="PASS",
            observation=f"Rate limiting detected (429 response). Status codes: {responses}",
            evidence={"status_codes": responses, "rate_limited": True},
            confidence=0.95,
            severity="LOW",
        )
    elif all_same and responses[0] in (401, 403, 404):
        return AuthTestResult(
            test_name="rate_limit_test",
            endpoint=login_url,
            status="SUSPICIOUS",
            observation=f"No rate limiting detected. {MAX_AUTH_ATTEMPTS} failed attempts returned consistent {responses[0]}. Brute force may be possible.",
            evidence={"status_codes": responses, "rate_limited": False, "attempts": MAX_AUTH_ATTEMPTS},
            confidence=0.85,
            severity="MEDIUM",
        )
    else:
        return AuthTestResult(
            test_name="rate_limit_test",
            endpoint=login_url,
            status="SUSPICIOUS",
            observation=f"Inconsistent responses without rate limit: {responses}",
            evidence={"status_codes": responses},
            confidence=0.6,
            severity="MEDIUM",
        )


async def _test_username_enumeration(client: httpx.AsyncClient, login_url: str, headers: dict) -> AuthTestResult:
    """Test if the endpoint reveals whether a username exists."""
    # Use a known-to-exist username (from lab seed) vs unknown
    test_cases = [
        {"username": "alice", "password": "wrongpass", "label": "known_user"},
        {"username": "definitely_nonexistent_xyz123", "password": "wrongpass", "label": "unknown_user"},
    ]
    responses_by_label = {}
    for tc in test_cases:
        try:
            resp = await client.post(
                login_url,
                json={"username": tc["username"], "password": tc["password"]},
                headers=headers,
            )
            responses_by_label[tc["label"]] = {
                "status_code": resp.status_code,
                "body_preview": resp.text[:200],
            }
            await asyncio.sleep(0.3)
        except Exception as e:
            responses_by_label[tc["label"]] = {"error": str(e)}

    known_code = responses_by_label.get("known_user", {}).get("status_code", -1)
    unknown_code = responses_by_label.get("unknown_user", {}).get("status_code", -1)
    known_body = responses_by_label.get("known_user", {}).get("body_preview", "")
    unknown_body = responses_by_label.get("unknown_user", {}).get("body_preview", "")

    # Different response for known vs unknown = enumeration
    if known_code != unknown_code:
        return AuthTestResult(
            test_name="username_enumeration_test",
            endpoint=login_url,
            status="SUSPICIOUS",
            observation=f"Different HTTP status codes for known ({known_code}) vs unknown ({unknown_code}) users. Username enumeration possible.",
            evidence=responses_by_label,
            confidence=0.9,
            severity="LOW",
        )
    elif known_body != unknown_body:
        return AuthTestResult(
            test_name="username_enumeration_test",
            endpoint=login_url,
            status="SUSPICIOUS",
            observation="Same status code but different response bodies for known vs unknown users. Enumeration possible via response content.",
            evidence=responses_by_label,
            confidence=0.75,
            severity="LOW",
        )
    else:
        return AuthTestResult(
            test_name="username_enumeration_test",
            endpoint=login_url,
            status="PASS",
            observation="No significant difference between known and unknown user responses.",
            evidence=responses_by_label,
            confidence=0.7,
            severity="LOW",
        )


async def _test_account_lockout(client: httpx.AsyncClient, login_url: str, headers: dict) -> AuthTestResult:
    """Test if accounts get locked after repeated failures (bounded to MAX_AUTH_ATTEMPTS)."""
    statuses = []
    for i in range(MAX_AUTH_ATTEMPTS):
        try:
            resp = await client.post(
                login_url,
                json={"username": "alice", "password": f"wrongpassword{i}"},
                headers=headers,
            )
            statuses.append(resp.status_code)
            await asyncio.sleep(0.2)
        except Exception:
            statuses.append(-1)

    # Look for lockout indicators (403, 423, "locked" in body)
    has_lockout = any(sc in (423, 403) for sc in statuses[2:])

    if has_lockout:
        return AuthTestResult(
            test_name="account_lockout_test",
            endpoint=login_url,
            status="PASS",
            observation=f"Account lockout detected after repeated failures. Status codes: {statuses}",
            evidence={"status_codes": statuses},
            confidence=0.9,
            severity="LOW",
        )
    else:
        return AuthTestResult(
            test_name="account_lockout_test",
            endpoint=login_url,
            status="SUSPICIOUS",
            observation=f"No account lockout detected after {MAX_AUTH_ATTEMPTS} failed attempts. Status codes: {statuses}",
            evidence={"status_codes": statuses, "lockout_detected": False},
            confidence=0.8,
            severity="MEDIUM",
        )


async def _test_weak_credentials(client: httpx.AsyncClient, login_url: str, headers: dict) -> AuthTestResult:
    """Test if lab app accepts obviously weak credentials (lab admin/admin test)."""
    weak_creds = [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "123456"),
        ("admin", "admin123"),
    ]
    successful_logins = []
    for username, password in weak_creds:
        try:
            resp = await client.post(
                login_url,
                json={"username": username, "password": password},
                headers=headers,
            )
            if resp.status_code == 200:
                successful_logins.append((username, password))
            await asyncio.sleep(0.2)
        except Exception:
            pass

    if successful_logins:
        return AuthTestResult(
            test_name="weak_credentials_test",
            endpoint=login_url,
            status="SUSPICIOUS",
            observation=f"Weak credential pairs accepted: {[u for u,_ in successful_logins]}",
            evidence={"successful_logins": [{"username": u} for u, _ in successful_logins]},
            confidence=1.0,
            severity="HIGH",
        )
    else:
        return AuthTestResult(
            test_name="weak_credentials_test",
            endpoint=login_url,
            status="PASS",
            observation="No weak credential pairs accepted.",
            evidence={"tested_count": len(weak_creds)},
            confidence=0.7,
            severity="LOW",
        )


async def _test_session_security(client: httpx.AsyncClient, login_url: str, headers: dict) -> AuthTestResult:
    """Test session/token security: HttpOnly, Secure, SameSite cookie flags."""
    try:
        resp = await client.post(
            login_url,
            json={"username": "alice", "password": "Alice@123"},
            headers=headers,
        )
    except Exception as e:
        return AuthTestResult(
            test_name="session_security_test",
            endpoint=login_url,
            status="ERROR",
            observation=f"Login failed: {e}",
        )

    issues = []
    cookie_data = {}
    for cookie in resp.cookies.jar:
        cookie_data[cookie.name] = {
            "httponly": cookie.has_nonstandard_attr("HttpOnly"),
            "secure": cookie.secure,
            "samesite": cookie.get_nonstandard_attr("SameSite", "None"),
        }
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append(f"Cookie '{cookie.name}' missing HttpOnly flag")
        if not cookie.secure:
            issues.append(f"Cookie '{cookie.name}' missing Secure flag")

    # Check JWT token in response body
    body = resp.json() if resp.status_code == 200 else {}
    if "token" in body:
        issues.append("JWT token exposed in response body (should use HttpOnly cookie only)")

    if issues:
        return AuthTestResult(
            test_name="session_security_test",
            endpoint=login_url,
            status="SUSPICIOUS",
            observation=f"Session security issues: {'; '.join(issues)}",
            evidence={"cookies": cookie_data, "token_in_body": "token" in body, "issues": issues},
            confidence=0.95,
            severity="MEDIUM",
        )
    else:
        return AuthTestResult(
            test_name="session_security_test",
            endpoint=login_url,
            status="PASS",
            observation="Session token security looks appropriate.",
            evidence={"cookies": cookie_data},
            confidence=0.8,
            severity="LOW",
        )


async def _test_auth_bypass(client: httpx.AsyncClient, bypass_url: str, headers: dict) -> AuthTestResult:
    """Test if sensitive endpoints can be accessed without authentication."""
    try:
        # No auth header
        resp = await client.get(bypass_url, headers=headers)
        if resp.status_code == 200:
            return AuthTestResult(
                test_name="auth_bypass_test",
                endpoint=bypass_url,
                status="SUSPICIOUS",
                observation=f"Endpoint accessible without authentication (HTTP {resp.status_code}). Response: {resp.text[:200]}",
                evidence={
                    "status_code": resp.status_code,
                    "response_preview": resp.text[:300],
                    "auth_required": False,
                },
                confidence=0.95,
                severity="HIGH",
            )
        else:
            return AuthTestResult(
                test_name="auth_bypass_test",
                endpoint=bypass_url,
                status="PASS",
                observation=f"Endpoint properly rejects unauthenticated requests (HTTP {resp.status_code}).",
                evidence={"status_code": resp.status_code},
                confidence=0.85,
                severity="LOW",
            )
    except Exception as e:
        return AuthTestResult(
            test_name="auth_bypass_test",
            endpoint=bypass_url,
            status="ERROR",
            observation=f"Test error: {e}",
            confidence=0.0,
        )
