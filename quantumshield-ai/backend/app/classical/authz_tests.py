"""
Classical Security Engine — Authorization Tests
Tests for: IDOR/BOLA, privilege escalation, missing authz, ownership validation.
"""
import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx

from app.policy.engine import PolicyEngine, ScopeConfig

logger = logging.getLogger(__name__)

LAB_USER_A = {"username": "alice", "password": "Alice@123"}
LAB_USER_B = {"username": "bob", "password": "Bob@456"}


@dataclass
class AuthzTestResult:
    test_name: str
    endpoint: str
    status: str  # PASS | FAIL | SUSPICIOUS | ERROR
    observation: str
    evidence: dict = field(default_factory=dict)
    confidence: float = 0.0
    severity: str = "LOW"
    finding_type: str = "IDOR"


async def run_authz_tests(
    target_url: str,
    scope: ScopeConfig,
    policy: PolicyEngine,
    scan_id: str = "",
    event_callback=None,
) -> list[AuthzTestResult]:
    """Run all authorization security tests."""
    results = []

    async def emit(msg: str):
        logger.info(f"[AUTHZ] {msg}")
        if event_callback:
            await event_callback("authz_test", msg)

    await emit("Starting authorization security tests...")
    timeout = httpx.Timeout(10.0)
    headers_base = {"Content-Type": "application/json", "User-Agent": "QuantumShield-SecurityScanner/1.0"}
    login_url = urljoin(target_url, "/api/auth/login")

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        # Login both test users
        await emit("Authenticating test users...")
        token_a = await _login(client, login_url, LAB_USER_A, headers_base)
        token_b = await _login(client, login_url, LAB_USER_B, headers_base)

        if not token_a or not token_b:
            await emit("Cannot authenticate test users — skipping authz tests")
            return results

        headers_a = {**headers_base, "Authorization": f"Bearer {token_a}"}
        headers_b = {**headers_base, "Authorization": f"Bearer {token_b}"}

        # Test 1: IDOR on orders
        await emit("Testing IDOR on order endpoints...")
        decision = policy.validate("authz_test_idor", urljoin(target_url, "/api/orders/1"), scope, scan_id)
        if decision.allowed:
            result = await _test_idor_orders(client, target_url, headers_a, headers_b)
            results.append(result)
            await emit(f"Order IDOR test: {result.status} — {result.observation}")

        # Test 2: IDOR on user profiles
        await emit("Testing IDOR on user profile endpoints...")
        decision = policy.validate("authz_test_idor", urljoin(target_url, "/api/users/1"), scope, scan_id)
        if decision.allowed:
            result = await _test_idor_users(client, target_url, headers_a, headers_b)
            results.append(result)
            await emit(f"User profile IDOR test: {result.status} — {result.observation}")

        # Test 3: Vertical privilege escalation — accessing admin endpoints
        await emit("Testing vertical privilege escalation (admin endpoints)...")
        admin_url = urljoin(target_url, "/api/admin/users")
        decision = policy.validate("authz_test_idor", admin_url, scope, scan_id)
        if decision.allowed:
            result = await _test_vertical_escalation(client, admin_url, headers_a)
            results.append(result)
            await emit(f"Vertical escalation test: {result.status} — {result.observation}")

        # Test 4: Mass assignment on user update
        await emit("Testing mass assignment vulnerability...")
        decision = policy.validate("authz_test_idor", urljoin(target_url, "/api/users/1"), scope, scan_id)
        if decision.allowed:
            result = await _test_mass_assignment(client, target_url, headers_b, token_b)
            results.append(result)
            await emit(f"Mass assignment test: {result.status} — {result.observation}")

        # Test 5: Unauthorized write — updating another user's order
        await emit("Testing unauthorized write (cross-user order update)...")
        result = await _test_unauthorized_write(client, target_url, headers_b)
        results.append(result)
        await emit(f"Unauthorized write test: {result.status} — {result.observation}")

    await emit(f"Authorization tests complete: {len(results)} tests run")
    return results


async def _login(client: httpx.AsyncClient, login_url: str, creds: dict, headers: dict) -> Optional[str]:
    """Login and return JWT token."""
    try:
        resp = await client.post(login_url, json=creds, headers=headers)
        if resp.status_code == 200:
            data = resp.json()
            return data.get("token")
    except Exception as e:
        logger.error(f"Login failed for {creds['username']}: {e}")
    return None


async def _test_idor_orders(
    client: httpx.AsyncClient,
    target_url: str,
    headers_a: dict,
    headers_b: dict,
) -> AuthzTestResult:
    """Test IDOR: User A accesses User B's order."""
    # First get User B's orders to know their IDs
    try:
        b_orders_resp = await client.get(urljoin(target_url, "/api/orders"), headers=headers_b)
        b_orders = b_orders_resp.json() if b_orders_resp.status_code == 200 else []
    except Exception:
        b_orders = []

    # Try orders by ID 1-5 with User A's token
    idor_found = False
    evidence_pairs = []

    for order_id in range(1, 6):
        try:
            resp_a = await client.get(urljoin(target_url, f"/api/orders/{order_id}"), headers=headers_a)
            await asyncio.sleep(0.1)

            if resp_a.status_code == 200:
                order = resp_a.json()
                # Check if order belongs to a different user
                order_user_id = order.get("user_id")
                # Alice is user 1, so if we see orders with user_id != 1, it's IDOR
                if order_user_id and order_user_id != 1:
                    idor_found = True
                    evidence_pairs.append({
                        "order_id": order_id,
                        "order_owner_id": order_user_id,
                        "accessed_by": "User A (ID=1)",
                        "status_code": 200,
                        "secret_notes_exposed": "secret_notes" in order,
                        "response_preview": str(order)[:200],
                    })
        except Exception:
            pass

    if idor_found:
        return AuthzTestResult(
            test_name="idor_orders_test",
            endpoint="/api/orders/{id}",
            status="SUSPICIOUS",
            observation=f"IDOR detected: User A accessed {len(evidence_pairs)} orders belonging to other users. Sensitive data (secret_notes) was exposed.",
            evidence={"idor_instances": evidence_pairs, "idor_confirmed": True},
            confidence=0.95,
            severity="HIGH",
            finding_type="IDOR",
        )
    else:
        return AuthzTestResult(
            test_name="idor_orders_test",
            endpoint="/api/orders/{id}",
            status="PASS",
            observation="No IDOR detected on order endpoints. Access properly restricted.",
            evidence={"tested_ids": list(range(1, 6))},
            confidence=0.7,
            severity="LOW",
        )


async def _test_idor_users(
    client: httpx.AsyncClient,
    target_url: str,
    headers_a: dict,
    headers_b: dict,
) -> AuthzTestResult:
    """Test IDOR: User A reads User B's profile."""
    # Alice (ID=1) tries to read Bob (ID=2)
    try:
        resp = await client.get(urljoin(target_url, "/api/users/2"), headers=headers_a)
        await asyncio.sleep(0.1)
        if resp.status_code == 200:
            profile = resp.json()
            return AuthzTestResult(
                test_name="idor_user_profile_test",
                endpoint="/api/users/{id}",
                status="SUSPICIOUS",
                observation=f"IDOR: User A (alice) read User B (bob) profile data: {list(profile.keys())}",
                evidence={
                    "status_code": 200,
                    "accessed_user_id": 2,
                    "accessed_by": "alice (ID=1)",
                    "fields_exposed": list(profile.keys()),
                    "response_preview": str(profile)[:300],
                },
                confidence=0.95,
                severity="HIGH",
                finding_type="IDOR",
            )
        else:
            return AuthzTestResult(
                test_name="idor_user_profile_test",
                endpoint="/api/users/{id}",
                status="PASS",
                observation=f"User profile access properly restricted (HTTP {resp.status_code}).",
                evidence={"status_code": resp.status_code},
                confidence=0.85,
            )
    except Exception as e:
        return AuthzTestResult(
            test_name="idor_user_profile_test",
            endpoint="/api/users/{id}",
            status="ERROR",
            observation=f"Test error: {e}",
            confidence=0.0,
        )


async def _test_vertical_escalation(
    client: httpx.AsyncClient,
    admin_url: str,
    headers_user: dict,
) -> AuthzTestResult:
    """Test vertical privilege escalation: regular user accessing admin endpoint."""
    try:
        resp = await client.get(admin_url, headers=headers_user)
        if resp.status_code == 200:
            data = resp.json()
            return AuthzTestResult(
                test_name="vertical_privilege_escalation_test",
                endpoint="/api/admin/users",
                status="SUSPICIOUS",
                observation=f"Vertical privilege escalation: Regular user accessed admin endpoint. Returned {len(data)} user records.",
                evidence={
                    "status_code": 200,
                    "records_returned": len(data) if isinstance(data, list) else 1,
                    "accessing_role": "user",
                    "required_role": "admin",
                    "response_preview": str(data)[:300],
                },
                confidence=0.98,
                severity="HIGH",
                finding_type="MISSING_AUTHZ",
            )
        elif resp.status_code in (401, 403):
            return AuthzTestResult(
                test_name="vertical_privilege_escalation_test",
                endpoint="/api/admin/users",
                status="PASS",
                observation=f"Admin endpoint properly restricted (HTTP {resp.status_code}).",
                evidence={"status_code": resp.status_code},
                confidence=0.9,
            )
        else:
            return AuthzTestResult(
                test_name="vertical_privilege_escalation_test",
                endpoint="/api/admin/users",
                status="SUSPICIOUS",
                observation=f"Unexpected response from admin endpoint: HTTP {resp.status_code}",
                evidence={"status_code": resp.status_code},
                confidence=0.5,
                severity="MEDIUM",
            )
    except Exception as e:
        return AuthzTestResult(
            test_name="vertical_privilege_escalation_test",
            endpoint="/api/admin/users",
            status="ERROR",
            observation=f"Test error: {e}",
        )


async def _test_mass_assignment(
    client: httpx.AsyncClient,
    target_url: str,
    headers_user: dict,
    token: str,
) -> AuthzTestResult:
    """Test mass assignment: regular user trying to elevate their own role."""
    # First decode token to get user ID (Bob = ID 2)
    import base64, json as jsonlib
    user_id = 2
    try:
        parts = token.split(".")
        if len(parts) >= 2:
            payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
            decoded = jsonlib.loads(base64.urlsafe_b64decode(payload))
            user_id = int(decoded.get("sub", 2))
    except Exception:
        pass

    try:
        resp = await client.put(
            urljoin(target_url, f"/api/users/{user_id}"),
            json={"role": "admin", "balance": 99999.99},
            headers=headers_user,
        )
        if resp.status_code == 200:
            # Verify if role actually changed
            verify_resp = await client.get(
                urljoin(target_url, f"/api/users/{user_id}"),
                headers=headers_user,
            )
            if verify_resp.status_code == 200:
                updated = verify_resp.json()
                role_changed = updated.get("role") == "admin"
                balance_changed = updated.get("balance") == 99999.99
                if role_changed or balance_changed:
                    return AuthzTestResult(
                        test_name="mass_assignment_test",
                        endpoint=f"/api/users/{user_id}",
                        status="SUSPICIOUS",
                        observation=f"Mass assignment: User elevated own role to admin={role_changed}, balance changed={balance_changed}.",
                        evidence={
                            "role_changed": role_changed,
                            "balance_changed": balance_changed,
                            "updated_fields": updated,
                        },
                        confidence=0.99,
                        severity="CRITICAL",
                        finding_type="MASS_ASSIGNMENT",
                    )

        return AuthzTestResult(
            test_name="mass_assignment_test",
            endpoint=f"/api/users/{user_id}",
            status="PASS",
            observation="Mass assignment protection appears effective.",
            evidence={"status_code": resp.status_code},
            confidence=0.7,
        )
    except Exception as e:
        return AuthzTestResult(
            test_name="mass_assignment_test",
            endpoint="/api/users/{id}",
            status="ERROR",
            observation=f"Test error: {e}",
        )


async def _test_unauthorized_write(
    client: httpx.AsyncClient,
    target_url: str,
    headers_b: dict,
) -> AuthzTestResult:
    """Test unauthorized write: User B tries to modify User A's order."""
    try:
        resp = await client.put(
            urljoin(target_url, "/api/orders/1"),  # Alice's order
            json={"status": "cancelled"},
            headers=headers_b,
        )
        if resp.status_code == 200:
            return AuthzTestResult(
                test_name="unauthorized_write_test",
                endpoint="/api/orders/1",
                status="SUSPICIOUS",
                observation="Unauthorized write: User B successfully modified User A's order. IDOR on write operation.",
                evidence={
                    "status_code": 200,
                    "accessing_user": "bob",
                    "target_order_owner": "alice",
                    "operation": "PUT /api/orders/1",
                },
                confidence=0.97,
                severity="HIGH",
                finding_type="IDOR_WRITE",
            )
        elif resp.status_code in (401, 403):
            return AuthzTestResult(
                test_name="unauthorized_write_test",
                endpoint="/api/orders/1",
                status="PASS",
                observation=f"Write operation properly restricted (HTTP {resp.status_code}).",
                evidence={"status_code": resp.status_code},
                confidence=0.9,
            )
        else:
            return AuthzTestResult(
                test_name="unauthorized_write_test",
                endpoint="/api/orders/1",
                status="SUSPICIOUS",
                observation=f"Unexpected response: HTTP {resp.status_code}",
                evidence={"status_code": resp.status_code},
                confidence=0.5,
            )
    except Exception as e:
        return AuthzTestResult(
            test_name="unauthorized_write_test",
            endpoint="/api/orders/1",
            status="ERROR",
            observation=f"Test error: {e}",
        )
