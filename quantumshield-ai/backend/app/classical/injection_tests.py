"""
Classical Security Engine — Injection Tests
Non-destructive detection of SQL injection, XSS, and template injection indicators.
"""
import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from app.policy.engine import PolicyEngine, ScopeConfig

logger = logging.getLogger(__name__)


@dataclass
class InjectionTestResult:
    test_name: str
    endpoint: str
    status: str
    observation: str
    evidence: dict = field(default_factory=dict)
    confidence: float = 0.0
    severity: str = "MEDIUM"
    injection_type: str = ""


# Safe, non-destructive SQL injection detection payloads
SQL_DETECTION_PAYLOADS = [
    ("'", "syntax_error"),
    ("1' OR '1'='1", "tautology"),
    ("1 AND 1=1", "numeric_tautology"),
    ("' UNION SELECT NULL--", "union_probe"),
]

# XSS detection payloads (safe - just looking for reflection)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "javascript:alert(1)",
    "'\"><script>alert(1)</script>",
]

# SSTI detection probes
SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%=7*7%>",
]


async def run_injection_tests(
    target_url: str,
    scope: ScopeConfig,
    policy: PolicyEngine,
    scan_id: str = "",
    event_callback=None,
) -> list[InjectionTestResult]:
    """Run all injection detection tests."""
    results = []

    async def emit(msg: str):
        logger.info(f"[INJECT] {msg}")
        if event_callback:
            await event_callback("injection_test", msg)

    await emit("Starting injection security tests...")
    timeout = httpx.Timeout(10.0)
    headers = {"User-Agent": "QuantumShield-SecurityScanner/1.0"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        # SQL Injection on products search
        await emit("Testing SQL injection on search endpoint...")
        products_url = urljoin(target_url, "/api/products")
        decision = policy.validate("injection_test_sql", products_url, scope, scan_id)
        if decision.allowed:
            result = await _test_sql_injection(client, products_url, headers)
            results.append(result)
            await emit(f"SQL injection test: {result.status} — {result.observation}")

        # XSS on search endpoint
        await emit("Testing XSS on search endpoint...")
        search_url = urljoin(target_url, "/api/search")
        decision = policy.validate("injection_test_xss", search_url, scope, scan_id)
        if decision.allowed:
            result = await _test_xss_reflected(client, search_url, headers)
            results.append(result)
            await emit(f"XSS reflection test: {result.status} — {result.observation}")

        # SSTI detection
        await emit("Testing template injection indicators...")
        decision = policy.validate("injection_test_ssti", search_url, scope, scan_id)
        if decision.allowed:
            result = await _test_ssti(client, search_url, headers)
            results.append(result)
            await emit(f"SSTI test: {result.status} — {result.observation}")

        # SQL injection via error messages
        await emit("Testing error-based SQL injection indicators...")
        result = await _test_sql_error_based(client, products_url, headers)
        results.append(result)
        await emit(f"Error-based SQLi test: {result.status} — {result.observation}")

    await emit(f"Injection tests complete: {len(results)} tests run")
    return results


async def _test_sql_injection(client: httpx.AsyncClient, url: str, headers: dict) -> InjectionTestResult:
    """Test for SQL injection via response anomalies."""
    baseline_resp = None
    try:
        baseline_resp = await client.get(url, params={"search": "laptop"}, headers=headers)
        baseline_count = len(baseline_resp.json()) if baseline_resp.status_code == 200 else 0
    except Exception:
        baseline_count = 0

    evidence = []
    for payload, payload_type in SQL_DETECTION_PAYLOADS:
        try:
            resp = await client.get(url, params={"search": payload}, headers=headers)
            await asyncio.sleep(0.2)
            body = resp.text

            # Error-based detection
            sql_error_indicators = [
                "syntax error", "sqlite_error", "ORA-", "mysql_fetch", "pg_query",
                "near \"", "SQLITE_", "sql syntax", "unclosed quotation", "unterminated"
            ]
            error_found = any(ind.lower() in body.lower() for ind in sql_error_indicators)

            # Union-based detection
            union_indicators = ["null", "union", "column"]

            if error_found or resp.status_code == 500:
                evidence.append({
                    "payload": payload,
                    "type": payload_type,
                    "status_code": resp.status_code,
                    "error_detected": error_found,
                    "response_preview": body[:300],
                })

            await asyncio.sleep(0.1)
        except Exception:
            pass

    if evidence:
        return InjectionTestResult(
            test_name="sql_injection_test",
            endpoint=url,
            status="SUSPICIOUS",
            observation=f"SQL injection indicators detected with {len(evidence)} payloads. Error messages or anomalous responses observed.",
            evidence={"sql_evidence": evidence},
            confidence=0.9,
            severity="CRITICAL",
            injection_type="SQL_INJECTION",
        )
    return InjectionTestResult(
        test_name="sql_injection_test",
        endpoint=url,
        status="PASS",
        observation="No SQL injection indicators detected.",
        evidence={"payloads_tested": len(SQL_DETECTION_PAYLOADS)},
        confidence=0.7,
        severity="CRITICAL",
        injection_type="SQL_INJECTION",
    )


async def _test_sql_error_based(client: httpx.AsyncClient, url: str, headers: dict) -> InjectionTestResult:
    """Test error-based SQL injection — looks for database errors in error responses."""
    try:
        resp = await client.get(url, params={"search": "'"}, headers=headers)
        body = resp.text
        if resp.status_code == 500 and ("query" in body.lower() or "sqlite" in body.lower() or "sql" in body.lower()):
            return InjectionTestResult(
                test_name="sql_error_based_test",
                endpoint=url,
                status="SUSPICIOUS",
                observation=f"Server returned 500 with SQL query exposed in error response. Query: {body[:400]}",
                evidence={"status_code": 500, "error_body": body[:500], "query_exposed": "query" in body.lower()},
                confidence=0.98,
                severity="CRITICAL",
                injection_type="SQL_INJECTION_ERROR_BASED",
            )
    except Exception as e:
        return InjectionTestResult(
            test_name="sql_error_based_test",
            endpoint=url,
            status="ERROR",
            observation=f"Test error: {e}",
        )
    return InjectionTestResult(
        test_name="sql_error_based_test",
        endpoint=url,
        status="PASS",
        observation="No SQL error disclosure detected.",
        evidence={},
        confidence=0.8,
    )


async def _test_xss_reflected(client: httpx.AsyncClient, url: str, headers: dict) -> InjectionTestResult:
    """Test for reflected XSS: payload echoed back without sanitization."""
    evidence = []
    for payload in XSS_PAYLOADS:
        try:
            resp = await client.get(url, params={"q": payload}, headers=headers)
            body = resp.text

            # Check if payload is reflected unencoded
            if payload in body:
                evidence.append({
                    "payload": payload,
                    "reflected": True,
                    "encoded": False,
                    "status_code": resp.status_code,
                    "response_preview": body[:300],
                })
            # Check for HTML-encoded version
            encoded_payload = payload.replace("<", "&lt;").replace(">", "&gt;")
            if encoded_payload in body and payload not in body:
                pass  # Properly encoded — good
            await asyncio.sleep(0.1)
        except Exception:
            pass

    if evidence:
        return InjectionTestResult(
            test_name="xss_reflected_test",
            endpoint=url,
            status="SUSPICIOUS",
            observation=f"Reflected XSS: {len(evidence)} payloads reflected without encoding in response body.",
            evidence={"xss_evidence": evidence},
            confidence=0.92,
            severity="MEDIUM",
            injection_type="XSS_REFLECTED",
        )
    return InjectionTestResult(
        test_name="xss_reflected_test",
        endpoint=url,
        status="PASS",
        observation="No unencoded XSS reflection detected.",
        evidence={"payloads_tested": len(XSS_PAYLOADS)},
        confidence=0.75,
        injection_type="XSS_REFLECTED",
    )


async def _test_ssti(client: httpx.AsyncClient, url: str, headers: dict) -> InjectionTestResult:
    """Test for server-side template injection indicators."""
    for payload in SSTI_PAYLOADS:
        try:
            resp = await client.get(url, params={"q": payload}, headers=headers)
            body = resp.text
            # If {{7*7}} was processed and 49 appears in response
            if "49" in body and payload not in body:
                return InjectionTestResult(
                    test_name="ssti_test",
                    endpoint=url,
                    status="SUSPICIOUS",
                    observation=f"Possible SSTI: Payload '{payload}' was processed (result 49 found in response).",
                    evidence={"payload": payload, "processed": True, "response_preview": body[:300]},
                    confidence=0.85,
                    severity="CRITICAL",
                    injection_type="SSTI",
                )
            await asyncio.sleep(0.1)
        except Exception:
            pass
    return InjectionTestResult(
        test_name="ssti_test",
        endpoint=url,
        status="PASS",
        observation="No SSTI indicators detected.",
        evidence={"payloads_tested": len(SSTI_PAYLOADS)},
        confidence=0.7,
        injection_type="SSTI",
    )
