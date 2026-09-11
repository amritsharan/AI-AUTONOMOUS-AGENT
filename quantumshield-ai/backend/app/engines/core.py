"""Evidence, Verification, Risk, and Remediation engines for QuantumShield AI."""
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


# ─── Evidence Engine ─────────────────────────────────────────────────────────

@dataclass
class EvidenceRecord:
    test_name: str
    endpoint: str
    status: str
    observations: list[str]
    request_data: Optional[dict] = None
    response_data: Optional[dict] = None
    confidence: float = 0.5
    raw_data: dict = field(default_factory=dict)
    collected_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())


def build_evidence(
    test_name: str,
    endpoint: str,
    status: str,
    observations: list[str],
    request_data: Optional[dict] = None,
    response_data: Optional[dict] = None,
    confidence: float = 0.5,
    **kwargs,
) -> EvidenceRecord:
    """Build a structured evidence record from test results."""
    return EvidenceRecord(
        test_name=test_name,
        endpoint=endpoint,
        status=status,
        observations=observations,
        request_data=request_data,
        response_data=response_data,
        confidence=confidence,
        raw_data=kwargs,
    )


# ─── Verification Engine ──────────────────────────────────────────────────────

@dataclass
class VerificationResult:
    finding_type: str
    endpoint: str
    is_confirmed: bool
    confidence: float
    verification_evidence: list[dict]
    false_positive_reason: Optional[str] = None
    verification_method: str = ""


async def verify_idor(
    client,
    target_url: str,
    endpoint: str,
    token_a: str,
    token_b: str,
    resource_id: Any,
    owner_user: str = "User A",
    accessor_user: str = "User B",
) -> VerificationResult:
    """
    Verify an IDOR finding by cross-validating resource access.
    - User A accesses their own resource (must succeed)
    - User A accesses User B's resource (must fail for finding to be confirmed)
    """
    from urllib.parse import urljoin
    headers_a = {"Authorization": f"Bearer {token_a}", "Content-Type": "application/json"}
    headers_b = {"Authorization": f"Bearer {token_b}", "Content-Type": "application/json"}
    evidence = []

    try:
        # Step 1: Verify User B owns the resource
        resp_b = await client.get(f"{target_url}{endpoint}", headers=headers_b)
        evidence.append({
            "step": "owner_access",
            "user": owner_user,
            "status_code": resp_b.status_code,
            "success": resp_b.status_code == 200,
        })

        # Step 2: User A attempts to access
        resp_a = await client.get(f"{target_url}{endpoint}", headers=headers_a)
        evidence.append({
            "step": "unauthorized_access",
            "user": accessor_user,
            "status_code": resp_a.status_code,
            "data_exposed": resp_a.status_code == 200,
            "response_preview": resp_a.text[:200] if resp_a.status_code == 200 else "",
        })

        # Confirmation logic
        owner_success = resp_b.status_code == 200
        unauthorized_success = resp_a.status_code == 200

        if owner_success and unauthorized_success:
            # Both can access — IDOR confirmed
            return VerificationResult(
                finding_type="IDOR",
                endpoint=endpoint,
                is_confirmed=True,
                confidence=0.97,
                verification_evidence=evidence,
                verification_method="cross_user_access_test",
            )
        elif owner_success and not unauthorized_success:
            return VerificationResult(
                finding_type="IDOR",
                endpoint=endpoint,
                is_confirmed=False,
                confidence=0.9,
                verification_evidence=evidence,
                false_positive_reason=f"Unauthorized access returned {resp_a.status_code} — properly restricted.",
                verification_method="cross_user_access_test",
            )
        else:
            return VerificationResult(
                finding_type="IDOR",
                endpoint=endpoint,
                is_confirmed=False,
                confidence=0.5,
                verification_evidence=evidence,
                false_positive_reason="Inconclusive — owner access also failed.",
                verification_method="cross_user_access_test",
            )
    except Exception as e:
        return VerificationResult(
            finding_type="IDOR",
            endpoint=endpoint,
            is_confirmed=False,
            confidence=0.0,
            verification_evidence=[{"error": str(e)}],
            false_positive_reason=f"Verification error: {e}",
            verification_method="cross_user_access_test",
        )


async def verify_injection(
    client,
    target_url: str,
    endpoint: str,
    payload: str,
    method: str = "GET",
    param: str = "search",
) -> VerificationResult:
    """Verify injection vulnerability by confirming error/anomalous response."""
    from urllib.parse import urljoin
    evidence = []
    try:
        # Baseline
        baseline = await client.get(f"{target_url}{endpoint}", params={param: "normal_query"})
        evidence.append({"step": "baseline", "status": baseline.status_code})

        # Inject
        inject_resp = await client.get(f"{target_url}{endpoint}", params={param: payload})
        evidence.append({
            "step": "injection",
            "payload": payload,
            "status": inject_resp.status_code,
            "response_preview": inject_resp.text[:300],
        })

        # Confirm if anomalous
        is_anomalous = (
            inject_resp.status_code == 500 or
            any(k in inject_resp.text.lower() for k in ["sqlite", "sql", "query", "error", "syntax"])
        )

        return VerificationResult(
            finding_type="INJECTION",
            endpoint=endpoint,
            is_confirmed=is_anomalous,
            confidence=0.92 if is_anomalous else 0.3,
            verification_evidence=evidence,
            false_positive_reason=None if is_anomalous else "No anomalous response detected on verification.",
            verification_method="injection_confirmation",
        )
    except Exception as e:
        return VerificationResult(
            finding_type="INJECTION",
            endpoint=endpoint,
            is_confirmed=False,
            confidence=0.0,
            verification_evidence=[{"error": str(e)}],
            false_positive_reason=f"Error: {e}",
            verification_method="injection_confirmation",
        )


# ─── Risk Engine ──────────────────────────────────────────────────────────────

def calculate_risk_score(
    severity: str,
    confidence: float,
    exploitability: float = 0.7,
    impact: float = 0.7,
    exposure: float = 0.5,
) -> float:
    """
    Calculate transparent risk score (0-100).
    score = severity_weight * confidence * exploitability * impact * exposure_modifier
    """
    severity_weights = {
        "CRITICAL": 100.0,
        "HIGH": 75.0,
        "MEDIUM": 50.0,
        "LOW": 25.0,
        "INFORMATIONAL": 5.0,
    }
    base = severity_weights.get(severity.upper(), 25.0)
    score = base * confidence * exploitability * impact * (0.5 + exposure * 0.5)
    return round(min(100.0, max(0.0, score)), 1)


def calculate_quantum_risk_score(crypto_assets: list) -> dict:
    """
    Calculate Quantum Security Score (0-100) from discovered crypto assets.
    Higher score = MORE SECURE (inverse of classical risk score convention).
    """
    if not crypto_assets:
        return {
            "quantum_score": 50.0,
            "reasoning": "No cryptographic assets discovered. Score set to neutral.",
            "breakdown": {},
        }

    total_weight = 0.0
    weighted_security = 0.0
    breakdown = {}

    for asset in crypto_assets:
        algo = asset.get("algorithm", "Unknown")
        quantum_security = asset.get("quantum_security", "UNKNOWN")
        key_size = asset.get("key_size")

        weight = _get_asset_importance_weight(algo, asset.get("usage", ""))
        total_weight += weight

        security_value = _quantum_security_value(quantum_security, algo, key_size)
        weighted_security += weight * security_value

        breakdown[algo] = {
            "quantum_security": quantum_security,
            "security_value": security_value,
            "weight": weight,
            "risk_score": asset.get("risk_score", 0),
        }

    quantum_score = (weighted_security / total_weight) * 100 if total_weight > 0 else 50.0

    return {
        "quantum_score": round(quantum_score, 1),
        "reasoning": _generate_quantum_score_reasoning(quantum_score, breakdown),
        "breakdown": breakdown,
        "pqc_readiness_pct": _estimate_pqc_readiness(crypto_assets),
    }


def _quantum_security_value(quantum_security: str, algorithm: str, key_size: Optional[int]) -> float:
    """Map quantum security status to a 0-1 value."""
    mapping = {
        "RESISTANT": 1.0,
        "QUANTUM_RESISTANT": 1.0,
        "ADEQUATE": 0.8,
        "PARTIALLY_VULNERABLE": 0.4,
        "VULNERABLE": 0.1,
        "CRITICAL_WEAK": 0.0,
        "UNKNOWN": 0.5,
        "DEPENDS_ON_KEY_SIZE": 0.5,
        "DEPENDS_ON_HASH": 0.7,
        "ASSESS_KEY_SIZE": 0.5,
        "ASSESS_UNDERLYING_HASH": 0.6,
    }
    return mapping.get(quantum_security, 0.5)


def _get_asset_importance_weight(algorithm: str, usage: str) -> float:
    algo = algorithm.upper()
    if any(a in algo for a in ["RSA", "ECDH", "DH"]):
        return 3.0  # Key exchange — critical
    if any(a in algo for a in ["ECDSA", "DSA"]):
        return 2.5  # Signatures — very important
    if "AES" in algo:
        return 2.0  # Symmetric — important
    if "SHA" in algo:
        return 1.0  # Hash — lower weight
    return 1.5


def _estimate_pqc_readiness(assets: list) -> float:
    """Estimate PQC readiness percentage."""
    if not assets:
        return 0.0
    ready = sum(1 for a in assets if a.get("quantum_security") in ("RESISTANT", "ADEQUATE"))
    return round((ready / len(assets)) * 100, 1)


def _generate_quantum_score_reasoning(score: float, breakdown: dict) -> str:
    if score >= 80:
        return "Strong quantum security posture. Most algorithms are quantum-resistant."
    elif score >= 60:
        return "Moderate quantum security. Some algorithms need migration planning."
    elif score >= 40:
        return "Below-average quantum security. Multiple algorithms are Shor-vulnerable."
    else:
        return "Poor quantum security. Critical quantum-vulnerable algorithms detected requiring migration planning."


# ─── Remediation Engine ───────────────────────────────────────────────────────

REMEDIATION_TEMPLATES = {
    "IDOR": {
        "title": "Insecure Direct Object Reference (IDOR / BOLA)",
        "explanation": "The endpoint authenticates the user but does NOT verify that the requested resource belongs to them. Any authenticated user can access any other user's resource by guessing/enumerating the ID.",
        "root_cause": "Missing ownership/authorization check on resource access. The code verifies the user is logged in, but not that resource.owner_id == authenticated_user.id.",
        "recommended_fix": "Add explicit resource ownership verification after authentication:\n\n```python\n# After fetching the resource:\nif resource.owner_id != current_user.id and not current_user.is_admin:\n    raise HTTPException(status_code=403, detail='Access forbidden')\n```",
        "priority": "HIGH",
        "regression_description": "1. Authenticate as User A. 2. Request User A's resource → expect 200. 3. Request User B's resource → expect 403.",
    },
    "MISSING_AUTHZ": {
        "title": "Missing Authorization on Privileged Endpoint",
        "explanation": "The endpoint requires authentication (valid token) but does NOT check whether the user has the required role/permission to access privileged functionality.",
        "root_cause": "Role/permission check is absent. The endpoint verifies user identity but not user authorization level.",
        "recommended_fix": "Add role-based authorization check:\n\n```python\n@require_role('admin')  # or\nif current_user.role != 'admin':\n    raise HTTPException(status_code=403, detail='Admin access required')\n```",
        "priority": "HIGH",
        "regression_description": "1. As regular user: request admin endpoint → expect 403. 2. As admin user: request admin endpoint → expect 200.",
    },
    "SQL_INJECTION": {
        "title": "SQL Injection",
        "explanation": "User-controlled input is directly interpolated into SQL queries without parameterization. An attacker can manipulate the query to extract, modify, or delete data.",
        "root_cause": "String formatting or concatenation used for SQL query construction instead of parameterized queries/prepared statements.",
        "recommended_fix": "Use parameterized queries:\n\n```python\n# WRONG:\nquery = f\"SELECT * FROM products WHERE name LIKE '%{search}%'\"\n\n# CORRECT:\nquery = \"SELECT * FROM products WHERE name LIKE ?\"\ncursor.execute(query, (f'%{search}%',))\n\n# Or use ORM:\nProduct.query.filter(Product.name.like(f'%{search}%')).all()\n```",
        "priority": "CRITICAL",
        "regression_description": "1. Send payload ' to search endpoint → expect 200 with empty results (not 500 with SQL error). 2. Send UNION payload → expect no extra data.",
    },
    "XSS_REFLECTED": {
        "title": "Reflected Cross-Site Scripting (XSS)",
        "explanation": "User-supplied input is echoed back in the response without HTML encoding. An attacker can inject JavaScript that executes in the victim's browser.",
        "root_cause": "Missing output encoding/sanitization. User input is reflected directly in the HTML or JSON response.",
        "recommended_fix": "Encode output and use CSP:\n\n```python\nimport html\n# HTML encode all reflected user input:\nsafe_query = html.escape(user_input)\n# Or use a templating engine that auto-escapes (Jinja2, etc.)\n# Add Content-Security-Policy header\n```",
        "priority": "MEDIUM",
        "regression_description": "1. Send <script>alert(1)</script> as search query → expect HTML-encoded output in response, no raw script tag.",
    },
    "WEAK_CRYPTO": {
        "title": "Weak Cryptographic Configuration",
        "explanation": "The application uses cryptographic algorithms or configurations with insufficient security margins against current or future attacks.",
        "root_cause": "Legacy algorithm selection, insufficient key sizes, or missing migration to quantum-resistant alternatives.",
        "recommended_fix": "Upgrade cryptographic configuration:\n- Replace RSA-512/1024 with RSA-2048+ (short-term) or ML-KEM (long-term)\n- Replace SHA-1/MD5 with SHA-256 or SHA-3\n- Replace AES-128 with AES-256\n- Plan ML-KEM/ML-DSA migration for RSA/ECDSA",
        "priority": "HIGH",
        "regression_description": "1. Verify all TLS connections use TLS 1.2+ with strong cipher suites. 2. Confirm no SHA-1 or MD5 usage in hash operations.",
    },
    "MISSING_AUTH": {
        "title": "Missing Authentication",
        "explanation": "A sensitive endpoint is accessible without any authentication. Any anonymous user can access protected functionality or data.",
        "root_cause": "Authentication middleware or decorator is not applied to the route.",
        "recommended_fix": "Add authentication requirement:\n\n```python\n@router.get('/admin/stats')\n@require_auth  # Add this decorator\nasync def admin_stats(current_user = Depends(get_current_user)):\n    ...\n```",
        "priority": "CRITICAL",
        "regression_description": "1. Send unauthenticated request → expect 401. 2. Send authenticated request → expect 200.",
    },
    "INSECURE_COOKIE": {
        "title": "Insecure Session Cookie Configuration",
        "explanation": "Session cookies are missing HttpOnly, Secure, and/or SameSite flags, making them vulnerable to XSS token theft and CSRF attacks.",
        "root_cause": "Cookie flags not configured when setting session tokens.",
        "recommended_fix": "Set secure cookie flags:\n\n```python\nresponse.set_cookie(\n    'session_token',\n    value=token,\n    httponly=True,   # Prevents XSS access\n    secure=True,     # HTTPS only\n    samesite='Lax',  # CSRF protection\n    max_age=3600,\n)\n```",
        "priority": "MEDIUM",
        "regression_description": "1. Login and check cookie flags → expect HttpOnly=True, Secure=True, SameSite=Lax.",
    },
    "MASS_ASSIGNMENT": {
        "title": "Mass Assignment / Parameter Binding",
        "explanation": "The API accepts and applies arbitrary user-supplied fields without validation, allowing users to modify sensitive fields like 'role' or 'balance' that should be server-controlled.",
        "root_cause": "No field allowlist applied to user input before database update.",
        "recommended_fix": "Use explicit field allowlists:\n\n```python\n# Define what fields users can update:\nALLOWED_USER_UPDATE_FIELDS = {'email', 'display_name'}  # NOT role, balance\nupdates = {k: v for k, v in data.items() if k in ALLOWED_USER_UPDATE_FIELDS}\n```",
        "priority": "HIGH",
        "regression_description": "1. Send PUT request with role=admin → expect role not changed. 2. Send PUT request with balance=99999 → expect balance not changed.",
    },
}


def generate_remediation(
    finding_type: str,
    endpoint: str,
    additional_context: str = "",
    llm_available: bool = False,
) -> dict:
    """Generate remediation recommendation for a finding."""
    template = REMEDIATION_TEMPLATES.get(finding_type, REMEDIATION_TEMPLATES.get("MISSING_AUTH", {}))

    return {
        "finding_type": finding_type,
        "endpoint": endpoint,
        "title": template.get("title", finding_type),
        "explanation": template.get("explanation", "See security documentation."),
        "root_cause": template.get("root_cause", ""),
        "recommended_fix": template.get("recommended_fix", ""),
        "code_example": template.get("recommended_fix", ""),
        "priority": template.get("priority", "MEDIUM"),
        "regression_test_description": template.get("regression_description", ""),
        "additional_context": additional_context,
        "generated_by": "template_engine",
    }
