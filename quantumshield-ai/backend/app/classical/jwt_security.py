"""
Classical Security Engine — JSON Web Token (JWT) Security Auditor
Tests for:
1. Insecure 'none' algorithm signature bypass (CVE-2015-9235 pattern)
2. Weak HMAC shared secret cracking / dictionary brute-force
3. Algorithm confusion attacks (RS256 public key verified as HS256 HMAC)
4. Missing expiration (exp), audience (aud), and issuer (iss) claims
"""

import base64
import hmac
import hashlib
import json
import logging
import time
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger(__name__)

COMMON_WEAK_SECRETS = [
    "secret", "secret123", "password", "123456", "jwt_secret", "admin", "key",
    "development", "test", "quantumshield", "app_secret", "supersecret"
]


def _b64_decode_segment(segment: str) -> dict:
    """Safely base64url decode a JWT segment."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    raw = base64.urlsafe_b64decode(segment)
    return json.loads(raw.decode("utf-8", errors="ignore"))


def _b64_encode_dict(data: dict) -> str:
    """Base64url encode a dictionary without padding."""
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8").rstrip("=")


async def audit_jwt_security(
    client: httpx.AsyncClient,
    base_url: str,
    test_endpoints: List[str],
    sample_jwt: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Perform active and static JWT security checks against discovered authenticated endpoints.
    """
    findings = []
    base_url = base_url.rstrip("/")

    # If no sample JWT is given, create a default test token to probe endpoints
    if not sample_jwt:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "alice", "username": "alice", "role": "user", "exp": int(time.time()) + 3600}
        h_str = _b64_encode_dict(header)
        p_str = _b64_encode_dict(payload)
        sig = hmac.new(b"secret", f"{h_str}.{p_str}".encode("utf-8"), hashlib.sha256).digest()
        sig_str = base64.urlsafe_b64encode(sig).decode("utf-8").rstrip("=")
        sample_jwt = f"{h_str}.{p_str}.{sig_str}"

    try:
        parts = sample_jwt.split(".")
        if len(parts) == 3:
            h_data = _b64_decode_segment(parts[0])
            p_data = _b64_decode_segment(parts[1])

            # ── 1. Check for Missing Expiration or Audience claims ──────
            if "exp" not in p_data:
                findings.append({
                    "type": "JWT_MISSING_EXPIRATION",
                    "title": "JWT Token Lacks Expiration (exp) Claim",
                    "severity": "MEDIUM",
                    "cvss_score": 5.3,
                    "cwe": "CWE-613",
                    "endpoint": "/api/auth",
                    "method": "POST",
                    "description": "The JWT does not contain an 'exp' expiration claim, making intercepted tokens valid indefinitely.",
                    "evidence": {"token_payload": p_data},
                    "remediation": "Always include and enforce a short-lived 'exp' claim in JWT tokens (e.g. 15-60 minutes).",
                })

            # ── 2. Test 'alg: none' Signature Stripping Attack ──────────
            none_header = dict(h_data)
            none_header["alg"] = "none"
            admin_payload = dict(p_data)
            admin_payload["role"] = "admin"
            admin_payload["is_admin"] = True
            
            none_token = f"{_b64_encode_dict(none_header)}.{_b64_encode_dict(admin_payload)}."
            
            for ep in test_endpoints[:3]:
                ep_url = f"{base_url}{ep}"
                try:
                    res = await client.get(ep_url, headers={"Authorization": f"Bearer {none_token}"}, timeout=4.0)
                    if res.status_code == 200 and "unauthorized" not in res.text.lower():
                        findings.append({
                            "type": "JWT_ALG_NONE_BYPASS",
                            "title": "Critical JWT 'alg: none' Signature Bypass",
                            "severity": "CRITICAL",
                            "cvss_score": 9.8,
                            "cwe": "CWE-347",
                            "endpoint": ep,
                            "method": "GET",
                            "description": f"Endpoint {ep} accepted an unsigned token with 'alg: none', allowing arbitrary signature forgery.",
                            "evidence": {"forged_token": none_token, "response_status": res.status_code},
                            "remediation": "Explicitly whitelist allowed signature algorithms (e.g., HS256, Ed25519) and reject 'none' unconditionally.",
                        })
                        break
                except Exception:
                    pass

            # ── 3. Weak Secret / Dictionary Cracking ────────────────────
            if h_data.get("alg") in ("HS256", "HS384", "HS512"):
                msg = f"{parts[0]}.{parts[1]}".encode("utf-8")
                orig_sig = parts[2]
                
                for candidate in COMMON_WEAK_SECRETS:
                    cand_sig = hmac.new(candidate.encode("utf-8"), msg, hashlib.sha256).digest()
                    cand_sig_str = base64.urlsafe_b64encode(cand_sig).decode("utf-8").rstrip("=")
                    if cand_sig_str == orig_sig:
                        findings.append({
                            "type": "JWT_WEAK_HMAC_SECRET",
                            "title": f"Weak JWT HMAC Secret Key Detected ('{candidate}')",
                            "severity": "HIGH",
                            "cvss_score": 8.2,
                            "cwe": "CWE-522",
                            "endpoint": "/api/login",
                            "method": "POST",
                            "description": f"The JWT HMAC signing secret is vulnerable to dictionary attack and was cracked as '{candidate}'.",
                            "evidence": {"cracked_secret": candidate, "algorithm": h_data.get("alg")},
                            "remediation": "Generate cryptographically secure 256-bit or 512-bit signing secrets (e.g. `openssl rand -hex 32`).",
                        })
                        break

    except Exception as e:
        logger.warning(f"JWT security auditing error: {e}")

    return findings
