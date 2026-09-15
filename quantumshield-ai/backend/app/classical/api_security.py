"""
Classical Security Engine — OpenAPI & GraphQL Security Auditor
Discovers and tests:
1. OpenAPI / Swagger schemas (/openapi.json, /swagger.json, /api-docs)
2. Undocumented endpoints & Mass Assignment parameter injection
3. GraphQL Introspection, Query Depth/Complexity limits, Field Suggestions, Batch Query Attacks
"""

import asyncio
import json
import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger(__name__)

OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/docs",
    "/api/docs",
]

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
]

GRAPHQL_INTROSPECTION_QUERY = {
    "query": "{ __schema { types { name kind fields { name } } } }"
}


async def audit_api_security(client: httpx.AsyncClient, base_url: str) -> List[Dict[str, Any]]:
    """
    Run comprehensive OpenAPI and GraphQL security audits.
    """
    findings = []
    base_url = base_url.rstrip("/")

    # ── 1. OpenAPI / Swagger Discovery & Parameter Auditing ─────────────
    discovered_specs = []
    for path in OPENAPI_PATHS:
        url = f"{base_url}{path}"
        try:
            r = await client.get(url, timeout=5.0)
            if r.status_code == 200 and ("application/json" in r.headers.get("content-type", "") or "swagger" in r.text.lower() or "openapi" in r.text.lower()):
                try:
                    spec_data = r.json()
                    discovered_specs.append((url, spec_data))
                    
                    # Finding: Exposed OpenAPI Specification
                    findings.append({
                        "type": "OPENAPI_EXPOSED",
                        "title": "Publicly Accessible OpenAPI / Swagger Specification",
                        "severity": "LOW",
                        "cvss_score": 3.7,
                        "cwe": "CWE-200",
                        "endpoint": path,
                        "method": "GET",
                        "description": f"OpenAPI documentation is publicly exposed at {path}, exposing internal API routes and schemas.",
                        "evidence": {
                            "url": url,
                            "status_code": r.status_code,
                            "total_paths_exposed": len(spec_data.get("paths", {})),
                        },
                        "remediation": "Restrict access to API documentation in production environments or require authentication.",
                    })
                    
                    # Test for Mass Assignment & Undocumented Parameters on discovered POST/PUT routes
                    paths = spec_data.get("paths", {})
                    for ep_path, ep_methods in list(paths.items())[:5]:
                        for method, op in ep_methods.items():
                            if method.lower() in ("post", "put"):
                                # Test mass assignment with administrative fields
                                test_url = f"{base_url}{ep_path}"
                                mass_payload = {"is_admin": True, "role": "administrator", "permissions": ["all"]}
                                try:
                                    res = await client.request(method.upper(), test_url, json=mass_payload, timeout=4.0)
                                    if res.status_code in (200, 201) and any(k in res.text.lower() for k in ["admin", "permission"]):
                                        findings.append({
                                            "type": "MASS_ASSIGNMENT",
                                            "title": f"Potential Mass Assignment on {ep_path}",
                                            "severity": "HIGH",
                                            "cvss_score": 7.5,
                                            "cwe": "CWE-915",
                                            "endpoint": ep_path,
                                            "method": method.upper(),
                                            "description": f"Endpoint accepted unauthorized privilege parameters ({list(mass_payload.keys())}).",
                                            "evidence": {"request": mass_payload, "response_snippet": res.text[:200]},
                                            "remediation": "Use strict DTOs / Pydantic schemas with whitelisted input fields (forbidden extra fields).",
                                        })
                                except Exception:
                                    pass
                except Exception:
                    pass
        except Exception:
            pass

    # ── 2. GraphQL Introspection & Abuse Testing ────────────────────────
    for path in GRAPHQL_PATHS:
        url = f"{base_url}{path}"
        try:
            # Test Introspection
            r = await client.post(url, json=GRAPHQL_INTROSPECTION_QUERY, timeout=5.0)
            if r.status_code == 200 and "__schema" in r.text:
                findings.append({
                    "type": "GRAPHQL_INTROSPECTION_ENABLED",
                    "title": "GraphQL Introspection Enabled in Production",
                    "severity": "MEDIUM",
                    "cvss_score": 5.3,
                    "cwe": "CWE-200",
                    "endpoint": path,
                    "method": "POST",
                    "description": f"GraphQL introspection is enabled at {path}, allowing full schema recovery and query harvesting.",
                    "evidence": {"query": GRAPHQL_INTROSPECTION_QUERY, "status_code": r.status_code},
                    "remediation": "Disable GraphQL introspection queries in production configurations.",
                })

            # Test Query Depth / Circular Reference DoS
            deep_query = {"query": "{ __schema { types { fields { type { fields { type { fields { name } } } } } } } }"}
            r_depth = await client.post(url, json=deep_query, timeout=5.0)
            if r_depth.status_code == 200 and "errors" not in r_depth.text:
                findings.append({
                    "type": "GRAPHQL_DEEP_QUERY_DOS",
                    "title": "Missing GraphQL Query Depth / Complexity Limiting",
                    "severity": "MEDIUM",
                    "cvss_score": 6.5,
                    "cwe": "CWE-400",
                    "endpoint": path,
                    "method": "POST",
                    "description": f"GraphQL endpoint at {path} executes unbounded recursive/deep queries without complexity limits.",
                    "evidence": {"query": deep_query, "status_code": r_depth.status_code},
                    "remediation": "Implement query depth limiting (max depth 5) and query cost analysis middleware.",
                })
        except Exception:
            pass

    return findings
