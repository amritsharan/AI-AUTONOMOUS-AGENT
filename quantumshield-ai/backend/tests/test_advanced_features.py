"""
Tests for Advanced Security & Quantum Features:
1. Hybrid PQC TLS (X25519 + ML-KEM-768)
2. CycloneDX v1.6 & SPDX 3.0 CBOM Export
3. OpenAPI & GraphQL Security Auditing
4. JWT Security Auditing (alg:none, weak secrets)
5. WebSocket & CSWSH Auditing
6. Scan Diff & Regression Tracking
7. Attack Surface Dependency Graph
"""

import pytest
import asyncio
import httpx
from app.quantum.hybrid_tls import assess_hybrid_pqc_tls
from app.quantum.cbom_export import export_cyclonedx_cbom, export_spdx_cbom
from app.classical.jwt_security import audit_jwt_security
from app.services.scan_diff import compute_scan_diff
from app.services.attack_graph import generate_attack_graph
from app.database.models import Finding, FindingStatus, Severity, FindingType, Endpoint, CryptoAsset


def test_hybrid_pqc_tls_assessment():
    res = assess_hybrid_pqc_tls("http://localhost:8080")
    assert "quantum_risk_verdict" in res
    assert "known_pqc_groups" in res
    assert "X25519MLKEM768" in res["known_pqc_groups"]


def test_cyclonedx_cbom_export():
    crypto_assets = [
        {"algorithm": "RSA-2048", "key_size": 2048, "usage": "key_exchange", "quantum_vulnerable": True, "file_path": "server.py"},
        {"algorithm": "ML-KEM-768", "key_size": 768, "usage": "key_encapsulation", "quantum_vulnerable": False, "file_path": "tls.py"}
    ]
    cbom = export_cyclonedx_cbom("TestApp", "https://test.local", crypto_assets)
    assert cbom["bomFormat"] == "CycloneDX"
    assert cbom["specVersion"] == "1.6"
    assert len(cbom["components"]) == 2
    assert cbom["components"][0]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert cbom["components"][1]["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3


def test_spdx_cbom_export():
    crypto_assets = [
        {"algorithm": "ECDSA-P256", "key_size": 256, "usage": "digital_signature", "quantum_vulnerable": True, "file_path": "auth.py"}
    ]
    spdx = export_spdx_cbom("TestApp", "https://test.local", crypto_assets)
    assert spdx["spdxVersion"] == "SPDX-3.0"
    assert len(spdx["packages"]) == 1
    assert "ECDSA-P256" in spdx["packages"][0]["name"]


def test_jwt_security_auditor_sync():
    async def _run():
        async with httpx.AsyncClient() as client:
            return await audit_jwt_security(client, "http://localhost:8080", ["/api/users/1/profile"])
    findings = asyncio.run(_run())
    assert isinstance(findings, list)


def test_scan_diff_service():
    f1 = Finding(
        id="f-1", scan_id="s-1", title="SQL Injection",
        category="INJECTION", finding_type=FindingType.CLASSICAL, severity=Severity.HIGH,
        risk_score=8.5, endpoint="/api/products", status=FindingStatus.OPEN
    )
    f2 = Finding(
        id="f-2", scan_id="s-1", title="Missing Headers",
        category="CONFIG", finding_type=FindingType.CLASSICAL, severity=Severity.LOW,
        risk_score=3.1, endpoint="/", status=FindingStatus.OPEN
    )
    f3 = Finding(
        id="f-3", scan_id="s-2", title="SQL Injection",
        category="INJECTION", finding_type=FindingType.CLASSICAL, severity=Severity.HIGH,
        risk_score=8.5, endpoint="/api/products", status=FindingStatus.FIXED
    )
    f4 = Finding(
        id="f-4", scan_id="s-2", title="IDOR",
        category="AUTHZ", finding_type=FindingType.CLASSICAL, severity=Severity.HIGH,
        risk_score=7.5, endpoint="/api/users/2", status=FindingStatus.OPEN
    )

    diff = compute_scan_diff(current_findings=[f3, f4], previous_findings=[f1, f2])
    assert diff["summary"]["new_count"] == 1  # IDOR is new
    assert diff["summary"]["fixed_count"] == 2  # Missing Headers is gone, SQLi is remediated


def test_attack_surface_graph_generator():
    endpoints = [
        Endpoint(id="ep-1", scan_id="s-1", path="/api/login", method="POST", auth_required=False),
        Endpoint(id="ep-2", scan_id="s-1", path="/api/products", method="GET", auth_required=False)
    ]
    findings = [
        Finding(id="f-1", scan_id="s-1", title="SQL Injection", category="INJECTION", finding_type=FindingType.CLASSICAL, severity=Severity.HIGH, endpoint="/api/products")
    ]
    crypto = [
        CryptoAsset(id="ca-1", scan_id="s-1", algorithm="RSA-2048", key_size=2048, quantum_attack="shor", usage="TLS")
    ]

    graph = generate_attack_graph("Test Target", "http://localhost:8080", endpoints, findings, crypto)
    assert "nodes" in graph
    assert "links" in graph
    assert len(graph["nodes"]) >= 4
    assert len(graph["links"]) >= 3
