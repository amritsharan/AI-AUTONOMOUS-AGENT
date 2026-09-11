"""
Unit tests for Core Engines: Evidence, Risk, Remediation, and Quantum Risk Scoring.
"""
import pytest
from app.engines.core import (
    build_evidence,
    calculate_risk_score,
    calculate_quantum_risk_score,
    generate_remediation,
)


def test_build_evidence():
    evidence = build_evidence(
        test_name="authz_test_idor",
        endpoint="/api/orders/1",
        status="detected",
        observations=["Access granted to order belonging to user B"],
        confidence=0.95,
        target="http://localhost:8080",
    )
    assert evidence.test_name == "authz_test_idor"
    assert evidence.endpoint == "/api/orders/1"
    assert evidence.confidence == 0.95
    assert len(evidence.observations) == 1
    assert evidence.raw_data["target"] == "http://localhost:8080"


def test_calculate_risk_score():
    crit_score = calculate_risk_score("CRITICAL", confidence=1.0, exploitability=1.0, impact=1.0, exposure=1.0)
    assert crit_score == 100.0

    low_score = calculate_risk_score("LOW", confidence=0.5, exploitability=0.5, impact=0.5, exposure=0.5)
    assert 0.0 < low_score < crit_score


def test_calculate_quantum_risk_score_vulnerable():
    assets = [
        {"algorithm": "RSA-2048", "quantum_security": "VULNERABLE", "key_size": 2048, "usage": "TLS"},
        {"algorithm": "ECDSA", "quantum_security": "VULNERABLE", "key_size": 256, "usage": "Signatures"},
    ]
    res = calculate_quantum_risk_score(assets)
    assert res["quantum_score"] < 40.0  # High quantum risk = low security score


def test_calculate_quantum_risk_score_safe():
    assets = [
        {"algorithm": "ML-KEM-768", "quantum_security": "QUANTUM_RESISTANT", "key_size": 768, "usage": "Key Exchange"},
        {"algorithm": "AES-256", "quantum_security": "QUANTUM_RESISTANT", "key_size": 256, "usage": "Encryption"},
    ]
    res = calculate_quantum_risk_score(assets)
    assert res["quantum_score"] >= 80.0  # Quantum safe assets = high security score


def test_generate_remediation():
    rem = generate_remediation(
        finding_type="IDOR",
        endpoint="/api/orders/1",
        additional_context="Missing ownership check on requested order ID",
    )
    assert rem is not None
    assert rem["finding_type"] == "IDOR"
    assert "recommended_fix" in rem
    assert len(rem["recommended_fix"]) > 10
