"""
Unit tests for Quantum Security Engine.
Tests Shor assessment & simulation, Grover assessment & simulation, and PQC readiness.
"""
import asyncio
import pytest
from app.quantum.shor_demo import assess_shor_threat, run_shor_demo
from app.quantum.grover_demo import assess_grover_threat, run_grover_demo
from app.quantum.pqc_assessment import assess_pqc_readiness, PQC_ALGORITHMS


def test_shor_assessment_rsa():
    assessment = assess_shor_threat("RSA", key_size=2048)
    assert assessment.shor_applicable is True
    assert assessment.quantum_resistant is False
    assert assessment.current_practical_break is False  # No CRQC exists today
    assert "ML-KEM" in assessment.recommendation or "Kyber" in assessment.recommendation


def test_shor_assessment_ecc():
    assessment = assess_shor_threat("ECDSA", key_size=256)
    assert assessment.shor_applicable is True
    assert assessment.quantum_resistant is False
    assert assessment.current_practical_break is False


def test_grover_assessment_aes128():
    assessment = assess_grover_threat("AES-128", key_size=128)
    assert assessment.effective_quantum_security_bits == 64
    assert assessment.is_sufficient is False
    assert assessment.migration_needed is True
    assert "AES-256" in assessment.recommendation


def test_grover_assessment_aes256():
    assessment = assess_grover_threat("AES-256", key_size=256)
    assert assessment.effective_quantum_security_bits == 128
    assert assessment.is_sufficient is True
    assert assessment.migration_needed is False


def test_shor_toy_circuit_n15():
    res = asyncio.run(run_shor_demo(15))
    assert res.N == 15
    assert res.success is True
    assert res.factors_found == (3, 5)
    assert res.num_qubits == 4
    assert res.shots == 1024


def test_grover_toy_circuit():
    res = asyncio.run(run_grover_demo(search_space_size=4, marked_item=3))
    assert res.search_space_size == 4
    assert res.marked_item == 3
    assert res.item_found is True
    assert res.found_item == 3


def test_pqc_readiness_assessment():
    crypto_inventory = [
        {"algorithm": "RSA", "key_size": 2048, "usage": "TLS Handshake"},
        {"algorithm": "AES-128", "key_size": 128, "usage": "Data Encryption"},
        {"algorithm": "ML-KEM-768", "key_size": 768, "usage": "Key Encapsulation"},
    ]
    pqc = assess_pqc_readiness(crypto_inventory)
    assert pqc["total_algorithms_assessed"] == 3
    assert pqc["quantum_vulnerable_count"] >= 1
    assert 0 <= pqc["pqc_readiness_score"] <= 100
