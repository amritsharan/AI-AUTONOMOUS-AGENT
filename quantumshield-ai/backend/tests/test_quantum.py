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


def test_quantum_hardware_backends():
    from app.quantum.quantum_hardware import list_available_backends
    backends = list_available_backends()
    assert len(backends) >= 3
    assert any(b["name"] == "ibm_brisbane" for b in backends)
    assert any(b["is_simulator"] is True for b in backends)


def test_quantum_comparative_benchmark():
    from app.quantum.quantum_hardware import run_comparative_shor
    result = asyncio.run(run_comparative_shor(N=15, backend_name="ibm_brisbane", shots=1024))
    assert result["N"] == 15
    assert result["factors_found"] == (3, 5)
    assert result["period_detected"] == 4
    assert "ideal" in result["comparative_results"]
    assert "noisy" in result["comparative_results"]
    assert "real_qpu" in result["comparative_results"]
    assert "quantum_security_interpretation" in result
    assert "RSA-2048" in result["quantum_security_interpretation"]["threatened_algorithm"]


def test_simon_algorithm():
    from app.quantum.simon_demo import run_simon_demo
    result = asyncio.run(run_simon_demo(hidden_string="11", shots=1024))
    assert result.hidden_string_target == "11"
    assert result.hidden_string_found == "11"
    assert result.success is True
    assert result.num_qubits == 4


def test_qpe_primitive():
    from app.quantum.qpe_demo import run_qpe_demo
    result = asyncio.run(run_qpe_demo(phase_theta=0.25, precision_qubits=3, shots=1024))
    assert result.target_phase_theta == 0.25
    assert result.estimated_phase_theta == 0.25
    assert result.phase_error == 0.0
    assert result.most_probable_bitstring == "010"


def test_qkd_bb84_secure_channel():
    from app.quantum.qkd_sim import simulate_bb84
    # Clean channel without Eve
    result = simulate_bb84(num_photons=100, eve_present=False, channel_noise=0.01)
    assert result.total_photons == 100
    assert result.qber < 11.0
    assert result.is_key_secure is True
    assert result.status == "KEY_ESTABLISHED"
    assert len(result.final_shared_key_hex) > 0


def test_qkd_bb84_eavesdropper_detected():
    from app.quantum.qkd_sim import simulate_bb84
    # Channel with Eve intercepting 100% of photons
    result = simulate_bb84(num_photons=120, eve_present=True, eve_intercept_prob=1.0, channel_noise=0.0)
    assert result.qber >= 11.0
    assert result.is_key_secure is False
    assert result.status == "EAVESDROPPER_DETECTED_ABORT"


def test_qkd_e91_bell_inequality():
    from app.quantum.qkd_sim import simulate_e91
    # Entangled without Eve -> S > 2.0
    result = simulate_e91(num_pairs=200, eve_present=False)
    assert result.chsh_correlation_s > 2.0
    assert result.is_quantum_entangled is True
    assert result.eavesdropper_detected is False

    # Entangled with Eve -> S <= 2.0
    result_eve = simulate_e91(num_pairs=200, eve_present=True)
    assert result_eve.chsh_correlation_s <= 2.0
    assert result_eve.is_quantum_entangled is False
    assert result_eve.eavesdropper_detected is True
