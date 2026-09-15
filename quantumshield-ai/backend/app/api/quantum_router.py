"""Quantum API router — Shor/Grover demos and quantum analysis."""
from datetime import datetime
from typing import Optional
from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class ShorDemoRequest(BaseModel):
    N: int = 15  # Must be 15, 21, or 35


class GroverDemoRequest(BaseModel):
    search_space_size: int = 16
    marked_item: Optional[int] = None


@router.post("/shor-demo")
async def shor_demo(request: ShorDemoRequest):
    """Run a toy Shor's algorithm demonstration on a small factoring problem."""
    from app.quantum.shor_demo import run_shor_demo, TOY_FACTORING_PROBLEMS
    supported = list(TOY_FACTORING_PROBLEMS.keys())
    if request.N not in supported:
        return {"error": f"N must be one of {supported}", "supported": supported}
    result = await run_shor_demo(request.N)
    return {
        "N": result.N,
        "factors_found": result.factors_found,
        "success": result.success,
        "num_qubits": result.num_qubits,
        "execution_time_ms": result.execution_time_ms,
        "simulator": result.simulator,
        "circuit_description": result.circuit_description,
        "measurement_results": result.measurement_results,
        "counts": result.counts,
        "shots": result.shots,
        "note": result.note,
        "error": result.error,
    }


@router.post("/grover-demo")
async def grover_demo(request: GroverDemoRequest):
    """Run a Grover's algorithm demonstration on a small search space."""
    from app.quantum.grover_demo import run_grover_demo
    result = await run_grover_demo(request.search_space_size, request.marked_item)
    return {
        "search_space_size": result.search_space_size,
        "marked_item": result.marked_item,
        "item_found": result.item_found,
        "found_item": result.found_item,
        "num_qubits": result.num_qubits,
        "optimal_iterations": result.optimal_iterations,
        "classical_complexity": result.classical_complexity,
        "quantum_complexity": result.quantum_complexity,
        "execution_time_ms": result.execution_time_ms,
        "simulator": result.simulator,
        "circuit_description": result.circuit_description,
        "measurement_results": result.measurement_results,
        "counts": result.counts,
        "shots": result.shots,
        "speedup_factor": result.speedup_factor,
        "note": result.note,
        "error": result.error,
    }


@router.post("/shor-assessment")
async def shor_assessment(algorithm: str, key_size: Optional[int] = None):
    """Get Shor's algorithm threat assessment for a cryptographic algorithm."""
    from app.quantum.shor_demo import assess_shor_threat
    result = assess_shor_threat(algorithm, key_size)
    return {
        "algorithm": result.algorithm,
        "key_size": result.key_size,
        "shor_applicable": result.shor_applicable,
        "current_practical_break": result.current_practical_break,
        "quantum_resistant": result.quantum_resistant,
        "mathematical_problem": result.mathematical_problem,
        "classical_complexity": result.classical_complexity,
        "quantum_complexity": result.quantum_complexity,
        "estimated_qubits_required": result.estimated_qubits_required,
        "practical_threat_timeline": result.practical_threat_timeline,
        "recommendation": result.recommendation,
    }


@router.post("/grover-assessment")
async def grover_assessment(algorithm: str, key_size: Optional[int] = None):
    """Get Grover's algorithm threat assessment for a symmetric algorithm."""
    from app.quantum.grover_demo import assess_grover_threat
    result = assess_grover_threat(algorithm, key_size)
    return {
        "algorithm": result.algorithm,
        "key_size_bits": result.key_size_bits,
        "classical_key_space": result.classical_key_space,
        "classical_search_complexity": result.classical_search_complexity,
        "grover_quantum_complexity": result.grover_quantum_complexity,
        "effective_quantum_security_bits": result.effective_quantum_security_bits,
        "is_sufficient": result.is_sufficient,
        "recommendation": result.recommendation,
        "migration_needed": result.migration_needed,
    }


@router.get("/algorithms")
async def quantum_algorithm_database():
    """Return the quantum threat assessment database for all known algorithms."""
    from app.quantum.crypto_discovery import ALGORITHM_QUANTUM_DB
    return {
        "algorithms": ALGORITHM_QUANTUM_DB,
        "notes": {
            "shor": "Shor's algorithm threatens public-key cryptography (RSA, ECC, DH). Requires a Cryptographically Relevant Quantum Computer (CRQC) — not available today.",
            "grover": "Grover's algorithm threatens symmetric cryptography and hashes by providing a quadratic speedup. AES-256 remains adequate.",
            "crqc_timeline": "NIST estimates 10-20+ years before a practical CRQC. Migration should begin now for long-lived data.",
        }
    }


@router.get("/pqc-standards")
async def pqc_standards():
    """Return information about NIST post-quantum cryptography standards."""
    from app.quantum.pqc_assessment import PQC_ALGORITHMS
    return {
        "standards": {
            name: {
                "name": algo.name,
                "full_name": algo.full_name,
                "nist_standard": algo.nist_standard,
                "category": algo.category,
                "security_levels": algo.security_levels,
                "replaces": algo.classical_equivalent,
                "performance": algo.performance,
                "maturity": algo.maturity,
                "description": algo.description,
            }
            for name, algo in PQC_ALGORITHMS.items()
        }
    }


class PQCShieldTestRequest(BaseModel):
    message: str = "Confidential Financial Asset Payload"
    algorithm_mode: str = "hybrid"  # "classical_rsa" | "pqc_mlkem" | "hybrid" | "aes_256"


@router.post("/pqc-shield-test")
async def pqc_shield_test(request: PQCShieldTestRequest):
    """
    Simulate quantum security enhancement comparing Classical vs PQC (ML-KEM / FIPS 203) vs Hybrid deployment.
    """
    import base64
    import time
    import hashlib

    start_time = time.perf_counter()
    msg_bytes = request.message.encode("utf-8")

    mode = request.algorithm_mode.lower()

    if mode == "classical_rsa":
        hash_val = hashlib.sha256(msg_bytes).hexdigest()
        ciphertext = base64.b64encode(f"RSA_ENC:{hash_val[:16]}:{request.message}".encode()).decode()
        exec_ms = round((time.perf_counter() - start_time) * 1000 + 1.2, 2)
        return {
            "mode": "Classical RSA-2048",
            "standard": "PKCS#1 v1.5 / ANSI X9.31",
            "ciphertext_sample": ciphertext[:48] + "...",
            "quantum_status": "VULNERABLE",
            "quantum_score": 15,
            "shor_vulnerable": True,
            "grover_vulnerable": False,
            "qubits_needed_to_break": 4096,
            "estimated_quantum_break_time": "< 10 seconds on CRQC",
            "mathematical_basis": "Integer Factorization Problem",
            "lattice_dimension": "N/A",
            "security_level_bits": 112,
            "quantum_security_bits": 0,
            "execution_time_ms": exec_ms,
            "recommendation": "URGENT MIGRATION REQUIRED — Transition to NIST ML-KEM-768 or Hybrid dual-encapsulation.",
        }

    elif mode == "pqc_mlkem":
        hash_val = hashlib.sha3_512(msg_bytes).hexdigest()
        ciphertext = base64.b64encode(f"MLKEM768_LATTICE:{hash_val[:24]}:{request.message}".encode()).decode()
        exec_ms = round((time.perf_counter() - start_time) * 1000 + 0.8, 2)
        return {
            "mode": "NIST ML-KEM-768 (PQC)",
            "standard": "NIST FIPS 203 (Module-Lattice KEM)",
            "ciphertext_sample": ciphertext[:48] + "...",
            "quantum_status": "QUANTUM SECURE",
            "quantum_score": 100,
            "shor_vulnerable": False,
            "grover_vulnerable": False,
            "qubits_needed_to_break": "Infinite (Not vulnerable to Shor)",
            "estimated_quantum_break_time": "> 10^30 years (Quantum resistant)",
            "mathematical_basis": "Module Learning With Errors (M-LWE)",
            "lattice_dimension": "Matrix (k=3, n=256)",
            "security_level_bits": 192,
            "quantum_security_bits": 192,
            "execution_time_ms": exec_ms,
            "recommendation": "FULLY PROTECTED — Standardized PQC post-quantum defense active.",
        }

    elif mode == "hybrid":
        hash_val = hashlib.sha3_512(msg_bytes).hexdigest()
        ciphertext = base64.b64encode(f"HYBRID_X25519+MLKEM768:{hash_val[:24]}:{request.message}".encode()).decode()
        exec_ms = round((time.perf_counter() - start_time) * 1000 + 1.1, 2)
        return {
            "mode": "Hybrid (X25519 + ML-KEM-768)",
            "standard": "IETF Hybrid PQC Draft / NIST FIPS 203",
            "ciphertext_sample": ciphertext[:48] + "...",
            "quantum_status": "MAXIMUM HYBRID PROTECTION",
            "quantum_score": 98,
            "shor_vulnerable": False,
            "grover_vulnerable": False,
            "qubits_needed_to_break": "Immune (Classical + PQC Dual Layer)",
            "estimated_quantum_break_time": "> 10^30 years",
            "mathematical_basis": "Dual Proof: ECDH Curve25519 + M-LWE Lattice",
            "lattice_dimension": "Matrix (k=3, n=256) + Curve25519",
            "security_level_bits": 256,
            "quantum_security_bits": 192,
            "execution_time_ms": exec_ms,
            "recommendation": "RECOMMENDED PRODUCTION STANDARD — Dual protection against both classical protocol flaws and quantum threats.",
        }

    else:
        hash_val = hashlib.sha256(msg_bytes).hexdigest()
        ciphertext = base64.b64encode(f"AES256_GCM:{hash_val[:16]}:{request.message}".encode()).decode()
        exec_ms = round((time.perf_counter() - start_time) * 1000 + 0.4, 2)
        return {
            "mode": "AES-256-GCM + SHA-384",
            "standard": "NIST SP 800-38D",
            "ciphertext_sample": ciphertext[:48] + "...",
            "quantum_status": "GROVER RESISTANT",
            "quantum_score": 90,
            "shor_vulnerable": False,
            "grover_vulnerable": False,
            "qubits_needed_to_break": "N/A (Symmetric Cipher)",
            "estimated_quantum_break_time": "2^128 operations (Grover bisects 256 bits)",
            "mathematical_basis": "Substitution-Permutation Network",
            "lattice_dimension": "N/A",
            "security_level_bits": 256,
            "quantum_security_bits": 128,
            "execution_time_ms": exec_ms,
            "recommendation": "ADEQUATE — AES-256 provides 128 bits of remaining security against Grover search.",
        }


# ─── Quantum Hardware Lab Endpoints ──────────────────────────────────────────

class IBMTokenRequest(BaseModel):
    token: str


class HardwareJobRequest(BaseModel):
    algorithm: str = "shor"  # "shor" | "grover"
    N: int = 15  # For Shor: 15, 21, 35
    search_space_size: int = 16  # For Grover
    marked_item: int = 7  # For Grover
    mode: str = "ideal"  # "ideal" | "noisy" | "real_qpu"
    backend_name: str = "ibm_brisbane"
    shots: int = 4096


class ComparativeBenchmarkRequest(BaseModel):
    N: int = 15
    backend_name: str = "ibm_brisbane"
    shots: int = 4096


@router.get("/backends")
async def get_quantum_backends():
    """List all available quantum hardware QPUs, simulators, and live operational status."""
    from app.quantum.quantum_hardware import list_available_backends, get_ibm_token
    backends = list_available_backends()
    return {
        "backends": backends,
        "has_ibm_token": bool(get_ibm_token()),
    }


@router.post("/set-ibm-token")
async def set_ibm_quantum_token(request: IBMTokenRequest):
    """Configure or update the IBM Quantum API access token."""
    from app.quantum.quantum_hardware import set_ibm_token
    success = set_ibm_token(request.token)
    return {
        "success": success,
        "message": "IBM Quantum API token configured successfully." if success else "Token cleared.",
        "has_ibm_token": success,
    }


@router.post("/hardware-job")
async def run_hardware_job(request: HardwareJobRequest):
    """Execute a quantum circuit job on Ideal Simulator, Noisy Simulator, or Real IBM QPU."""
    from app.quantum.quantum_hardware import construct_shor_circuit, construct_grover_circuit, _execute_qiskit_circuit
    if request.algorithm.lower() == "shor":
        qc, num_qubits, depth = construct_shor_circuit(N=request.N, a=2)
    else:
        qc, num_qubits, depth = construct_grover_circuit(
            search_space_size=request.search_space_size,
            marked_item=request.marked_item
        )

    result = _execute_qiskit_circuit(
        qc=qc,
        mode=request.mode,
        backend_name=request.backend_name,
        shots=request.shots
    )
    return result


@router.post("/compare-modes")
async def compare_execution_modes(request: ComparativeBenchmarkRequest):
    """
    Execute small-integer Shor's Algorithm across Ideal Simulator vs Noisy Simulator vs Real QPU.
    Returns side-by-side histograms, fidelity metrics, and Quantum Security Risk Interpretation.
    """
    from app.quantum.quantum_hardware import run_comparative_shor
    result = await run_comparative_shor(
        N=request.N,
        backend_name=request.backend_name,
        shots=request.shots
    )
    return result


# ─── Phase 2 Quantum Security Algorithms ──────────────────────────────────────

class SimonDemoRequest(BaseModel):
    hidden_string: str = "101"
    shots: int = 1024


class QPEDemoRequest(BaseModel):
    phase_theta: float = 0.375  # 3/8
    precision_qubits: int = 4
    shots: int = 2048


class BB84Request(BaseModel):
    num_photons: int = 100
    eve_present: bool = False
    eve_intercept_prob: float = 1.0
    channel_noise: float = 0.02


class E91Request(BaseModel):
    num_pairs: int = 200
    eve_present: bool = False


@router.post("/simon-demo")
async def simon_demo(request: SimonDemoRequest):
    """Execute Simon's algorithm for exponential hidden period finding in symmetric cryptography."""
    from app.quantum.simon_demo import run_simon_demo
    result = await run_simon_demo(request.hidden_string, request.shots)
    return {
        "hidden_string_target": result.hidden_string_target,
        "hidden_string_found": result.hidden_string_found,
        "n_bits": result.n_bits,
        "num_qubits": result.num_qubits,
        "success": result.success,
        "execution_time_ms": result.execution_time_ms,
        "shots": result.shots,
        "measurements": result.measurements,
        "orthogonal_equations": result.orthogonal_equations,
        "classical_complexity": result.classical_complexity,
        "quantum_complexity": result.quantum_complexity,
        "speedup_factor": result.speedup_factor,
        "cryptographic_impact": result.cryptographic_impact,
        "note": result.note,
    }


@router.post("/qpe-demo")
async def qpe_demo(request: QPEDemoRequest):
    """Execute Quantum Phase Estimation (QPE) primitive circuit."""
    from app.quantum.qpe_demo import run_qpe_demo
    result = await run_qpe_demo(request.phase_theta, request.precision_qubits, request.shots)
    return {
        "target_phase_theta": result.target_phase_theta,
        "target_phase_fraction": result.target_phase_fraction,
        "estimated_phase_theta": result.estimated_phase_theta,
        "estimated_phase_fraction": result.estimated_phase_fraction,
        "phase_error": result.phase_error,
        "precision_qubits": result.precision_qubits,
        "total_qubits": result.total_qubits,
        "shots": result.shots,
        "execution_time_ms": result.execution_time_ms,
        "measurements": result.measurements,
        "most_probable_bitstring": result.most_probable_bitstring,
        "circuit_depth": result.circuit_depth,
        "theoretical_explanation": result.theoretical_explanation,
        "shor_connection": result.shor_connection,
    }


@router.post("/qkd-bb84")
async def qkd_bb84(request: BB84Request):
    """Simulate BB84 Quantum Key Distribution with Eve Intercept-Resend & QBER threshold test."""
    from app.quantum.qkd_sim import simulate_bb84
    result = simulate_bb84(
        num_photons=request.num_photons,
        eve_present=request.eve_present,
        eve_intercept_prob=request.eve_intercept_prob,
        channel_noise=request.channel_noise
    )
    return {
        "total_photons": result.total_photons,
        "raw_key_length": result.raw_key_length,
        "sifted_key_length": result.sifted_key_length,
        "final_key_length": result.final_key_length,
        "alice_sample_bits": result.alice_sample_bits,
        "alice_sample_bases": result.alice_sample_bases,
        "bob_sample_bases": result.bob_sample_bases,
        "bob_sample_bits": result.bob_sample_bits,
        "eve_present": result.eve_present,
        "eve_intercept_probability": result.eve_intercept_probability,
        "channel_noise": result.channel_noise,
        "qber": result.qber,
        "qber_threshold": result.qber_threshold,
        "is_key_secure": result.is_key_secure,
        "status": result.status,
        "final_shared_key_hex": result.final_shared_key_hex,
        "explanation": result.explanation,
    }


@router.post("/qkd-e91")
async def qkd_e91(request: E91Request):
    """Simulate E91 Entanglement-based QKD with CHSH Bell Inequality verification."""
    from app.quantum.qkd_sim import simulate_e91
    result = simulate_e91(
        num_pairs=request.num_pairs,
        eve_present=request.eve_present
    )
    return {
        "total_pairs": result.total_pairs,
        "chsh_correlation_s": result.chsh_correlation_s,
        "classical_limit": result.classical_limit,
        "tsirelson_bound": result.tsirelson_bound,
        "is_quantum_entangled": result.is_quantum_entangled,
        "eavesdropper_detected": result.eavesdropper_detected,
        "sifted_key_bits": result.sifted_key_bits,
        "final_key_hex": result.final_key_hex,
        "explanation": result.explanation,
    }


class HybridTLSRequest(BaseModel):
    target_url: str = "http://localhost:8080"
    custom_port: Optional[int] = None


class CBOMExportRequest(BaseModel):
    target_name: str = "QuantumShield Testbed"
    target_url: str = "http://localhost:8080"
    crypto_assets: list[dict] = []


@router.post("/hybrid-tls")
async def assess_hybrid_tls_endpoint(request: HybridTLSRequest):
    """Evaluate server TLS for X25519 + ML-KEM-768 hybrid key exchange support."""
    from app.quantum.hybrid_tls import assess_hybrid_pqc_tls
    return assess_hybrid_pqc_tls(request.target_url, request.custom_port)


@router.post("/cbom/cyclonedx")
async def export_cyclonedx_cbom_endpoint(request: CBOMExportRequest):
    """Export standard CycloneDX v1.6 Cryptography Extension CBOM JSON document."""
    from app.quantum.cbom_export import export_cyclonedx_cbom
    assets = request.crypto_assets or [
        {"algorithm": "RSA-2048", "key_size": 2048, "usage": "key_exchange", "quantum_vulnerable": True, "file_path": "security-lab/app/main.py"},
        {"algorithm": "ECDSA-P256", "key_size": 256, "usage": "digital_signature", "quantum_vulnerable": True, "file_path": "backend/app/auth.py"},
        {"algorithm": "AES-256-GCM", "key_size": 256, "usage": "data_encryption", "quantum_vulnerable": False, "file_path": "backend/app/database.py"},
    ]
    return export_cyclonedx_cbom(request.target_name, request.target_url, assets)


@router.post("/cbom/spdx")
async def export_spdx_cbom_endpoint(request: CBOMExportRequest):
    """Export standard SPDX 3.0 Cryptography Profile JSON-LD document."""
    from app.quantum.cbom_export import export_spdx_cbom
    assets = request.crypto_assets or [
        {"algorithm": "RSA-2048", "key_size": 2048, "usage": "key_exchange", "quantum_vulnerable": True, "file_path": "security-lab/app/main.py"},
        {"algorithm": "ECDSA-P256", "key_size": 256, "usage": "digital_signature", "quantum_vulnerable": True, "file_path": "backend/app/auth.py"},
    ]
    return export_spdx_cbom(request.target_name, request.target_url, assets)


@router.post("/cbom/json")
async def export_json_cbom_endpoint(request: CBOMExportRequest):
    """Export structured Cryptographic Bill of Materials JSON report."""
    from app.quantum.pqc_assessment import assess_pqc_readiness
    assets = request.crypto_assets or [
        {"algorithm": "RSA-2048", "key_size": 2048, "usage": "key_exchange", "quantum_vulnerable": True},
        {"algorithm": "ECDSA-P256", "key_size": 256, "usage": "digital_signature", "quantum_vulnerable": True},
    ]
    pqc = assess_pqc_readiness(assets)
    return {
        "target_name": request.target_name,
        "target_url": request.target_url,
        "generated_at": str(datetime.utcnow()),
        "total_crypto_assets": len(assets),
        "assets": assets,
        "pqc_migration_assessment": pqc,
    }


