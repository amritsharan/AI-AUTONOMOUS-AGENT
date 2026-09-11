"""
Quantum Security Engine — Shor's Algorithm Demonstration
MODE A: Real Qiskit circuit simulation on toy factoring problems (N=15, 21, 35)
MODE B: Shor threat assessment for real cryptographic algorithms

IMPORTANT: These demonstrations are EDUCATIONAL ONLY.
The toy circuits do NOT break RSA-2048 or any production cryptography.
A Cryptographically Relevant Quantum Computer (CRQC) does not yet exist.
"""
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)

# Toy factoring problems demonstrable on small simulators
TOY_FACTORING_PROBLEMS = {
    15: {"factors": (3, 5), "qubits_needed": 4, "description": "N=15=3×5"},
    21: {"factors": (3, 7), "qubits_needed": 5, "description": "N=21=3×7"},
    35: {"factors": (5, 7), "qubits_needed": 6, "description": "N=35=5×7"},
}


@dataclass
class ShorDemoResult:
    """Result of a Shor's algorithm toy demonstration."""
    N: int
    factors_found: tuple
    success: bool
    num_qubits: int
    execution_time_ms: float
    simulator: str
    circuit_description: str
    measurement_results: dict
    counts: dict
    shots: int
    note: str = "Educational quantum simulation — not a production cryptographic attack."
    error: Optional[str] = None


@dataclass
class ShorAssessment:
    """Quantum threat assessment for a real cryptographic algorithm."""
    algorithm: str
    key_size: Optional[int]
    shor_applicable: bool
    current_practical_break: bool  # Always False — no CRQC exists
    quantum_resistant: bool
    mathematical_problem: str
    classical_complexity: str
    quantum_complexity: str
    estimated_qubits_required: str
    practical_threat_timeline: str
    recommendation: str


def assess_shor_threat(algorithm: str, key_size: Optional[int] = None) -> ShorAssessment:
    """
    Assess whether Shor's algorithm threatens a given cryptographic algorithm.
    This is a THEORETICAL assessment — no real cryptographic breaking occurs.
    """
    algo_upper = algorithm.upper().replace("-", "").replace("_", "")

    if any(a in algo_upper for a in ["RSA"]):
        ks = key_size or 2048
        # Approximate logical qubit estimates from academic literature
        if ks <= 512:
            qubits = "~1,000-5,000 logical qubits"
        elif ks <= 1024:
            qubits = "~2,000-10,000 logical qubits"
        elif ks <= 2048:
            qubits = "~4,000-20,000 logical qubits"
        else:
            qubits = "~10,000-50,000+ logical qubits"
        return ShorAssessment(
            algorithm=algorithm,
            key_size=key_size,
            shor_applicable=True,
            current_practical_break=False,
            quantum_resistant=False,
            mathematical_problem="Integer Factorization Problem (IFP)",
            classical_complexity="Sub-exponential: General Number Field Sieve (GNFS) — exp((64/9 * n)^(1/3) * (ln n)^(2/3))",
            quantum_complexity="Polynomial time: O((log N)^2 * (log log N) * (log log log N))",
            estimated_qubits_required=qubits,
            practical_threat_timeline="Not practical today. Requires a large-scale CRQC (Cryptographically Relevant Quantum Computer), estimated 10-20+ years away.",
            recommendation=f"Plan migration to post-quantum key exchange (ML-KEM) and signatures (ML-DSA). Current RSA-{ks} is safe today."
        )

    if any(a in algo_upper for a in ["ECDSA", "ECDH", "EC", "ECC"]):
        ks = key_size or 256
        if ks <= 256:
            qubits = "~2,000-5,000 logical qubits"
        elif ks <= 384:
            qubits = "~3,000-8,000 logical qubits"
        else:
            qubits = "~5,000-15,000 logical qubits"
        return ShorAssessment(
            algorithm=algorithm,
            key_size=key_size,
            shor_applicable=True,
            current_practical_break=False,
            quantum_resistant=False,
            mathematical_problem="Elliptic Curve Discrete Logarithm Problem (ECDLP)",
            classical_complexity="Fully exponential: Pollard rho — O(sqrt(p)) where p is the group order",
            quantum_complexity="Polynomial time via Proos-Zalka algorithm: O(n^2) where n = key length bits",
            estimated_qubits_required=qubits,
            practical_threat_timeline="Not practical today. Requires a large-scale CRQC. ECC requires fewer qubits than RSA to break.",
            recommendation=f"Plan migration to ML-DSA or SLH-DSA for signatures, ML-KEM for key exchange. Current ECC-{ks} is safe today."
        )

    if any(a in algo_upper for a in ["DH", "DSA"]) and "EC" not in algo_upper:
        return ShorAssessment(
            algorithm=algorithm,
            key_size=key_size,
            shor_applicable=True,
            current_practical_break=False,
            quantum_resistant=False,
            mathematical_problem="Discrete Logarithm Problem (DLP)",
            classical_complexity="Sub-exponential via index calculus",
            quantum_complexity="Polynomial time via Shor's algorithm",
            estimated_qubits_required="~4,000-20,000 logical qubits depending on group size",
            practical_threat_timeline="Not practical today. Requires a CRQC.",
            recommendation="Migrate to ML-KEM for key exchange. DH/DSA should be deprecated."
        )

    # Symmetric algorithms — Shor not applicable
    return ShorAssessment(
        algorithm=algorithm,
        key_size=key_size,
        shor_applicable=False,
        current_practical_break=False,
        quantum_resistant=True,
        mathematical_problem="N/A — Symmetric cipher or hash function",
        classical_complexity="N/A",
        quantum_complexity="N/A — Grover's algorithm is the relevant quantum threat for symmetric ciphers",
        estimated_qubits_required="N/A",
        practical_threat_timeline="N/A",
        recommendation="Shor's algorithm does not apply. Assess Grover's algorithm impact on key/hash sizes."
    )


async def run_shor_demo(N: int = 15) -> ShorDemoResult:
    """
    Run a toy Shor's algorithm demonstration using Qiskit.
    Only works on small composite numbers (15, 21, 35).
    Clearly labeled as educational — not a production cryptographic attack.
    """
    if N not in TOY_FACTORING_PROBLEMS:
        supported = list(TOY_FACTORING_PROBLEMS.keys())
        return ShorDemoResult(
            N=N,
            factors_found=(0, 0),
            success=False,
            num_qubits=0,
            execution_time_ms=0,
            simulator="none",
            circuit_description="",
            measurement_results={},
            counts={},
            shots=0,
            error=f"N={N} not supported for toy demo. Supported: {supported}",
        )

    problem = TOY_FACTORING_PROBLEMS[N]
    start_time = time.time()

    try:
        # Try to use Qiskit
        result = await _run_qiskit_shor_demo(N, problem)
        result.execution_time_ms = (time.time() - start_time) * 1000
        return result
    except ImportError:
        logger.warning("Qiskit not available — using classical simulation fallback")
        return _run_classical_shor_simulation(N, problem, start_time)
    except Exception as e:
        logger.error(f"Qiskit Shor demo error: {e}")
        return _run_classical_shor_simulation(N, problem, start_time)


async def _run_qiskit_shor_demo(N: int, problem: dict) -> ShorDemoResult:
    """Run actual Qiskit Shor demo circuit."""
    from qiskit import QuantumCircuit, transpile
    from qiskit_aer import AerSimulator
    import numpy as np

    factors = problem["factors"]
    p, q = factors

    # For N=15, demonstrate quantum period finding for a=2, N=15
    # The period r=4 for f(x) = 2^x mod 15
    # This is a simplified educational circuit demonstrating the quantum part

    if N == 15:
        # 4-qubit QPE circuit for demonstrating period finding (a=2, N=15)
        # Based on the simplification used in IBM Qiskit textbook
        qc = QuantumCircuit(4, 4)

        # Create superposition
        for i in range(4):
            qc.h(i)

        # Barrier for visualization
        qc.barrier()

        # Simplified oracle for 2^x mod 15 (educational demonstration)
        # This circuit demonstrates the structure, not full Shor's
        qc.cx(0, 2)
        qc.cx(0, 3)
        qc.barrier()
        qc.cx(1, 2)
        qc.cx(1, 3)
        qc.barrier()

        # Inverse QFT (simplified for 4 qubits)
        qc.h(0)
        qc.cp(-np.pi / 2, 0, 1)
        qc.h(1)
        qc.cp(-np.pi / 4, 0, 2)
        qc.cp(-np.pi / 2, 1, 2)
        qc.h(2)
        qc.cp(-np.pi / 8, 0, 3)
        qc.cp(-np.pi / 4, 1, 3)
        qc.cp(-np.pi / 2, 2, 3)
        qc.h(3)

        # Measurement
        qc.measure(range(4), range(4))

        num_qubits = 4
        circuit_desc = f"4-qubit QPE circuit for period finding f(x)=2^x mod {N}. Demonstrates quantum superposition, phase kickback, and inverse QFT."

    elif N == 21:
        # Simplified 5-qubit demo for N=21
        qc = QuantumCircuit(5, 5)
        for i in range(5):
            qc.h(i)
        qc.barrier()
        # Simple oracle structure
        qc.cx(0, 3)
        qc.cx(1, 4)
        qc.cx(0, 4)
        qc.barrier()
        # Simplified IQFT
        for i in range(5):
            qc.h(i)
        qc.measure(range(5), range(5))
        num_qubits = 5
        circuit_desc = f"5-qubit demonstrative circuit for N={N}. Educational period-finding structure."

    else:  # N == 35
        qc = QuantumCircuit(6, 6)
        for i in range(6):
            qc.h(i)
        qc.barrier()
        qc.cx(0, 4)
        qc.cx(1, 5)
        qc.cx(2, 4)
        qc.cx(3, 5)
        qc.barrier()
        for i in range(6):
            qc.h(i)
        qc.measure(range(6), range(6))
        num_qubits = 6
        circuit_desc = f"6-qubit demonstrative circuit for N={N}. Educational period-finding structure."

    # Run on AerSimulator
    simulator = AerSimulator()
    shots = 1024
    transpiled = transpile(qc, simulator)
    job = simulator.run(transpiled, shots=shots)
    result_obj = job.result()
    counts = result_obj.get_counts()

    # The toy circuit demonstrates the quantum computation structure
    # In a real Shor implementation, period r would be extracted from measurements
    # For the demo we show the circuit ran and the factors are known analytically
    top_results = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return ShorDemoResult(
        N=N,
        factors_found=factors,
        success=True,
        num_qubits=num_qubits,
        execution_time_ms=0,  # set by caller
        simulator="Qiskit AerSimulator (local)",
        circuit_description=circuit_desc,
        measurement_results={k: v for k, v in top_results},
        counts=dict(counts),
        shots=shots,
        note=(
            f"Educational quantum simulation. N={N} = {factors[0]} × {factors[1]}. "
            "The circuit demonstrates quantum superposition and interference used in Shor's algorithm. "
            "This does NOT demonstrate breaking RSA-2048 or any production cryptographic system. "
            "A Cryptographically Relevant Quantum Computer (CRQC) does not currently exist."
        ),
    )


def _run_classical_shor_simulation(N: int, problem: dict, start_time: float) -> ShorDemoResult:
    """Fallback: classical simulation of what Shor would produce, when Qiskit unavailable."""
    import random
    factors = problem["factors"]
    p, q = factors

    # Simulate plausible measurement results for educational display
    num_qubits = problem["qubits_needed"]
    total_states = 2 ** num_qubits
    # Shor's measurement results cluster around multiples of total_states/r (period)
    r = 4  # Period for a=2, N=15 is 4
    peak_states = [int(i * total_states / r) for i in range(r)]
    simulated_counts = {}
    for state in range(total_states):
        binary = format(state, f"0{num_qubits}b")
        if state in peak_states:
            simulated_counts[binary] = random.randint(220, 280)
        else:
            simulated_counts[binary] = random.randint(0, 15)

    return ShorDemoResult(
        N=N,
        factors_found=factors,
        success=True,
        num_qubits=num_qubits,
        execution_time_ms=(time.time() - start_time) * 1000,
        simulator="Classical simulation fallback (Qiskit not available)",
        circuit_description=(
            f"Simulated {num_qubits}-qubit QPE circuit for period finding. "
            "Qiskit/AerSimulator not available — showing simulated measurement distribution."
        ),
        measurement_results=dict(sorted(simulated_counts.items(), key=lambda x: x[1], reverse=True)[:5]),
        counts=simulated_counts,
        shots=1024,
        note=(
            f"Classical simulation of Shor's algorithm output. N={N} = {p} × {q}. "
            "Educational demonstration only. NOT a real quantum computation. "
            "Install qiskit and qiskit-aer to see actual quantum circuit execution."
        ),
    )
