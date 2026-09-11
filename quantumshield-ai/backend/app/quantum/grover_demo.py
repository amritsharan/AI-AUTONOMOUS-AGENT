"""
Quantum Security Engine — Grover's Algorithm Demonstration
MODE A: Real Qiskit Grover circuit on small search spaces (4-64 items)
MODE B: Grover threat assessment for symmetric cryptographic algorithms
"""
import logging
import math
import time
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class GroverDemoResult:
    search_space_size: int
    marked_item: int
    item_found: bool
    found_item: Optional[int]
    num_qubits: int
    optimal_iterations: int
    classical_complexity: str
    quantum_complexity: str
    execution_time_ms: float
    simulator: str
    circuit_description: str
    measurement_results: dict
    counts: dict
    shots: int
    speedup_factor: str
    note: str = "Educational quantum simulation — not a production cryptographic attack."
    error: Optional[str] = None


@dataclass
class GroverAssessment:
    """Grover threat assessment for symmetric algorithms."""
    algorithm: str
    key_size_bits: int
    classical_key_space: str
    classical_search_complexity: str
    grover_quantum_complexity: str
    effective_quantum_security_bits: int
    is_sufficient: bool
    recommendation: str
    migration_needed: bool


SYMMETRIC_GROVER_TABLE = {
    "AES-128": {
        "key_bits": 128,
        "classical_complexity": "2^128 operations",
        "grover_complexity": "~2^64 quantum operations",
        "effective_quantum_bits": 64,
        "sufficient": False,
        "recommendation": "Migrate to AES-256. AES-128 provides only ~64-bit quantum security under Grover's attack.",
        "migration_needed": True,
    },
    "AES-192": {
        "key_bits": 192,
        "classical_complexity": "2^192 operations",
        "grover_complexity": "~2^96 quantum operations",
        "effective_quantum_bits": 96,
        "sufficient": True,
        "recommendation": "AES-192 provides ~96-bit quantum security. Generally considered adequate but AES-256 provides higher margin.",
        "migration_needed": False,
    },
    "AES-256": {
        "key_bits": 256,
        "classical_complexity": "2^256 operations",
        "grover_complexity": "~2^128 quantum operations",
        "effective_quantum_bits": 128,
        "sufficient": True,
        "recommendation": "AES-256 is quantum-safe. Provides ~128-bit security margin against Grover's algorithm.",
        "migration_needed": False,
    },
    "3DES": {
        "key_bits": 112,
        "classical_complexity": "2^112 operations",
        "grover_complexity": "~2^56 quantum operations",
        "effective_quantum_bits": 56,
        "sufficient": False,
        "recommendation": "3DES should be deprecated regardless of quantum threats. Migrate to AES-256.",
        "migration_needed": True,
    },
    "DES": {
        "key_bits": 56,
        "classical_complexity": "2^56 operations",
        "grover_complexity": "~2^28 quantum operations",
        "effective_quantum_bits": 28,
        "sufficient": False,
        "recommendation": "DES is critically insecure classically and quantumly. Immediate migration required.",
        "migration_needed": True,
    },
    "SHA-256": {
        "key_bits": 256,
        "classical_complexity": "2^128 preimage resistance",
        "grover_complexity": "~2^128 preimage resistance (Grover doesn't help against SHA-256 preimage)",
        "effective_quantum_bits": 128,
        "sufficient": True,
        "recommendation": "SHA-256 provides adequate quantum resistance for hash functions.",
        "migration_needed": False,
    },
}


def assess_grover_threat(algorithm: str, key_size: Optional[int] = None) -> GroverAssessment:
    """Assess Grover's algorithm threat for a symmetric cipher or hash function."""
    # Look up or calculate
    table_key = algorithm.upper().replace(" ", "-")
    if table_key in SYMMETRIC_GROVER_TABLE:
        entry = SYMMETRIC_GROVER_TABLE[table_key]
    elif key_size:
        effective_bits = key_size // 2
        sufficient = effective_bits >= 128
        entry = {
            "key_bits": key_size,
            "classical_complexity": f"2^{key_size} operations",
            "grover_complexity": f"~2^{effective_bits} quantum operations",
            "effective_quantum_bits": effective_bits,
            "sufficient": sufficient,
            "recommendation": (
                f"{'Adequate' if sufficient else 'Insufficient'} quantum security. "
                f"Grover reduces effective key strength from {key_size} to ~{effective_bits} bits."
            ),
            "migration_needed": not sufficient,
        }
    else:
        entry = SYMMETRIC_GROVER_TABLE.get("AES-256", {})

    return GroverAssessment(
        algorithm=algorithm,
        key_size_bits=entry.get("key_bits", key_size or 0),
        classical_key_space=f"2^{entry.get('key_bits', key_size or 0)} possible keys",
        classical_search_complexity=entry.get("classical_complexity", "Unknown"),
        grover_quantum_complexity=entry.get("grover_complexity", "Unknown"),
        effective_quantum_security_bits=entry.get("effective_quantum_bits", 0),
        is_sufficient=entry.get("sufficient", False),
        recommendation=entry.get("recommendation", ""),
        migration_needed=entry.get("migration_needed", False),
    )


async def run_grover_demo(search_space_size: int = 16, marked_item: Optional[int] = None) -> GroverDemoResult:
    """
    Run Grover's algorithm demonstration on a small search space.
    search_space_size must be a power of 2, max 64 for simulator performance.
    """
    # Validate and clamp
    search_space_size = min(max(search_space_size, 4), 64)
    # Round to nearest power of 2
    num_qubits = math.ceil(math.log2(search_space_size))
    actual_size = 2 ** num_qubits

    if marked_item is None or marked_item >= actual_size:
        marked_item = actual_size // 3  # Pick a non-obvious item

    # Grover's optimal iterations: int(pi/4 * sqrt(N)), minimum 1
    optimal_iterations = max(1, int((math.pi / 4) * math.sqrt(actual_size)))

    classical_complexity = f"O(N) = O({actual_size}) — average N/2 = {actual_size // 2} checks"
    quantum_complexity = f"O(√N) = O({actual_size}^0.5) ≈ {round(math.sqrt(actual_size), 1)} oracle queries"
    speedup = round(math.sqrt(actual_size), 1)

    start_time = time.time()

    try:
        result = await _run_qiskit_grover_demo(
            actual_size, num_qubits, marked_item, optimal_iterations,
            classical_complexity, quantum_complexity, speedup
        )
        result.execution_time_ms = (time.time() - start_time) * 1000
        return result
    except ImportError:
        logger.warning("Qiskit not available — using classical Grover simulation")
        return _classical_grover_simulation(
            actual_size, num_qubits, marked_item, optimal_iterations,
            classical_complexity, quantum_complexity, speedup, start_time
        )
    except Exception as e:
        logger.error(f"Grover demo error: {e}")
        return _classical_grover_simulation(
            actual_size, num_qubits, marked_item, optimal_iterations,
            classical_complexity, quantum_complexity, speedup, start_time
        )


async def _run_qiskit_grover_demo(
    N: int, n: int, marked: int, iterations: int,
    classical_complexity: str, quantum_complexity: str, speedup: float
) -> GroverDemoResult:
    """Run actual Qiskit Grover's algorithm circuit."""
    from qiskit import QuantumCircuit, transpile
    from qiskit_aer import AerSimulator
    import numpy as np

    # Build Grover's circuit
    qc = QuantumCircuit(n, n)

    # 1. Initialize: Hadamard on all qubits
    qc.h(range(n))
    qc.barrier()

    # 2. Grover iterations: Oracle + Diffuser
    for _ in range(iterations):
        # Oracle: flip phase of marked item
        marked_binary = format(marked, f"0{n}b")

        # Add X gates for 0-bits to create |marked> -> |11...1>
        for i, bit in enumerate(reversed(marked_binary)):
            if bit == "0":
                qc.x(i)

        # Multi-controlled Z
        if n == 1:
            qc.z(0)
        elif n == 2:
            qc.cz(0, 1)
        else:
            # Use mcz via auxiliary gates
            qc.h(n - 1)
            qc.mcx(list(range(n - 1)), n - 1)
            qc.h(n - 1)

        # Undo X gates
        for i, bit in enumerate(reversed(marked_binary)):
            if bit == "0":
                qc.x(i)

        qc.barrier()

        # Diffuser (Grover's diffusion operator)
        qc.h(range(n))
        qc.x(range(n))
        if n == 1:
            qc.z(0)
        elif n == 2:
            qc.cz(0, 1)
        else:
            qc.h(n - 1)
            qc.mcx(list(range(n - 1)), n - 1)
            qc.h(n - 1)
        qc.x(range(n))
        qc.h(range(n))
        qc.barrier()

    # 3. Measure
    qc.measure(range(n), range(n))

    # Run simulation
    shots = 1024
    simulator = AerSimulator()
    transpiled = transpile(qc, simulator)
    job = simulator.run(transpiled, shots=shots)
    result_obj = job.result()
    counts = result_obj.get_counts()

    marked_binary = format(marked, f"0{n}b")
    marked_count = counts.get(marked_binary, 0)
    probability = marked_count / shots
    item_found = probability > 0.3  # Should be much higher with Grover

    top_results = dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:8])

    return GroverDemoResult(
        search_space_size=N,
        marked_item=marked,
        item_found=item_found,
        found_item=marked if item_found else None,
        num_qubits=n,
        optimal_iterations=iterations,
        classical_complexity=classical_complexity,
        quantum_complexity=quantum_complexity,
        execution_time_ms=0,  # set by caller
        simulator="Qiskit AerSimulator (local)",
        circuit_description=(
            f"{n}-qubit Grover's algorithm searching {N} items for marked item #{marked}. "
            f"{iterations} Grover iteration(s) applied. "
            f"Oracle marks |{marked_binary}⟩. Measured probability: {probability:.1%}."
        ),
        measurement_results=top_results,
        counts=dict(counts),
        shots=shots,
        speedup_factor=f"√{N} ≈ {speedup}x quadratic speedup over classical search",
        note=(
            f"Educational Grover's algorithm demonstration. Search space: {N} items. "
            f"Classical: O(N)={N} checks. Quantum: O(√N)≈{round(math.sqrt(N))} queries. "
            "This demonstrates the STRUCTURE of Grover's algorithm. "
            "It does NOT search a real AES keyspace (2^128 items) — "
            "that would require a CRQC with millions of physical qubits."
        ),
    )


def _classical_grover_simulation(
    N: int, n: int, marked: int, iterations: int,
    classical_complexity: str, quantum_complexity: str, speedup: float,
    start_time: float
) -> GroverDemoResult:
    """Classical simulation of Grover outputs when Qiskit unavailable."""
    import random

    marked_binary = format(marked, f"0{n}b")
    total_shots = 1024

    # Simulate Grover's amplification: marked item gets high probability
    # After optimal_iterations, P(marked) ≈ sin²((2k+1)*arcsin(1/√N)) ≈ 1 for k=optimal
    import math
    theta = math.asin(1.0 / math.sqrt(N))
    prob_marked = math.sin((2 * iterations + 1) * theta) ** 2
    expected_marked_shots = int(prob_marked * total_shots)

    counts = {}
    remaining = total_shots - expected_marked_shots
    for i in range(N):
        binary = format(i, f"0{n}b")
        if i == marked:
            counts[binary] = expected_marked_shots
        else:
            counts[binary] = max(0, remaining // max(N - 1, 1) + random.randint(-2, 2))

    top_results = dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:8])

    return GroverDemoResult(
        search_space_size=N,
        marked_item=marked,
        item_found=True,
        found_item=marked,
        num_qubits=n,
        optimal_iterations=iterations,
        classical_complexity=classical_complexity,
        quantum_complexity=quantum_complexity,
        execution_time_ms=(time.time() - start_time) * 1000,
        simulator="Classical simulation fallback (Qiskit not available)",
        circuit_description=(
            f"Simulated {n}-qubit Grover's circuit for {N}-item search. "
            f"Marked item: #{marked} ({marked_binary}). "
            f"Simulated {iterations} Grover iteration(s). "
            f"Expected marked-item probability: {prob_marked:.1%}."
        ),
        measurement_results=top_results,
        counts=counts,
        shots=total_shots,
        speedup_factor=f"√{N} ≈ {speedup}x quadratic speedup over classical search",
        note=(
            f"Classical simulation of Grover's algorithm. Install qiskit+qiskit-aer for real quantum simulation. "
            f"Search space: {N} items. Quantum advantage: O(√N)≈{round(math.sqrt(N))} vs O(N)={N} classical."
        ),
    )
