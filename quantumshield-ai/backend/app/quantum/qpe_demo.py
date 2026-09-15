"""
Quantum Security Engine — Quantum Phase Estimation (QPE) Primitive Playground
Demonstrates the fundamental quantum subroutine underpinning Shor's Algorithm,
Quantum Counting, and Quantum Machine Learning (HHL).
Given unitary U and eigenstate |ψ⟩ such that U|ψ⟩ = e^(2πiθ)|ψ⟩, QPE estimates θ.
"""

import logging
import math
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class QPEResult:
    target_phase_theta: float
    target_phase_fraction: str
    estimated_phase_theta: float
    estimated_phase_fraction: str
    phase_error: float
    precision_qubits: int
    total_qubits: int
    shots: int
    execution_time_ms: float
    measurements: Dict[str, int]
    most_probable_bitstring: str
    circuit_depth: int
    theoretical_explanation: str
    shor_connection: str


def _inverse_qft(qc, n_qubits: int):
    """Apply inverse Quantum Fourier Transform to n qubits."""
    import numpy as np
    for j in range(n_qubits // 2):
        qc.swap(j, n_qubits - j - 1)
    for j in range(n_qubits):
        for k in range(j):
            qc.cp(-np.pi / float(2 ** (j - k)), k, j)
        qc.h(j)


async def run_qpe_demo(
    phase_theta: float = 0.375,  # 3/8
    precision_qubits: int = 4,
    shots: int = 2048
) -> QPEResult:
    """
    Run Quantum Phase Estimation circuit for unitary U = PhaseGate(2πθ) on eigenstate |1⟩.
    """
    start_time = time.perf_counter()
    import numpy as np
    from qiskit import QuantumCircuit, transpile
    from qiskit_aer import AerSimulator

    n = max(2, min(6, precision_qubits))
    total_qubits = n + 1  # n counting qubits + 1 eigenstate qubit

    qc = QuantumCircuit(total_qubits, n)

    # Step 1: Prepare eigenstate |1⟩ on target qubit (qubit n)
    qc.x(n)

    # Step 2: Initialize counting qubits in superposition
    for i in range(n):
        qc.h(i)
    qc.barrier()

    # Step 3: Apply Controlled-U^(2^j) operations
    # U = PhaseGate(2πθ)
    angle = 2 * np.pi * phase_theta
    repetitions = 1
    for counting_qubit in range(n):
        for _ in range(repetitions):
            qc.cp(angle, counting_qubit, n)
        repetitions *= 2
    qc.barrier()

    # Step 4: Apply Inverse QFT on counting register
    _inverse_qft(qc, n)
    qc.barrier()

    # Step 5: Measure counting register
    qc.measure(range(n), range(n))

    simulator = AerSimulator()
    t_qc = transpile(qc, simulator)
    job = simulator.run(t_qc, shots=shots)
    result = job.result()
    counts = result.get_counts()

    # Most probable bitstring
    best_state = max(counts.items(), key=lambda x: x[1])[0]
    decimal_val = int(best_state, 2)
    estimated_theta = decimal_val / (2**n)

    error = abs(phase_theta - estimated_theta)
    exec_ms = round((time.perf_counter() - start_time) * 1000, 2)

    # Fraction representations
    from fractions import Fraction
    target_frac = str(Fraction(phase_theta).limit_denominator(32))
    est_frac = str(Fraction(estimated_theta).limit_denominator(32))

    return QPEResult(
        target_phase_theta=phase_theta,
        target_phase_fraction=target_frac,
        estimated_phase_theta=estimated_theta,
        estimated_phase_fraction=est_frac,
        phase_error=round(error, 6),
        precision_qubits=n,
        total_qubits=total_qubits,
        shots=shots,
        execution_time_ms=exec_ms,
        measurements=dict(counts),
        most_probable_bitstring=best_state,
        circuit_depth=t_qc.depth(),
        theoretical_explanation=(
            f"QPE uses {n} counting qubits to extract phase θ={phase_theta:.4f} ({target_frac}). "
            f"Phase kickback encodes the eigenvalue e^(2πiθ) into register phases, which Inverse QFT converts into bitstring |{best_state}⟩ (binary fraction 0.{best_state}_2 = {estimated_theta:.4f})."
        ),
        shor_connection=(
            "In Shor's Algorithm, QPE is applied where unitary U is modular multiplication U|y⟩ = |a·y mod N⟩. "
            "The eigenvalues of U contain phases of the form s/r, allowing QPE to measure the hidden period r and factorize composite RSA modulus N."
        ),
    )
