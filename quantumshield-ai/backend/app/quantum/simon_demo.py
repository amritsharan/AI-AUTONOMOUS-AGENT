"""
Quantum Security Engine — Simon's Algorithm Demonstration
Demonstrates exponential quantum speedup for hidden period finding.
Cryptographic relevance: Proves vulnerability of classical symmetric schemes
(Even-Mansour, GCM authentication tag forgeries, 3-round Feistel) in quantum-chosen-message models.
"""

import logging
import math
import random
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# Predefined hidden string test sets (bit strings)
SUPPORTED_HIDDEN_STRINGS = {
    "11": {"n": 2, "qubits": 4, "description": "2-bit hidden period s='11' (f(x) = f(x ⊕ 11))"},
    "101": {"n": 3, "qubits": 6, "description": "3-bit hidden period s='101' (f(x) = f(x ⊕ 101))"},
    "110": {"n": 3, "qubits": 6, "description": "3-bit hidden period s='110' (f(x) = f(x ⊕ 110))"},
    "1100": {"n": 4, "qubits": 8, "description": "4-bit hidden period s='1100' (f(x) = f(x ⊕ 1100))"},
}


@dataclass
class SimonResult:
    hidden_string_target: str
    hidden_string_found: str
    n_bits: int
    num_qubits: int
    success: bool
    execution_time_ms: float
    shots: int
    measurements: Dict[str, int]
    orthogonal_equations: List[str]
    classical_complexity: str
    quantum_complexity: str
    speedup_factor: str
    cryptographic_impact: str
    note: str
    error: Optional[str] = None


def _construct_simon_oracle(n: int, s: str):
    """
    Construct a Simon oracle circuit for 2-to-1 function with period s.
    f(x) = f(y) <=> x ⊕ y in {0^n, s}
    """
    from qiskit import QuantumCircuit

    oracle = QuantumCircuit(2 * n)
    # Copy first register to second register: f(x) = x
    for i in range(n):
        oracle.cx(i, n + i)

    # Find first '1' in hidden string s
    first_1 = s.find("1")
    if first_1 != -1:
        for i in range(n):
            if s[i] == "1":
                oracle.cx(first_1, n + i)

    return oracle


def _solve_linear_system(equations: List[str], n: int) -> str:
    """
    Solve y · s = 0 (mod 2) using Gaussian elimination over GF(2)
    to recover the hidden period s.
    """
    matrix = []
    for eq in equations:
        row = [int(b) for b in eq]
        if any(row):  # Exclude all-zero row
            matrix.append(row)

    # Row reduce over GF(2)
    rows = len(matrix)
    cols = n

    lead = 0
    for r in range(rows):
        if lead >= cols:
            break
        i = r
        while i < rows and matrix[i][lead] == 0:
            i += 1
        if i == rows:
            lead += 1
            continue
        matrix[i], matrix[r] = matrix[r], matrix[i]
        for j in range(rows):
            if j != r and matrix[j][lead] == 1:
                matrix[j] = [a ^ b for a, b in zip(matrix[j], matrix[r])]
        lead += 1

    # Candidate search for non-zero s where all rows y · s == 0 (mod 2)
    for candidate_int in range(1, 2**n):
        cand_str = format(candidate_int, f"0{n}b")
        cand_vec = [int(b) for b in cand_str]
        valid = True
        for row in matrix:
            dot = sum(a * b for a, b in zip(row, cand_vec)) % 2
            if dot != 0:
                valid = False
                break
        if valid:
            return cand_str

    return "0" * n


async def run_simon_demo(hidden_string: str = "101", shots: int = 1024) -> SimonResult:
    """
    Execute Simon's algorithm circuit on AerSimulator.
    Recovers the hidden period s in O(n) quantum queries vs classical O(2^(n/2)).
    """
    start_time = time.perf_counter()
    s = hidden_string.strip()
    if s not in SUPPORTED_HIDDEN_STRINGS:
        s = "101"

    n = len(s)
    num_qubits = 2 * n

    from qiskit import QuantumCircuit, transpile
    from qiskit_aer import AerSimulator

    qc = QuantumCircuit(2 * n, n)

    # Step 1: Apply Hadamard gates to input register
    for i in range(n):
        qc.h(i)
    qc.barrier()

    # Step 2: Apply Simon Oracle
    oracle = _construct_simon_oracle(n, s)
    qc.compose(oracle, inplace=True)
    qc.barrier()

    # Step 3: Apply Hadamard gates to input register again
    for i in range(n):
        qc.h(i)
    qc.barrier()

    # Step 4: Measure input register (outputs y such that y · s = 0 mod 2)
    qc.measure(range(n), range(n))

    simulator = AerSimulator()
    t_qc = transpile(qc, simulator)
    job = simulator.run(t_qc, shots=shots)
    result = job.result()
    counts = result.get_counts()

    # Collect unique measurement vectors y
    top_y = [k for k, v in sorted(counts.items(), key=lambda x: x[1], reverse=True) if k != "0" * n]

    # Solve linear system y · s = 0 (mod 2)
    found_s = _solve_linear_system(top_y, n)
    success = (found_s == s)

    exec_ms = round((time.perf_counter() - start_time) * 1000, 2)

    return SimonResult(
        hidden_string_target=s,
        hidden_string_found=found_s,
        n_bits=n,
        num_qubits=num_qubits,
        success=success,
        execution_time_ms=exec_ms,
        shots=shots,
        measurements=dict(counts),
        orthogonal_equations=[f"{y} · s = 0 (mod 2)" for y in top_y[:5]],
        classical_complexity=f"Exponential: O(2^(n/2)) = ~{int(2**(n/2))} queries (Birthday Paradox bound)",
        quantum_complexity=f"Linear: O(n) = {n} queries + classical Gaussian elimination",
        speedup_factor=f"Exponential quantum speedup (O(2^(n/2)) -> O(n))",
        cryptographic_impact=(
            "Simon's algorithm provides an exponential attack against classical symmetric cryptography with internal linear/periodic structures. "
            "It breaks Even-Mansour block ciphers, authenticated encryption modes (such as classical GCM tag generation in Q2 attack models), and polynomial 3-round Feistel networks."
        ),
        note=(
            f"Successfully executed Simon's circuit. Measured orthogonal vectors y orthogonal to secret period s='{s}'. "
            "Demonstrates the fundamental quantum subroutine that inspired Shor's algorithm."
        ),
    )
