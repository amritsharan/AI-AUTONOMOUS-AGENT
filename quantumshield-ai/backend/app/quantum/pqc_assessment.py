"""
Quantum Security Engine — Post-Quantum Cryptography (PQC) Assessment
Assesses PQC readiness and provides migration recommendations.
Based on NIST PQC standards: ML-KEM, ML-DSA, SLH-DSA.
"""
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PQCAlgorithm:
    name: str
    full_name: str
    nist_standard: str
    category: str  # key_encapsulation | digital_signature
    security_levels: list[int]  # NIST security levels available
    classical_equivalent: list[str]  # What it replaces
    performance: str  # FAST | MODERATE | SLOW
    maturity: str  # STANDARDIZED | DRAFT | CANDIDATE
    description: str


@dataclass
class PQCRecommendation:
    current_algorithm: str
    current_key_size: Optional[int]
    quantum_vulnerable: bool
    vulnerability_type: str  # shor | grover | none
    urgency: str  # IMMEDIATE | PLANNED | OPTIONAL | NONE
    recommended_pqc_algorithms: list[PQCAlgorithm]
    hybrid_recommended: bool
    hybrid_rationale: str
    migration_complexity: str  # LOW | MEDIUM | HIGH
    migration_notes: str
    timeline_recommendation: str


# NIST-standardized post-quantum algorithms (FIPS 203, 204, 205)
PQC_ALGORITHMS = {
    "ML-KEM": PQCAlgorithm(
        name="ML-KEM",
        full_name="Module-Lattice-Based Key-Encapsulation Mechanism",
        nist_standard="FIPS 203",
        category="key_encapsulation",
        security_levels=[512, 768, 1024],
        classical_equivalent=["RSA-2048", "ECDH-P256", "ECDHE"],
        performance="FAST",
        maturity="STANDARDIZED",
        description=(
            "ML-KEM (formerly CRYSTALS-Kyber) is a lattice-based key encapsulation mechanism. "
            "It provides quantum-resistant key exchange, replacing RSA/ECDH. "
            "ML-KEM-768 provides security comparable to AES-192; ML-KEM-1024 to AES-256."
        ),
    ),
    "ML-DSA": PQCAlgorithm(
        name="ML-DSA",
        full_name="Module-Lattice-Based Digital Signature Algorithm",
        nist_standard="FIPS 204",
        category="digital_signature",
        security_levels=[44, 65, 87],  # parameter sets
        classical_equivalent=["RSA-2048", "ECDSA-P256", "ECDSA-P384"],
        performance="MODERATE",
        maturity="STANDARDIZED",
        description=(
            "ML-DSA (formerly CRYSTALS-Dilithium) is a lattice-based digital signature algorithm. "
            "It replaces RSA and ECDSA for digital signatures. "
            "Generally preferred for most use cases due to performance and key size balance."
        ),
    ),
    "SLH-DSA": PQCAlgorithm(
        name="SLH-DSA",
        full_name="Stateless Hash-Based Digital Signature Algorithm",
        nist_standard="FIPS 205",
        category="digital_signature",
        security_levels=[128, 192, 256],
        classical_equivalent=["RSA-2048", "ECDSA"],
        performance="SLOW",
        maturity="STANDARDIZED",
        description=(
            "SLH-DSA (formerly SPHINCS+) is a hash-based digital signature algorithm. "
            "It relies only on the security of hash functions — conservative choice. "
            "Slower than ML-DSA but provides a different security assumption (hash-based). "
            "Good for long-term signatures where performance is not critical."
        ),
    ),
}


def assess_pqc_readiness(algorithms: list[dict]) -> dict:
    """
    Assess PQC readiness for a list of discovered cryptographic assets.

    Args:
        algorithms: List of dicts with 'algorithm', 'key_size', 'usage' fields

    Returns:
        Dict with overall score, per-algorithm recommendations, and migration plan
    """
    recommendations = []
    total_risk_weight = 0.0
    covered_risk_weight = 0.0

    for algo_info in algorithms:
        algo = algo_info.get("algorithm", "")
        key_size = algo_info.get("key_size")
        usage = algo_info.get("usage", "")

        rec = _get_pqc_recommendation(algo, key_size, usage)
        recommendations.append(rec)

        # Scoring
        weight = _get_algorithm_weight(algo, usage)
        total_risk_weight += weight
        if not rec.quantum_vulnerable:
            covered_risk_weight += weight
        elif rec.urgency == "OPTIONAL":
            covered_risk_weight += weight * 0.8
        elif rec.urgency == "PLANNED":
            covered_risk_weight += weight * 0.3

    # PQC readiness score (0-100%)
    if total_risk_weight > 0:
        readiness_score = (covered_risk_weight / total_risk_weight) * 100
    else:
        readiness_score = 50.0  # No crypto found — unknown

    immediate_actions = [r for r in recommendations if r.urgency == "IMMEDIATE"]
    planned_actions = [r for r in recommendations if r.urgency == "PLANNED"]

    return {
        "pqc_readiness_score": round(readiness_score, 1),
        "total_algorithms_assessed": len(recommendations),
        "quantum_vulnerable_count": sum(1 for r in recommendations if r.quantum_vulnerable),
        "immediate_migration_needed": len(immediate_actions),
        "planned_migration_needed": len(planned_actions),
        "recommendations": [_recommendation_to_dict(r) for r in recommendations],
        "available_pqc_standards": {
            name: {
                "standard": algo.nist_standard,
                "category": algo.category,
                "maturity": algo.maturity,
                "performance": algo.performance,
            }
            for name, algo in PQC_ALGORITHMS.items()
        },
        "migration_summary": _generate_migration_summary(recommendations),
    }


def _get_pqc_recommendation(algorithm: str, key_size: Optional[int], usage: str) -> PQCRecommendation:
    """Get PQC migration recommendation for a specific algorithm."""
    algo_upper = algorithm.upper().replace("-", "").replace("_", "")

    # RSA
    if "RSA" in algo_upper:
        return PQCRecommendation(
            current_algorithm=algorithm,
            current_key_size=key_size,
            quantum_vulnerable=True,
            vulnerability_type="shor",
            urgency="PLANNED",
            recommended_pqc_algorithms=[PQC_ALGORITHMS["ML-KEM"], PQC_ALGORITHMS["ML-DSA"]],
            hybrid_recommended=True,
            hybrid_rationale="Hybrid RSA + ML-KEM/ML-DSA provides backward compatibility during migration while adding quantum resistance.",
            migration_complexity="HIGH",
            migration_notes=(
                f"RSA-{key_size or 2048} is secure today but will be broken by a future CRQC. "
                "For key exchange: replace RSA-KEM with ML-KEM. "
                "For signatures: replace RSA-sign with ML-DSA or SLH-DSA. "
                "Begin planning hybrid deployment now — full migration target: 2030 (NIST recommendation)."
            ),
            timeline_recommendation="Begin evaluation 2024-2026. Hybrid deployment 2026-2028. Full migration by 2030.",
        )

    # ECDSA / ECDH / EC
    if any(a in algo_upper for a in ["ECDSA", "ECDH", "EC"]):
        return PQCRecommendation(
            current_algorithm=algorithm,
            current_key_size=key_size,
            quantum_vulnerable=True,
            vulnerability_type="shor",
            urgency="PLANNED",
            recommended_pqc_algorithms=[PQC_ALGORITHMS["ML-KEM"], PQC_ALGORITHMS["ML-DSA"]],
            hybrid_recommended=True,
            hybrid_rationale="Hybrid ECDHE + ML-KEM provides quantum-resistant key exchange while maintaining TLS compatibility.",
            migration_complexity="MEDIUM",
            migration_notes=(
                f"ECDSA/ECDH requires more qubits than RSA to break, but is still Shor-vulnerable. "
                "For TLS key exchange: add ML-KEM to cipher suite (X25519MLKEM768 or similar). "
                "For code signing: migrate to ML-DSA or SLH-DSA."
            ),
            timeline_recommendation="Begin evaluation 2024-2026. Hybrid TLS deployment 2025-2027. Full migration by 2030.",
        )

    # DH/DSA
    if any(a in algo_upper for a in ["DH", "DSA"]) and "EC" not in algo_upper and "ML" not in algo_upper:
        return PQCRecommendation(
            current_algorithm=algorithm,
            current_key_size=key_size,
            quantum_vulnerable=True,
            vulnerability_type="shor",
            urgency="IMMEDIATE",
            recommended_pqc_algorithms=[PQC_ALGORITHMS["ML-KEM"], PQC_ALGORITHMS["ML-DSA"]],
            hybrid_recommended=False,
            hybrid_rationale="DH/DSA are already considered weak classically in many configurations.",
            migration_complexity="MEDIUM",
            migration_notes="DH (Finite-field) and DSA should be deprecated. Migrate to ML-KEM (key exchange) and ML-DSA (signatures).",
            timeline_recommendation="Immediate deprecation. Replace as soon as possible.",
        )

    # AES
    if "AES" in algo_upper:
        ks = key_size or 128
        if ks < 256:
            return PQCRecommendation(
                current_algorithm=algorithm,
                current_key_size=key_size,
                quantum_vulnerable=True,
                vulnerability_type="grover",
                urgency="PLANNED",
                recommended_pqc_algorithms=[],
                hybrid_recommended=False,
                hybrid_rationale="",
                migration_complexity="LOW",
                migration_notes=f"AES-{ks} provides ~{ks//2}-bit quantum security under Grover. Migrate to AES-256.",
                timeline_recommendation="Migrate to AES-256 at next key rotation cycle.",
            )
        else:
            return PQCRecommendation(
                current_algorithm=algorithm,
                current_key_size=key_size,
                quantum_vulnerable=False,
                vulnerability_type="grover",
                urgency="NONE",
                recommended_pqc_algorithms=[],
                hybrid_recommended=False,
                hybrid_rationale="",
                migration_complexity="LOW",
                migration_notes="AES-256 is quantum-safe. Provides ~128-bit security under Grover. No migration needed.",
                timeline_recommendation="No action required.",
            )

    # SHA
    if "SHA" in algo_upper:
        if "SHA1" in algo_upper or algo_upper == "SHA":
            return PQCRecommendation(
                current_algorithm=algorithm,
                current_key_size=None,
                quantum_vulnerable=True,
                vulnerability_type="grover",
                urgency="IMMEDIATE",
                recommended_pqc_algorithms=[],
                hybrid_recommended=False,
                hybrid_rationale="",
                migration_complexity="LOW",
                migration_notes="SHA-1 is classically broken (SHAttered collision). Migrate to SHA-256 or SHA-3 immediately.",
                timeline_recommendation="Immediate migration required.",
            )
        elif "SHA256" in algo_upper or "SHA384" in algo_upper or "SHA512" in algo_upper:
            return PQCRecommendation(
                current_algorithm=algorithm,
                current_key_size=None,
                quantum_vulnerable=False,
                vulnerability_type="grover",
                urgency="NONE",
                recommended_pqc_algorithms=[],
                hybrid_recommended=False,
                hybrid_rationale="",
                migration_complexity="LOW",
                migration_notes="SHA-256/384/512 are quantum-safe hash functions.",
                timeline_recommendation="No action required.",
            )

    # Default / unknown
    return PQCRecommendation(
        current_algorithm=algorithm,
        current_key_size=key_size,
        quantum_vulnerable=False,
        vulnerability_type="unknown",
        urgency="OPTIONAL",
        recommended_pqc_algorithms=[],
        hybrid_recommended=False,
        hybrid_rationale="",
        migration_complexity="LOW",
        migration_notes=f"Algorithm '{algorithm}' not in quantum threat database. Manual assessment recommended.",
        timeline_recommendation="Assess manually.",
    )


def _get_algorithm_weight(algorithm: str, usage: str) -> float:
    """Weight algorithms by their criticality."""
    algo_upper = algorithm.upper()
    # Key exchange and authentication are highest priority
    if any(a in algo_upper for a in ["ECDH", "RSA", "DH"]) or "key_exchange" in usage:
        return 3.0
    if any(a in algo_upper for a in ["ECDSA", "DSA"]) or "signature" in usage:
        return 2.0
    if "AES" in algo_upper or "SHA" in algo_upper:
        return 1.0
    return 1.0


def _recommendation_to_dict(rec: PQCRecommendation) -> dict:
    return {
        "current_algorithm": rec.current_algorithm,
        "current_key_size": rec.current_key_size,
        "quantum_vulnerable": rec.quantum_vulnerable,
        "vulnerability_type": rec.vulnerability_type,
        "urgency": rec.urgency,
        "recommended_pqc": [a.name for a in rec.recommended_pqc_algorithms],
        "hybrid_recommended": rec.hybrid_recommended,
        "hybrid_rationale": rec.hybrid_rationale,
        "migration_complexity": rec.migration_complexity,
        "migration_notes": rec.migration_notes,
        "timeline": rec.timeline_recommendation,
    }


def _generate_migration_summary(recommendations: list[PQCRecommendation]) -> str:
    immediate = [r.current_algorithm for r in recommendations if r.urgency == "IMMEDIATE"]
    planned = [r.current_algorithm for r in recommendations if r.urgency == "PLANNED"]
    safe = [r.current_algorithm for r in recommendations if not r.quantum_vulnerable]

    parts = []
    if immediate:
        parts.append(f"IMMEDIATE action required for: {', '.join(immediate)}")
    if planned:
        parts.append(f"Plan migration for: {', '.join(planned)}")
    if safe:
        parts.append(f"Quantum-safe algorithms in use: {', '.join(safe)}")
    if not parts:
        parts.append("No PQC migration issues identified.")

    return ". ".join(parts) + "."
