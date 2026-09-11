"""
Quantum Security Engine — Cryptographic Asset Discovery
Discovers cryptographic algorithms in use and assesses quantum vulnerability.
"""
import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx

from app.policy.engine import PolicyEngine, ScopeConfig

logger = logging.getLogger(__name__)


@dataclass
class CryptoAssetInfo:
    algorithm: str
    key_size: Optional[int]
    protocol: Optional[str]
    endpoint: str
    usage: str
    classical_security: str  # STRONG | ADEQUATE | WEAK
    quantum_security: str    # RESISTANT | VULNERABLE | UNKNOWN
    quantum_attack: str      # shor | grover | none | unknown
    pqc_status: str          # MIGRATION_RECOMMENDED | MIGRATION_REQUIRED | OK | UNKNOWN
    risk_score: float
    details: dict = field(default_factory=dict)


# Known algorithm quantum vulnerability database
ALGORITHM_QUANTUM_DB = {
    # Asymmetric (public-key) algorithms — vulnerable to Shor
    "RSA": {
        "quantum_attack": "shor",
        "quantum_security": "VULNERABLE",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "RSA security relies on integer factoring. Shor's algorithm solves factoring in polynomial time on a quantum computer.",
        "key_sizes": {
            512: {"classical_security": "CRITICAL_WEAK", "quantum_security": "VULNERABLE"},
            1024: {"classical_security": "WEAK", "quantum_security": "VULNERABLE"},
            2048: {"classical_security": "STRONG", "quantum_security": "VULNERABLE"},
            4096: {"classical_security": "STRONG", "quantum_security": "VULNERABLE"},
        }
    },
    "ECDSA": {
        "quantum_attack": "shor",
        "quantum_security": "VULNERABLE",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "ECDSA security relies on the Elliptic Curve Discrete Logarithm Problem (ECDLP). Shor's algorithm (adapted by Proos & Zalka) solves ECDLP in polynomial time.",
        "key_sizes": {
            256: {"classical_security": "STRONG", "quantum_security": "VULNERABLE"},
            384: {"classical_security": "STRONG", "quantum_security": "VULNERABLE"},
            521: {"classical_security": "STRONG", "quantum_security": "VULNERABLE"},
        }
    },
    "ECDH": {
        "quantum_attack": "shor",
        "quantum_security": "VULNERABLE",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "ECDH key agreement is based on ECDLP, which Shor's algorithm can break.",
    },
    "ECDHE": {
        "quantum_attack": "shor",
        "quantum_security": "VULNERABLE",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "ECDHE (Ephemeral ECDH) is vulnerable to Shor's algorithm. Forward secrecy does not protect against a future CRQC decrypting stored traffic.",
    },
    "DH": {
        "quantum_attack": "shor",
        "quantum_security": "VULNERABLE",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "Diffie-Hellman security relies on the Discrete Logarithm Problem (DLP). Shor's algorithm solves DLP in polynomial time.",
    },
    "DSA": {
        "quantum_attack": "shor",
        "quantum_security": "VULNERABLE",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "DSA is based on DLP and is vulnerable to Shor's algorithm.",
    },
    # Symmetric algorithms — affected by Grover (reduced effective key size)
    "AES-128": {
        "quantum_attack": "grover",
        "quantum_security": "PARTIALLY_VULNERABLE",
        "pqc_migration": "MIGRATION_RECOMMENDED",
        "reason": "Grover's algorithm provides ~sqrt speedup on symmetric key search. AES-128 drops to ~64-bit effective quantum security.",
        "grover_effective_bits": 64,
    },
    "AES-192": {
        "quantum_attack": "grover",
        "quantum_security": "ADEQUATE",
        "pqc_migration": "OPTIONAL",
        "reason": "AES-192 drops to ~96-bit effective quantum security under Grover. Generally considered adequate.",
        "grover_effective_bits": 96,
    },
    "AES-256": {
        "quantum_attack": "grover",
        "quantum_security": "RESISTANT",
        "pqc_migration": "NONE_REQUIRED",
        "reason": "AES-256 drops to ~128-bit effective quantum security under Grover. 128 bits is considered quantum-safe.",
        "grover_effective_bits": 128,
    },
    "AES": {
        "quantum_attack": "grover",
        "quantum_security": "DEPENDS_ON_KEY_SIZE",
        "pqc_migration": "ASSESS_KEY_SIZE",
        "reason": "AES quantum vulnerability depends on key size. AES-128 is weaker; AES-256 is sufficient.",
    },
    # Hash functions
    "SHA-256": {
        "quantum_attack": "grover",
        "quantum_security": "ADEQUATE",
        "pqc_migration": "NONE_REQUIRED",
        "reason": "SHA-256 provides ~128-bit quantum security against preimage attacks via Grover.",
        "grover_effective_bits": 128,
    },
    "SHA-384": {
        "quantum_attack": "grover",
        "quantum_security": "RESISTANT",
        "pqc_migration": "NONE_REQUIRED",
        "grover_effective_bits": 192,
    },
    "SHA-512": {
        "quantum_attack": "grover",
        "quantum_security": "RESISTANT",
        "pqc_migration": "NONE_REQUIRED",
        "grover_effective_bits": 256,
    },
    "SHA-1": {
        "quantum_attack": "grover",
        "quantum_security": "CRITICAL_WEAK",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "SHA-1 is already classically broken (SHAttered). Quantum attacks make it further irrelevant.",
        "grover_effective_bits": 40,
    },
    "MD5": {
        "quantum_attack": "grover",
        "quantum_security": "CRITICAL_WEAK",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "MD5 is already classically broken. Deprecated and insecure.",
        "grover_effective_bits": 32,
    },
    "HMAC": {
        "quantum_attack": "grover",
        "quantum_security": "DEPENDS_ON_HASH",
        "pqc_migration": "ASSESS_UNDERLYING_HASH",
        "reason": "HMAC security depends on underlying hash function key size.",
    },
    # JWT algorithms
    "HS256": {
        "quantum_attack": "grover",
        "quantum_security": "ADEQUATE",
        "pqc_migration": "NONE_REQUIRED",
        "reason": "HMAC-SHA256 with a strong secret provides adequate quantum security.",
    },
    "RS256": {
        "quantum_attack": "shor",
        "quantum_security": "VULNERABLE",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "RSA-based JWT signing is vulnerable to Shor's algorithm.",
    },
    "ES256": {
        "quantum_attack": "shor",
        "quantum_security": "VULNERABLE",
        "pqc_migration": "MIGRATION_REQUIRED",
        "reason": "ECDSA P-256 JWT signing is vulnerable to Shor's algorithm.",
    },
}


async def run_crypto_discovery(
    target_url: str,
    scope: ScopeConfig,
    policy: PolicyEngine,
    scan_id: str = "",
    event_callback=None,
) -> list[CryptoAssetInfo]:
    """Discover cryptographic assets in the target application."""
    assets = []

    async def emit(msg: str):
        logger.info(f"[QUANTUM-DISCOVERY] {msg}")
        if event_callback:
            await event_callback("quantum_crypto_discovery", msg)

    await emit("Starting cryptographic asset discovery...")

    decision = policy.validate("quantum_crypto_discovery", target_url, scope, scan_id)
    if not decision.allowed:
        await emit(f"Crypto discovery blocked by policy: {decision.reason}")
        return assets

    timeout = httpx.Timeout(10.0)
    headers = {"User-Agent": "QuantumShield-SecurityScanner/1.0"}

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        # 1. Fetch crypto config endpoint
        await emit("Fetching cryptographic configuration...")
        try:
            resp = await client.get(urljoin(target_url, "/api/crypto/config"), headers=headers)
            if resp.status_code == 200:
                config = resp.json()
                assets.extend(_parse_crypto_config(config, target_url))
                await emit(f"Crypto config endpoint revealed {len(assets)} assets")
        except Exception as e:
            await emit(f"Crypto config fetch error: {e}")

        # 2. JWT algorithm detection from login response
        await emit("Detecting JWT algorithm...")
        try:
            login_resp = await client.post(
                urljoin(target_url, "/api/auth/login"),
                json={"username": "alice", "password": "Alice@123"},
                headers={**headers, "Content-Type": "application/json"},
            )
            if login_resp.status_code == 200:
                token = login_resp.json().get("token", "")
                if token:
                    jwt_assets = _analyze_jwt(token, target_url)
                    assets.extend(jwt_assets)
                    await emit(f"JWT analysis revealed algorithm: {jwt_assets[0].algorithm if jwt_assets else 'unknown'}")
        except Exception as e:
            await emit(f"JWT detection error: {e}")

        # 3. TLS check
        await emit("Checking TLS configuration...")
        if target_url.startswith("https://"):
            try:
                tls_resp = await client.get(target_url, headers=headers)
                tls_asset = _assess_tls_from_response(tls_resp, target_url)
                if tls_asset:
                    assets.append(tls_asset)
            except Exception:
                pass
        else:
            await emit("HTTP-only endpoint — no TLS to analyze")

        # 4. RSA/ECC demo endpoints
        for endpoint, key in [
            ("/api/crypto/rsa-demo", "rsa"),
            ("/api/crypto/ecc-demo", "ecc"),
            ("/api/crypto/aes-demo", "aes"),
        ]:
            try:
                resp = await client.get(urljoin(target_url, endpoint), headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    demo_assets = _parse_demo_crypto(data, key, urljoin(target_url, endpoint))
                    assets.extend(demo_assets)
                await asyncio.sleep(0.1)
            except Exception:
                pass

    await emit(f"Cryptographic discovery complete: {len(assets)} assets identified")
    return assets


def _parse_crypto_config(config: dict, target_url: str) -> list[CryptoAssetInfo]:
    """Parse the crypto config response into CryptoAssetInfo objects."""
    assets = []

    # TLS
    tls = config.get("tls", {})
    if tls:
        cert = tls.get("certificate", {})
        algo = cert.get("algorithm", "RSA")
        key_size = cert.get("key_size", 2048)
        asset = _classify_algorithm(algo, key_size, "TLS", target_url, "tls_certificate")
        assets.append(asset)

        # Cipher suites
        for cipher in tls.get("cipher_suites", []):
            cipher_algo = _cipher_to_algo(cipher)
            if cipher_algo:
                a = _classify_algorithm(cipher_algo, None, "TLS", target_url, "cipher_suite")
                assets.append(a)

    # JWT
    jwt_config = config.get("jwt", {})
    if jwt_config:
        algo = jwt_config.get("algorithm", "HS256")
        a = _classify_algorithm(algo, None, "JWT", urljoin(target_url, "/api/auth"), "jwt_signing")
        assets.append(a)

    # Session
    session = config.get("session", {})
    if session.get("mechanism") == "JWT":
        pass  # Already handled

    # Hashing
    hashing = config.get("hashing", {})
    for purpose, algo in hashing.items():
        a = _classify_algorithm(algo, None, "Application", target_url, f"hashing_{purpose}")
        assets.append(a)

    return assets


def _analyze_jwt(token: str, target_url: str) -> list[CryptoAssetInfo]:
    """Decode JWT header to find signing algorithm."""
    import base64, json as jsonlib
    assets = []
    try:
        header_b64 = token.split(".")[0]
        header_b64 += "=" * (4 - len(header_b64) % 4)
        header = jsonlib.loads(base64.urlsafe_b64decode(header_b64))
        algo = header.get("alg", "HS256")
        a = _classify_algorithm(algo, None, "JWT", urljoin(target_url, "/api/auth"), "jwt_signing")
        a.details["jwt_header"] = header
        assets.append(a)
    except Exception:
        pass
    return assets


def _assess_tls_from_response(resp: httpx.Response, target_url: str) -> Optional[CryptoAssetInfo]:
    """Try to extract TLS info from response headers."""
    # Check for any TLS-related headers
    return None  # Advanced TLS inspection requires direct socket access


def _parse_demo_crypto(data: dict, key_type: str, endpoint: str) -> list[CryptoAssetInfo]:
    """Parse crypto demo endpoint responses."""
    assets = []
    if key_type == "rsa":
        for key_size in data.get("key_sizes_in_use", [2048]):
            a = _classify_algorithm("RSA", key_size, "Application", endpoint, "key_encryption")
            assets.append(a)
    elif key_type == "ecc":
        curve = data.get("curve", "P-256")
        key_size = data.get("key_size_bits", 256)
        algo = "ECDSA"
        a = _classify_algorithm(algo, key_size, "Application", endpoint, "digital_signature")
        a.details["curve"] = curve
        assets.append(a)
    elif key_type == "aes":
        for key_size in [k for k in [128, 256] if k in data.get("grover_analysis", {})]:
            a = _classify_algorithm(f"AES-{key_size}", key_size, "Application", endpoint, "symmetric_encryption")
            assets.append(a)
    return assets


def _classify_algorithm(
    algorithm: str,
    key_size: Optional[int],
    protocol: str,
    endpoint: str,
    usage: str,
) -> CryptoAssetInfo:
    """Look up algorithm in quantum DB and classify it."""
    db_entry = ALGORITHM_QUANTUM_DB.get(algorithm, {})

    # Handle AES with key size
    if algorithm == "AES" and key_size:
        specific_key = f"AES-{key_size}"
        db_entry = ALGORITHM_QUANTUM_DB.get(specific_key, db_entry)
        algorithm = specific_key

    quantum_attack = db_entry.get("quantum_attack", "unknown")
    quantum_security = db_entry.get("quantum_security", "UNKNOWN")
    pqc_migration = db_entry.get("pqc_migration", "UNKNOWN")

    # Classical security
    if algorithm.startswith("RSA"):
        ks = key_size or 2048
        if ks <= 1024:
            classical_security = "WEAK"
        elif ks >= 2048:
            classical_security = "STRONG"
        else:
            classical_security = "ADEQUATE"
    elif algorithm.startswith("AES"):
        ks = key_size or 128
        classical_security = "STRONG" if ks >= 256 else ("ADEQUATE" if ks >= 192 else "WEAK")
    elif "SHA-1" in algorithm or "MD5" in algorithm:
        classical_security = "CRITICAL_WEAK"
    elif "SHA-256" in algorithm or "SHA-384" in algorithm or "SHA-512" in algorithm:
        classical_security = "STRONG"
    else:
        classical_security = "UNKNOWN"

    # Risk score (0-100, higher = more risky)
    risk = _calculate_crypto_risk(quantum_security, classical_security, key_size)

    return CryptoAssetInfo(
        algorithm=algorithm,
        key_size=key_size,
        protocol=protocol,
        endpoint=endpoint,
        usage=usage,
        classical_security=classical_security,
        quantum_security=quantum_security,
        quantum_attack=quantum_attack,
        pqc_status=pqc_migration,
        risk_score=risk,
        details={
            "reason": db_entry.get("reason", ""),
            "grover_effective_bits": db_entry.get("grover_effective_bits"),
        },
    )


def _calculate_crypto_risk(quantum_security: str, classical_security: str, key_size: Optional[int]) -> float:
    """Calculate quantum risk score 0-100."""
    base = 50.0
    if quantum_security == "VULNERABLE":
        base = 75.0
    elif quantum_security == "PARTIALLY_VULNERABLE":
        base = 55.0
    elif quantum_security == "RESISTANT":
        base = 15.0
    elif quantum_security == "CRITICAL_WEAK":
        base = 95.0
    elif quantum_security == "ADEQUATE":
        base = 30.0

    # Classical modifier
    if classical_security == "CRITICAL_WEAK":
        base = min(100.0, base + 20.0)
    elif classical_security == "WEAK":
        base = min(100.0, base + 10.0)
    elif classical_security == "STRONG":
        base = max(0.0, base - 5.0)

    return round(base, 1)


def _cipher_to_algo(cipher_suite: str) -> Optional[str]:
    """Map a TLS cipher suite name to a crypto algorithm."""
    cipher_upper = cipher_suite.upper()
    if "ECDHE" in cipher_upper:
        return "ECDHE"
    if "RSA" in cipher_upper and "ECDHE" not in cipher_upper:
        return "RSA"
    if "DH" in cipher_upper and "ECDH" not in cipher_upper:
        return "DH"
    if "AES_128" in cipher_upper:
        return "AES-128"
    if "AES_256" in cipher_upper:
        return "AES-256"
    return None
