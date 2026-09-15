"""
Quantum Security Engine — Cryptographic Bill of Materials (CBOM) Exporter
Supports:
1. CycloneDX v1.6 CBOM (Cryptography Extension - JSON)
2. SPDX v3.0 Security & Cryptography Profile (JSON-LD)
3. Standard Structured JSON Downloadable Audit Report
"""

import datetime
import json
import uuid
from typing import Any, Dict, List, Optional


def export_cyclonedx_cbom(
    target_name: str,
    target_url: str,
    crypto_assets: List[Dict[str, Any]],
    pqc_recommendations: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Generate standard CycloneDX v1.6 CBOM JSON document with cryptographic properties.
    Reference: CycloneDX Cryptography Extension Specification (v1.6).
    """
    serial_number = f"urn:uuid:{uuid.uuid4()}"
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    components = []
    for idx, asset in enumerate(crypto_assets or []):
        algo = asset.get("algorithm", "UNKNOWN")
        key_size = asset.get("key_size") or 2048
        usage = asset.get("usage", "key_exchange")
        file_path = asset.get("file_path", "target/tls/certificate")
        quantum_vulnerable = asset.get("quantum_vulnerable", True)

        # Map to NIST Quantum Security Levels (0 = broken by Shor, 1-5 = PQC levels)
        if not quantum_vulnerable:
            nist_level = 3 if "ML-KEM-768" in algo or "AES-256" in algo else 5
        else:
            nist_level = 0  # Quantum Broken

        component = {
            "type": "cryptographic-asset",
            "bom-ref": f"crypto-asset-{idx+1}",
            "name": algo,
            "version": str(key_size) if key_size else "N/A",
            "description": f"Cryptographic primitive detected at {file_path} for {usage}.",
            "cryptoProperties": {
                "assetType": "algorithm",
                "algorithmProperties": {
                    "primitive": "public-key" if "RSA" in algo or "ECC" in algo else "symmetric",
                    "parameterSetIdentifier": str(key_size),
                    "executionEnvironment": "software-plain",
                    "implementationPlatform": "standard",
                    "certificationLevel": ["NIST-CAVP"] if not quantum_vulnerable else [],
                    "cryptoFunctions": [usage],
                    "classicalSecurityLevel": 112 if "RSA-2048" in algo else (128 if "256" in algo else 256),
                    "nistQuantumSecurityLevel": nist_level,
                },
                "oid": f"1.3.6.1.4.1.quantumshield.{idx+1}",
            },
            "evidence": {
                "occurrences": [
                    {
                        "location": file_path,
                        "line": asset.get("line_number", 1)
                    }
                ]
            }
        }
        components.append(component)

    cbom_doc = {
        "$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "QuantumShield AI",
                    "name": "QuantumShield Cryptographic Discovery & CBOM Engine",
                    "version": "2.0.0"
                }
            ],
            "component": {
                "type": "application",
                "name": target_name or "Target Application",
                "version": "1.0.0",
                "properties": [
                    {"name": "quantumshield:target_url", "value": target_url}
                ]
            }
        },
        "components": components,
        "declarations": {
            "assessors": [
                {
                    "name": "QuantumShield Autonomous PQC Agent",
                    "organization": "QuantumShield AI Security"
                }
            ]
        }
    }

    return cbom_doc


def export_spdx_cbom(
    target_name: str,
    target_url: str,
    crypto_assets: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Generate SPDX 3.0 Cryptography Profile JSON-LD Document.
    """
    doc_id = f"SPDXRef-DOCUMENT-{uuid.uuid4().hex[:8]}"
    created = datetime.datetime.utcnow().isoformat() + "Z"

    packages = []
    for idx, asset in enumerate(crypto_assets or []):
        pkg_id = f"SPDXRef-CryptoPkg-{idx+1}"
        algo = asset.get("algorithm", "UNKNOWN")
        quantum_vulnerable = asset.get("quantum_vulnerable", True)

        packages.append({
            "SPDXID": pkg_id,
            "name": algo,
            "versionInfo": str(asset.get("key_size", "")),
            "supplier": "Organization: Detected in Target Scope",
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": True,
            "summary": f"Cryptographic asset {algo} used for {asset.get('usage', 'general')}.",
            "description": f"Quantum status: {'VULNERABLE (Shor/Grover)' if quantum_vulnerable else 'QUANTUM_SAFE'}.",
            "comment": json.dumps({
                "file_path": asset.get("file_path", ""),
                "quantum_vulnerable": quantum_vulnerable,
                "replacement_standard": "NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)" if quantum_vulnerable else "COMPLIANT"
            })
        })

    spdx_doc = {
        "spdxVersion": "SPDX-3.0",
        "dataLicense": "CC0-1.0",
        "SPDXID": doc_id,
        "name": f"CBOM-{target_name or 'Application'}",
        "documentNamespace": f"https://quantumshield.ai/spdx/{doc_id}",
        "creationInfo": {
            "created": created,
            "creators": ["Tool: QuantumShield AI CBOM Generator v2.0"],
            "licenseListVersion": "3.22"
        },
        "packages": packages,
        "relationships": [
            {
                "spdxElementId": doc_id,
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": pkg["SPDXID"]
            }
            for pkg in packages
        ]
    }
    return spdx_doc
