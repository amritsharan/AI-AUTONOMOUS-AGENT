"""
QuantumShield Services — Attack Surface & Dependency Graph Generator
Builds a node-link dependency graph of:
- Target Root Node
- Discovered Endpoints
- Discovered Cryptographic Primitives (CBOM)
- Discovered Vulnerabilities & CWEs
- Remediation Patch Nodes
"""

from typing import Any, Dict, List
from app.database.models import Finding, CryptoAsset, Endpoint


def generate_attack_graph(
    target_name: str,
    target_url: str,
    endpoints: List[Endpoint],
    findings: List[Finding],
    crypto_assets: List[CryptoAsset]
) -> Dict[str, Any]:
    """
    Generate graph nodes and directed links for visualization.
    """
    nodes = []
    links = []

    # Root Target Node
    root_id = "node-target-root"
    nodes.append({
        "id": root_id,
        "name": target_name or "Target Host",
        "type": "target",
        "category": "root",
        "details": target_url,
        "status": "active",
        "val": 25,
    })

    # Endpoints
    for idx, ep in enumerate(endpoints or []):
        ep_id = f"node-ep-{ep.id or idx}"
        nodes.append({
            "id": ep_id,
            "name": f"{ep.method} {ep.path}",
            "type": "endpoint",
            "category": "surface",
            "details": f"Auth required: {ep.auth_required}",
            "val": 12,
        })
        links.append({
            "source": root_id,
            "target": ep_id,
            "relation": "exposes",
        })

    # Crypto Assets
    for idx, crypto in enumerate(crypto_assets or []):
        cr_id = f"node-crypto-{crypto.id or idx}"
        is_vuln = getattr(crypto, "quantum_attack", None) in ("shor", "grover") or getattr(crypto, "quantum_security", "") == "VULNERABLE"
        nodes.append({
            "id": cr_id,
            "name": f"{crypto.algorithm} ({crypto.key_size or 'N/A'})",
            "type": "crypto",
            "category": "quantum_risk" if is_vuln else "quantum_safe",
            "details": f"Usage: {crypto.usage} | Shor/Grover Risk: {'HIGH' if is_vuln else 'LOW'}",
            "val": 14,
        })
        links.append({
            "source": root_id,
            "target": cr_id,
            "relation": "uses_crypto",
        })

    # Findings
    for idx, f in enumerate(findings or []):
        f_id = f"node-finding-{f.id or idx}"
        sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        nodes.append({
            "id": f_id,
            "name": f.title,
            "type": "finding",
            "category": f"severity_{sev.lower()}",
            "details": f"Risk Score: {getattr(f, 'risk_score', 0.0)} | Type: {getattr(f, 'category', 'VULNERABILITY')}",
            "val": 16 if sev == "CRITICAL" else (14 if sev == "HIGH" else 10),
        })
        
        # Link finding to matching endpoint or root
        linked_ep = next((f"node-ep-{ep.id or i}" for i, ep in enumerate(endpoints or []) if ep.path == f.endpoint), root_id)
        links.append({
            "source": linked_ep,
            "target": f_id,
            "relation": "vulnerable_to",
        })

    return {
        "nodes": nodes,
        "links": links,
        "metrics": {
            "total_nodes": len(nodes),
            "total_edges": len(links),
            "attack_surface_density": f"{len(findings)} issues across {len(endpoints)} endpoints",
        }
    }
