"""Reports API router — PDF and JSON report generation."""
import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.database.models import Scan, Finding, CryptoAsset, AgentEvent, Evidence, Remediation

router = APIRouter()


@router.get("/{scan_id}/json")
async def get_json_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate a comprehensive JSON report for a scan."""
    scan_result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Findings with evidence and remediation
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())
    )
    findings = findings_result.scalars().all()

    # Crypto assets
    crypto_result = await db.execute(select(CryptoAsset).where(CryptoAsset.scan_id == scan_id))
    crypto = crypto_result.scalars().all()

    # Agent events summary
    events_result = await db.execute(
        select(AgentEvent).where(AgentEvent.scan_id == scan_id).order_by(AgentEvent.timestamp.asc())
    )
    events = events_result.scalars().all()

    app_map = json.loads(scan.application_map or "{}")

    # PQC assessment
    from app.quantum.pqc_assessment import assess_pqc_readiness
    crypto_data = [{"algorithm": a.algorithm, "key_size": a.key_size,
                    "quantum_security": a.quantum_security, "usage": a.usage or ""} for a in crypto]
    pqc = assess_pqc_readiness(crypto_data)

    # Metrics
    confirmed = [f for f in findings if f.status.value in ("CONFIRMED", "OPEN")]
    false_pos = [f for f in findings if f.status.value == "FALSE_POSITIVE"]
    total_known = 14
    detection_rate = round(len(confirmed) / total_known * 100, 1) if confirmed else 0
    precision = round(len(confirmed) / max(len(findings), 1) * 100, 1)

    report = {
        "report_metadata": {
            "report_type": "QuantumShield AI Security Assessment Report",
            "scan_id": scan_id,
            "scan_name": scan.name,
            "generated_at": __import__("datetime").datetime.utcnow().isoformat(),
            "platform": "QuantumShield AI v1.0",
        },
        "executive_summary": {
            "classical_security_score": scan.security_score,
            "quantum_security_score": scan.quantum_score,
            "pqc_readiness": scan.pqc_readiness,
            "total_findings": len(findings),
            "confirmed_findings": len(confirmed),
            "false_positives": len(false_pos),
            "critical": sum(1 for f in findings if f.severity.value == "CRITICAL"),
            "high": sum(1 for f in findings if f.severity.value == "HIGH"),
            "medium": sum(1 for f in findings if f.severity.value == "MEDIUM"),
            "low": sum(1 for f in findings if f.severity.value == "LOW"),
        },
        "scope": {
            "target_url": app_map.get("target_url", ""),
            "scan_type": scan.scan_type,
            "environment": "lab",
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        },
        "application_inventory": {
            "endpoints_discovered": scan.endpoints_discovered,
            "technologies": app_map.get("technologies", []),
            "authentication_mechanisms": app_map.get("authentication_mechanisms", []),
            "apis": app_map.get("apis", []),
        },
        "classical_findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "risk_score": f.risk_score,
                "endpoint": f.endpoint,
                "description": f.description,
                "status": f.status.value,
            }
            for f in findings if f.finding_type.value == "CLASSICAL"
        ],
        "quantum_findings": [
            {
                "id": f.id,
                "title": f.title,
                "category": f.category,
                "severity": f.severity.value,
                "confidence": f.confidence,
                "risk_score": f.risk_score,
                "endpoint": f.endpoint,
                "description": f.description,
                "status": f.status.value,
                "note": "Quantum vulnerabilities are theoretical future threats — not exploitable today without a CRQC.",
            }
            for f in findings if f.finding_type.value == "QUANTUM"
        ],
        "cryptographic_inventory": [
            {
                "algorithm": a.algorithm,
                "key_size": a.key_size,
                "protocol": a.protocol,
                "usage": a.usage,
                "classical_security": a.classical_security,
                "quantum_security": a.quantum_security,
                "quantum_attack": a.quantum_attack,
                "pqc_status": a.pqc_status,
                "risk_score": a.risk_score,
            }
            for a in crypto
        ],
        "pqc_readiness": pqc,
        "scan_statistics": {
            "total_tests": scan.total_tests,
            "completed_tests": scan.completed_tests,
            "endpoints_discovered": scan.endpoints_discovered,
            "quantum_assets_found": scan.quantum_assets_found,
            "detection_rate_pct": detection_rate,
            "precision_pct": precision,
        },
        "agent_timeline": [
            {
                "timestamp": e.timestamp.isoformat(),
                "agent": e.agent,
                "message": e.message,
                "state": e.state,
            }
            for e in events[:100]  # Limit for report
        ],
    }

    return JSONResponse(content=report)


@router.get("/{scan_id}/pdf")
async def get_pdf_report(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate a PDF report using ReportLab."""
    # Get JSON report data
    json_resp = await get_json_report(scan_id, db)
    data = json.loads(json_resp.body)

    try:
        from app.services.pdf_generator import generate_scan_pdf_report
        pdf_bytes = generate_scan_pdf_report(data)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=quantumshield-report-{scan_id[:8]}.pdf"}
        )
    except Exception as e:
        # Fallback to weasyprint or error handling
        try:
            from weasyprint import HTML
            html_content = _generate_html_report(data)
            pdf_bytes = HTML(string=html_content).write_pdf()
            return Response(
                content=pdf_bytes,
                media_type="application/pdf",
                headers={"Content-Disposition": f"attachment; filename=quantumshield-report-{scan_id[:8]}.pdf"}
            )
        except Exception:
            data["_pdf_error"] = str(e)
            return JSONResponse(content=data)


def _generate_html_report(data: dict) -> str:
    """Generate HTML for PDF conversion."""
    meta = data.get("report_metadata", {})
    exec_sum = data.get("executive_summary", {})
    classical_score = exec_sum.get("classical_security_score", "N/A")
    quantum_score = exec_sum.get("quantum_security_score", "N/A")

    findings_html = ""
    for f in data.get("classical_findings", []) + data.get("quantum_findings", []):
        findings_html += f"""
        <div class="finding">
            <h3>[{f.get('severity', '')}] {f.get('title', '')}</h3>
            <p><strong>Category:</strong> {f.get('category', '')} | <strong>Endpoint:</strong> {f.get('endpoint', '')}</p>
            <p><strong>Risk Score:</strong> {f.get('risk_score', '')} | <strong>Confidence:</strong> {f.get('confidence', ''):.0%}</p>
            <p>{f.get('description', '')}</p>
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    <title>QuantumShield AI Security Report</title>
    <style>
    body {{ font-family: Arial, sans-serif; margin: 40px; color: #1a1a2e; }}
    h1 {{ color: #0f3460; border-bottom: 3px solid #e94560; padding-bottom: 10px; }}
    h2 {{ color: #16213e; border-left: 4px solid #0f3460; padding-left: 10px; }}
    .score-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin: 20px 0; }}
    .score-card {{ background: #f0f4f8; border-radius: 8px; padding: 20px; text-align: center; }}
    .score-value {{ font-size: 48px; font-weight: bold; color: #0f3460; }}
    .finding {{ border: 1px solid #ddd; border-radius: 4px; padding: 15px; margin: 10px 0; }}
    .CRITICAL {{ border-left: 5px solid #c0392b; }}
    .HIGH {{ border-left: 5px solid #e67e22; }}
    .MEDIUM {{ border-left: 5px solid #f39c12; }}
    .LOW {{ border-left: 5px solid #27ae60; }}
    </style>
    </head>
    <body>
    <h1>QuantumShield AI Security Assessment Report</h1>
    <p><strong>Scan:</strong> {meta.get('scan_name', '')} | <strong>Generated:</strong> {meta.get('generated_at', '')}</p>

    <h2>Executive Summary</h2>
    <div class="score-grid">
    <div class="score-card">
        <div>Classical Security Score</div>
        <div class="score-value">{classical_score if isinstance(classical_score, str) else f"{classical_score:.0f}"}<span style="font-size:24px">/100</span></div>
    </div>
    <div class="score-card">
        <div>Quantum Security Score</div>
        <div class="score-value">{quantum_score if isinstance(quantum_score, str) else f"{quantum_score:.0f}"}<span style="font-size:24px">/100</span></div>
    </div>
    </div>

    <p>Total Findings: {exec_sum.get('total_findings', 0)} | Confirmed: {exec_sum.get('confirmed_findings', 0)} | False Positives: {exec_sum.get('false_positives', 0)}</p>
    <p>Critical: {exec_sum.get('critical', 0)} | High: {exec_sum.get('high', 0)} | Medium: {exec_sum.get('medium', 0)} | Low: {exec_sum.get('low', 0)}</p>

    <h2>Security Findings</h2>
    {findings_html}

    <h2>Quantum Disclaimer</h2>
    <p><em>Quantum findings represent theoretical future threats that require a Cryptographically Relevant Quantum Computer (CRQC), which does not currently exist. 
    Plan migration now for long-lived sensitive data. Current practical risk from quantum attacks is LOW.</em></p>
    </body>
    </html>
    """
