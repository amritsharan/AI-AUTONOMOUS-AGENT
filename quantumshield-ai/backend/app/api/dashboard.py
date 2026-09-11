"""Dashboard API router."""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.database.session import get_db
from app.database.models import Scan, Finding, CryptoAsset, ScanStatus, Severity, FindingType

router = APIRouter()


@router.get("/{project_id}")
async def get_dashboard(project_id: str, db: AsyncSession = Depends(get_db)):
    """Get comprehensive dashboard metrics for a project."""
    # Latest scan
    scan_result = await db.execute(
        select(Scan)
        .where(Scan.project_id == project_id)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    latest_scan = scan_result.scalar_one_or_none()

    # All scans stats
    all_scans_result = await db.execute(
        select(Scan).where(Scan.project_id == project_id)
    )
    all_scans = all_scans_result.scalars().all()

    # Findings aggregation
    findings_result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .where(Scan.project_id == project_id)
    )
    all_findings = findings_result.scalars().all()

    # Crypto assets
    crypto_result = await db.execute(
        select(CryptoAsset)
        .join(Scan, CryptoAsset.scan_id == Scan.id)
        .where(Scan.project_id == project_id)
    )
    all_crypto = crypto_result.scalars().all()

    # Count by severity
    severity_counts = {}
    for sv in Severity:
        severity_counts[sv.value] = sum(1 for f in all_findings if f.severity == sv)

    # Quantum stats
    shor_vulnerable = [a for a in all_crypto if a.quantum_attack == "shor"]
    quantum_findings = [f for f in all_findings if f.finding_type == FindingType.QUANTUM]
    classical_findings = [f for f in all_findings if f.finding_type == FindingType.CLASSICAL]
    confirmed_findings = [f for f in all_findings if f.status.value in ("CONFIRMED", "OPEN")]
    false_positives = [f for f in all_findings if f.status.value == "FALSE_POSITIVE"]

    # Detection rate vs known vulnerabilities
    total_known = 14  # From lab's /api/known-vulnerabilities
    detection_rate = min(100.0, len(confirmed_findings) / total_known * 100) if confirmed_findings else 0

    # Duration
    scan_duration = None
    if latest_scan and latest_scan.started_at and latest_scan.completed_at:
        duration = (latest_scan.completed_at - latest_scan.started_at).total_seconds()
        minutes = int(duration // 60)
        seconds = int(duration % 60)
        scan_duration = f"{minutes}m {seconds}s"

    return {
        "project_id": project_id,
        "latest_scan": {
            "id": latest_scan.id if latest_scan else None,
            "status": latest_scan.status.value if latest_scan else "NO_SCAN",
            "scan_type": latest_scan.scan_type if latest_scan else None,
            "started_at": latest_scan.started_at.isoformat() if latest_scan and latest_scan.started_at else None,
            "duration": scan_duration,
        } if latest_scan else None,
        "classical_security": {
            "score": latest_scan.security_score if latest_scan else None,
            "findings_by_severity": {
                "critical": severity_counts.get("CRITICAL", 0),
                "high": severity_counts.get("HIGH", 0),
                "medium": severity_counts.get("MEDIUM", 0),
                "low": severity_counts.get("LOW", 0),
                "informational": severity_counts.get("INFORMATIONAL", 0),
            },
            "confirmed_findings": len(confirmed_findings),
            "false_positives": len(false_positives),
            "detection_rate": round(detection_rate, 1),
        },
        "quantum_security": {
            "score": latest_scan.quantum_score if latest_scan else None,
            "pqc_readiness": latest_scan.pqc_readiness if latest_scan else None,
            "quantum_assets_total": len(all_crypto),
            "shor_vulnerable_assets": len(shor_vulnerable),
            "quantum_findings": len(quantum_findings),
            "algorithms_discovered": list({a.algorithm for a in all_crypto}),
        },
        "scan_statistics": {
            "total_scans": len(all_scans),
            "completed_scans": sum(1 for s in all_scans if s.status == ScanStatus.COMPLETED),
            "total_endpoints": latest_scan.endpoints_discovered if latest_scan else 0,
            "total_tests": latest_scan.total_tests if latest_scan else 0,
            "completed_tests": latest_scan.completed_tests if latest_scan else 0,
        },
        "finding_trends": [
            {
                "scan_id": s.id,
                "scan_name": s.name,
                "security_score": s.security_score,
                "quantum_score": s.quantum_score,
                "created_at": s.created_at.isoformat(),
            }
            for s in sorted(all_scans, key=lambda x: x.created_at)[-10:]
        ],
    }


@router.get("/global/stats")
async def global_stats(db: AsyncSession = Depends(get_db)):
    """Global platform statistics."""
    scan_count = await db.execute(select(func.count(Scan.id)))
    finding_count = await db.execute(select(func.count(Finding.id)))
    crypto_count = await db.execute(select(func.count(CryptoAsset.id)))

    return {
        "total_scans": scan_count.scalar() or 0,
        "total_findings": finding_count.scalar() or 0,
        "total_crypto_assets": crypto_count.scalar() or 0,
        "platform": "QuantumShield AI v1.0",
        "llm_available": __import__("app.agents.llm_provider", fromlist=["llm_provider"]).llm_provider.available,
    }
