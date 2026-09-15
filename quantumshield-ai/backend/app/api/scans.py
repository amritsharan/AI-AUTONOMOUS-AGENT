"""Scans API router."""
import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.database.models import Scan, Target, AgentEvent, Finding, CryptoAsset, ScanStatus
from app.services.scan_manager import start_scan_background, cancel_scan

router = APIRouter()


class ScanCreate(BaseModel):
    project_id: str
    target_id: str
    name: str
    scan_type: str = "full"  # classical | quantum | full


class ScanResponse(BaseModel):
    id: str
    project_id: str
    target_id: str
    name: str
    scan_type: str
    status: str
    current_state: Optional[str]
    security_score: Optional[float]
    quantum_score: Optional[float]
    total_tests: int
    completed_tests: int
    endpoints_discovered: int
    quantum_assets_found: int
    pqc_readiness: Optional[float]
    error_message: Optional[str]
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=list[ScanResponse])
async def list_scans(project_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    q = select(Scan)
    if project_id:
        q = q.where(Scan.project_id == project_id)
    result = await db.execute(q.order_by(Scan.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=ScanResponse, status_code=201)
async def create_scan(
    data: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    # Verify target exists
    target_result = await db.execute(select(Target).where(Target.id == data.target_id))
    target = target_result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    scan = Scan(
        project_id=data.project_id,
        target_id=data.target_id,
        name=data.name,
        scan_type=data.scan_type,
        status=ScanStatus.PENDING,
        total_tests=0,
        completed_tests=0,
        endpoints_discovered=0,
        quantum_assets_found=0,
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # Start scan in background
    background_tasks.add_task(start_scan_background, scan.id)

    return scan


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.get("/{scan_id}/events")
async def get_scan_events(scan_id: str, limit: int = 100, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(AgentEvent)
        .where(AgentEvent.scan_id == scan_id)
        .order_by(AgentEvent.timestamp.asc())
        .limit(limit)
    )
    events = result.scalars().all()
    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "agent": e.agent,
            "message": e.message,
            "reason": e.reason,
            "tool": e.tool,
            "target": e.target,
            "result": e.result,
            "decision": e.decision,
            "state": e.state,
            "timestamp": e.timestamp.isoformat(),
        }
        for e in events
    ]


@router.get("/{scan_id}/findings")
async def get_scan_findings(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Finding).where(Finding.scan_id == scan_id).order_by(Finding.risk_score.desc())
    )
    findings = result.scalars().all()
    return [
        {
            "id": f.id,
            "title": f.title,
            "category": f.category,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "confidence": f.confidence,
            "endpoint": f.endpoint,
            "description": f.description,
            "risk_score": f.risk_score,
            "quantum_risk": f.quantum_risk,
            "status": f.status,
            "first_detected": f.first_detected.isoformat() if f.first_detected else None,
            "last_verified": f.last_verified.isoformat() if f.last_verified else None,
        }
        for f in findings
    ]


@router.get("/{scan_id}/crypto")
async def get_scan_crypto(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(CryptoAsset).where(CryptoAsset.scan_id == scan_id)
    )
    assets = result.scalars().all()
    return [
        {
            "id": a.id,
            "algorithm": a.algorithm,
            "key_size": a.key_size,
            "protocol": a.protocol,
            "endpoint": a.endpoint,
            "usage": a.usage,
            "classical_security": a.classical_security,
            "quantum_security": a.quantum_security,
            "quantum_attack": a.quantum_attack,
            "pqc_status": a.pqc_status,
            "risk_score": a.risk_score,
            "details": json.loads(a.details or "{}"),
        }
        for a in assets
    ]


@router.get("/{scan_id}/quantum")
async def get_scan_quantum(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get quantum security summary for a scan."""
    from app.quantum.pqc_assessment import assess_pqc_readiness
    from app.engines.core import calculate_quantum_risk_score

    crypto_result = await db.execute(select(CryptoAsset).where(CryptoAsset.scan_id == scan_id))
    assets = crypto_result.scalars().all()

    crypto_data = [
        {"algorithm": a.algorithm, "key_size": a.key_size,
         "quantum_security": a.quantum_security, "usage": a.usage or ""}
        for a in assets
    ]

    quantum_score = calculate_quantum_risk_score(crypto_data)
    pqc = assess_pqc_readiness(crypto_data)

    return {
        "quantum_score": quantum_score,
        "pqc_assessment": pqc,
        "crypto_assets": crypto_data,
        "shor_vulnerable": [a.algorithm for a in assets if a.quantum_attack == "shor"],
        "grover_vulnerable": [a.algorithm for a in assets if a.quantum_attack == "grover"],
    }


@router.post("/{scan_id}/cancel")
async def cancel_scan_endpoint(scan_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = result.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    cancelled = cancel_scan(scan_id)
    if cancelled:
        scan.status = ScanStatus.CANCELLED
        await db.commit()
        return {"message": "Scan cancelled"}
    return {"message": "Scan was not running"}


@router.get("/{scan_id}/attack-graph")
async def get_scan_attack_graph(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Generate the interactive attack surface & dependency graph."""
    from app.services.attack_graph import generate_attack_graph
    from app.database.models import Endpoint

    scan_res = await db.execute(select(Scan).where(Scan.id == scan_id))
    scan = scan_res.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    target_res = await db.execute(select(Target).where(Target.id == scan.target_id))
    target = target_res.scalar_one_or_none()

    findings_res = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    findings = findings_res.scalars().all()

    crypto_res = await db.execute(select(CryptoAsset).where(CryptoAsset.scan_id == scan_id))
    crypto_assets = crypto_res.scalars().all()

    endpoints_res = await db.execute(select(Endpoint).where(Endpoint.scan_id == scan_id))
    endpoints = endpoints_res.scalars().all()

    graph = generate_attack_graph(
        target_name=target.name if target else scan.name,
        target_url=target.url if target else "http://target.local",
        endpoints=endpoints,
        findings=findings,
        crypto_assets=crypto_assets,
    )
    return graph


@router.get("/{scan_id}/diff")
async def get_scan_diff_auto(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Compute scan diff / regression against the immediate previous scan on the same target."""
    from app.services.scan_diff import compute_scan_diff

    scan_res = await db.execute(select(Scan).where(Scan.id == scan_id))
    current_scan = scan_res.scalar_one_or_none()
    if not current_scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Find previous scan on same target
    prev_res = await db.execute(
        select(Scan)
        .where(Scan.target_id == current_scan.target_id, Scan.id != scan_id, Scan.created_at < current_scan.created_at)
        .order_by(Scan.created_at.desc())
        .limit(1)
    )
    prev_scan = prev_res.scalar_one_or_none()

    curr_findings_res = await db.execute(select(Finding).where(Finding.scan_id == scan_id))
    curr_findings = curr_findings_res.scalars().all()

    prev_findings = []
    if prev_scan:
        prev_f_res = await db.execute(select(Finding).where(Finding.scan_id == prev_scan.id))
        prev_findings = prev_f_res.scalars().all()

    diff_data = compute_scan_diff(curr_findings, prev_findings)
    diff_data["previous_scan_id"] = prev_scan.id if prev_scan else None
    diff_data["current_scan_id"] = scan_id
    return diff_data

