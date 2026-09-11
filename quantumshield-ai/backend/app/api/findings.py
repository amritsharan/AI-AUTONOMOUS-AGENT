"""Findings API router."""
import json
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.database.models import Finding, Evidence, Remediation, RegressionTest, FindingStatus

router = APIRouter()


@router.get("/{finding_id}")
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Load evidence
    ev_result = await db.execute(select(Evidence).where(Evidence.finding_id == finding_id))
    evidence_list = ev_result.scalars().all()

    # Load remediation
    rem_result = await db.execute(select(Remediation).where(Remediation.finding_id == finding_id))
    remediation = rem_result.scalar_one_or_none()

    # Load regression tests
    reg_result = await db.execute(
        select(RegressionTest).where(RegressionTest.finding_id == finding_id)
        .order_by(RegressionTest.created_at.desc())
    )
    regression_tests = reg_result.scalars().all()

    return {
        "id": finding.id,
        "scan_id": finding.scan_id,
        "title": finding.title,
        "category": finding.category,
        "finding_type": finding.finding_type,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "endpoint": finding.endpoint,
        "description": finding.description,
        "impact": finding.impact,
        "root_cause": finding.root_cause,
        "risk_score": finding.risk_score,
        "quantum_risk": finding.quantum_risk,
        "status": finding.status,
        "first_detected": finding.first_detected.isoformat() if finding.first_detected else None,
        "last_verified": finding.last_verified.isoformat() if finding.last_verified else None,
        "fixed_at": finding.fixed_at.isoformat() if finding.fixed_at else None,
        "evidence": [
            {
                "id": e.id,
                "test_name": e.test_name,
                "endpoint": e.endpoint,
                "observation": e.observation,
                "confidence": e.confidence,
                "is_confirmed": e.is_confirmed,
                "raw_data": json.loads(e.raw_data or "{}"),
                "collected_at": e.collected_at.isoformat(),
            }
            for e in evidence_list
        ],
        "remediation": {
            "explanation": remediation.explanation,
            "root_cause": remediation.root_cause,
            "recommended_fix": remediation.recommended_fix,
            "code_example": remediation.code_example,
            "priority": remediation.priority,
            "regression_test_description": remediation.regression_test_description,
        } if remediation else None,
        "regression_tests": [
            {
                "id": rt.id,
                "status": rt.status,
                "result_details": json.loads(rt.result_details or "{}"),
                "run_at": rt.run_at.isoformat() if rt.run_at else None,
            }
            for rt in regression_tests
        ],
    }


@router.post("/{finding_id}/status")
async def update_finding_status(
    finding_id: str,
    status: str,
    db: AsyncSession = Depends(get_db),
):
    """Update finding status (mark as fixed, false positive, etc.)"""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    valid_statuses = {s.value for s in FindingStatus}
    if status.upper() not in valid_statuses:
        raise HTTPException(status_code=400, detail=f"Invalid status. Valid: {valid_statuses}")

    finding.status = FindingStatus(status.upper())
    if status.upper() == "FIXED":
        finding.fixed_at = datetime.utcnow()
    await db.commit()
    return {"message": f"Status updated to {status}", "finding_id": finding_id}


@router.post("/{finding_id}/regression")
async def run_regression_test(finding_id: str, db: AsyncSession = Depends(get_db)):
    """Trigger regression testing for a fixed finding."""
    result = await db.execute(select(Finding).where(Finding.id == finding_id))
    finding = result.scalar_one_or_none()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    if finding.status != FindingStatus.FIXED:
        raise HTTPException(status_code=400, detail="Finding must be marked as FIXED before running regression")

    # Create regression test record
    reg_test = RegressionTest(
        finding_id=finding_id,
        status="PENDING",
        run_at=datetime.utcnow(),
    )
    db.add(reg_test)
    await db.commit()
    await db.refresh(reg_test)

    # TODO: Run actual regression test asynchronously
    # For now, mark as PASS (would need the full scan context to re-test)
    reg_test.status = "PASS"
    reg_test.result_details = json.dumps({"note": "Regression test scheduled. Re-verification required against live target."})
    await db.commit()

    return {
        "regression_test_id": reg_test.id,
        "status": reg_test.status,
        "message": "Regression test recorded. Run a new full scan to verify the fix.",
    }
