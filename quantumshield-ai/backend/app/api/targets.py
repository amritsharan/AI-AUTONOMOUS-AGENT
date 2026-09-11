"""Targets API router."""
import json
import os
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.session import get_db
from app.database.models import Target

router = APIRouter()

LAB_TARGET_URL = os.getenv("LAB_TARGET_URL", "http://vulnerable-app:8080")


class TargetCreate(BaseModel):
    project_id: str
    name: str
    url: str
    environment: str = "lab"
    allowed_hosts: list[str] = []
    allowed_ports: list[int] = [8080, 8000, 80, 443]
    destructive_tests: bool = False
    max_requests_per_minute: int = 60
    notes: str = ""


class TargetResponse(BaseModel):
    id: str
    project_id: str
    name: str
    url: str
    environment: str
    allowed_hosts: Optional[str]
    allowed_ports: Optional[str]
    destructive_tests: bool
    max_requests_per_minute: int
    is_authorized: bool
    notes: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=list[TargetResponse])
async def list_targets(project_id: Optional[str] = None, db: AsyncSession = Depends(get_db)):
    q = select(Target)
    if project_id:
        q = q.where(Target.project_id == project_id)
    result = await db.execute(q.order_by(Target.created_at.desc()))
    return result.scalars().all()


@router.post("/", response_model=TargetResponse, status_code=201)
async def create_target(data: TargetCreate, db: AsyncSession = Depends(get_db)):
    # Determine allowed hosts
    allowed_hosts = data.allowed_hosts
    if not allowed_hosts:
        from urllib.parse import urlparse
        try:
            host = urlparse(data.url).hostname or data.url
            allowed_hosts = [host]
        except Exception:
            allowed_hosts = []

    target = Target(
        project_id=data.project_id,
        name=data.name,
        url=data.url,
        environment=data.environment,
        allowed_hosts=json.dumps(allowed_hosts),
        allowed_ports=json.dumps(data.allowed_ports),
        destructive_tests=data.destructive_tests,
        max_requests_per_minute=data.max_requests_per_minute,
        is_authorized=True,
        notes=data.notes,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return target


@router.get("/{target_id}", response_model=TargetResponse)
async def get_target(target_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target


@router.get("/lab/default")
async def get_lab_default_target():
    """Return default lab target configuration for demo."""
    from urllib.parse import urlparse
    host = urlparse(LAB_TARGET_URL).hostname or "vulnerable-app"
    port = urlparse(LAB_TARGET_URL).port or 8080
    return {
        "url": LAB_TARGET_URL,
        "environment": "lab",
        "allowed_hosts": [host, "localhost"],
        "allowed_ports": [port],
        "destructive_tests": False,
        "max_requests_per_minute": 60,
        "lab_users": [
            {"username": "alice", "password": "Alice@123", "role": "user"},
            {"username": "bob", "password": "Bob@456", "role": "user"},
        ],
        "known_vulnerabilities_endpoint": f"{LAB_TARGET_URL}/api/known-vulnerabilities",
    }
