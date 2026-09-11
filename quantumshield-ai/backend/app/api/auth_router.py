"""Reports and Auth API routers."""
from fastapi import APIRouter

# ─── Auth Router (minimal for demo) ─────────────────────────────────────────
router = APIRouter()


@router.get("/status")
async def auth_status():
    return {"authenticated": True, "user": {"id": "demo-user-001", "username": "demo", "role": "admin"}}
