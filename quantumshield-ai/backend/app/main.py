"""
QuantumShield AI — FastAPI Main Application
All routers registered here.
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text

from app.database.session import engine, Base
from app.database import models  # Register all ORM models

# Import routers
from app.api.projects import router as projects_router
from app.api.targets import router as targets_router
from app.api.scans import router as scans_router
from app.api.findings import router as findings_router
from app.api.quantum_router import router as quantum_router
from app.api.dashboard import router as dashboard_router
from app.api.reports import router as reports_router
from app.api.auth_router import router as auth_router
from app.api.websocket import ws_router
from app.api.ngrok_router import router as ngrok_router

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """App startup/shutdown lifecycle."""
    logger.info("Starting QuantumShield AI backend...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created/verified.")
    yield
    logger.info("Shutting down QuantumShield AI backend...")


app = FastAPI(
    title="QuantumShield AI",
    description="AI-powered Classical + Quantum Security Testing Platform",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — allow frontend dev server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(auth_router, prefix="/api/auth", tags=["auth"])
app.include_router(projects_router, prefix="/api/projects", tags=["projects"])
app.include_router(targets_router, prefix="/api/targets", tags=["targets"])
app.include_router(scans_router, prefix="/api/scans", tags=["scans"])
app.include_router(findings_router, prefix="/api/findings", tags=["findings"])
app.include_router(quantum_router, prefix="/api/quantum", tags=["quantum"])
app.include_router(dashboard_router, prefix="/api/dashboard", tags=["dashboard"])
app.include_router(reports_router, prefix="/api/reports", tags=["reports"])
app.include_router(ws_router)  # WebSocket — no prefix (uses /api/scans/{id}/stream path directly)
app.include_router(ngrok_router, prefix="/api/ngrok", tags=["ngrok"])


@app.get("/health")
async def health():
    return {"status": "healthy", "service": "QuantumShield AI", "version": "1.0.0"}


@app.get("/")
async def root():
    return {
        "service": "QuantumShield AI Backend",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
    }
