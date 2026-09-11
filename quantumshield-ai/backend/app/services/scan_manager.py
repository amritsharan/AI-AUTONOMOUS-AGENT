"""Scan Manager — background task runner for security scans."""
import asyncio
import json
import logging
from datetime import datetime
from typing import Dict

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import AsyncSessionLocal
from app.database.models import Scan, Target, ScanStatus
from app.policy.engine import ScopeConfig
from app.agents.orchestrator import ScanOrchestrator
from app.services.websocket_manager import manager as ws_manager

logger = logging.getLogger(__name__)

# Track running scan tasks
_running_scans: Dict[str, asyncio.Task] = {}


async def start_scan_background(scan_id: str):
    """Start a scan in the background."""
    task = asyncio.create_task(_run_scan_task(scan_id))
    _running_scans[scan_id] = task
    task.add_done_callback(lambda t: _running_scans.pop(scan_id, None))
    logger.info(f"Scan {scan_id} started in background")


async def _run_scan_task(scan_id: str):
    """Execute the scan in an async background task."""
    async with AsyncSessionLocal() as db:
        try:
            from sqlalchemy import select
            result = await db.execute(select(Scan).where(Scan.id == scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return

            # Load target
            target_result = await db.execute(select(Target).where(Target.id == scan.target_id))
            target = target_result.scalar_one_or_none()
            if not target:
                logger.error(f"Target for scan {scan_id} not found")
                return

            # Build scope config
            allowed_hosts = json.loads(target.allowed_hosts or "[]") or [_extract_host(target.url)]
            allowed_ports = json.loads(target.allowed_ports or "[8080, 8000, 80, 443]")

            scope = ScopeConfig(
                target=target.url,
                environment=target.environment or "lab",
                allowed_hosts=allowed_hosts,
                allowed_ports=allowed_ports,
                destructive_tests=target.destructive_tests,
                max_requests_per_minute=target.max_requests_per_minute or 60,
                test_account_username="alice",
                test_account_password="Alice@123",
            )

            # Event callback for WebSocket broadcast
            async def event_callback(data: dict):
                await ws_manager.broadcast(scan_id, data)

            orchestrator = ScanOrchestrator(db, event_callback)
            await orchestrator.run_scan(scan, scope)

        except asyncio.CancelledError:
            logger.info(f"Scan {scan_id} was cancelled")
            raise
        except Exception as e:
            logger.error(f"Scan task {scan_id} failed: {e}", exc_info=True)


def _extract_host(url: str) -> str:
    from urllib.parse import urlparse
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def cancel_scan(scan_id: str) -> bool:
    """Cancel a running scan."""
    task = _running_scans.get(scan_id)
    if task and not task.done():
        task.cancel()
        return True
    return False


def get_running_scans() -> list:
    return list(_running_scans.keys())
