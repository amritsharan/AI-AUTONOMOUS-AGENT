"""WebSocket connection manager for live scan events."""
import asyncio
import json
import logging
from typing import Dict, Set
from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """Manages WebSocket connections grouped by scan_id."""

    def __init__(self):
        self.connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, scan_id: str, websocket: WebSocket):
        await websocket.accept()
        if scan_id not in self.connections:
            self.connections[scan_id] = set()
        self.connections[scan_id].add(websocket)
        logger.info(f"WebSocket connected for scan {scan_id}. Total: {len(self.connections[scan_id])}")

    def disconnect(self, scan_id: str, websocket: WebSocket):
        if scan_id in self.connections:
            self.connections[scan_id].discard(websocket)
            if not self.connections[scan_id]:
                del self.connections[scan_id]
        logger.info(f"WebSocket disconnected for scan {scan_id}")

    async def broadcast(self, scan_id: str, data: dict):
        """Broadcast a message to all connected clients for a scan."""
        if scan_id not in self.connections:
            return

        dead_connections = set()
        message = json.dumps(data)

        for ws in list(self.connections.get(scan_id, set())):
            try:
                await ws.send_text(message)
            except Exception:
                dead_connections.add(ws)

        # Clean up dead connections
        for ws in dead_connections:
            self.connections[scan_id].discard(ws)


# Global singleton
manager = WebSocketManager()
