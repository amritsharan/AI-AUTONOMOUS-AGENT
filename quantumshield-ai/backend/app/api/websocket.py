"""WebSocket router for live scan events."""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.services.websocket_manager import manager

ws_router = APIRouter()


@ws_router.websocket("/api/scans/{scan_id}/stream")
async def scan_stream(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for live scan event streaming."""
    await manager.connect(scan_id, websocket)
    try:
        while True:
            # Keep connection alive; server pushes events
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
    except Exception:
        manager.disconnect(scan_id, websocket)
