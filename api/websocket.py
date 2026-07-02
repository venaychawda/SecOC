"""WebSocket event bus — broadcasts DEM events and ECU state changes in real time.

Drop-in FastAPI WebSocket infrastructure for automotive simulation projects.
Mount at /ws/events in your FastAPI app.
"""
import json
from typing import Any

from fastapi import WebSocket


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts events to all."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self._connections.remove(ws)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        """Send JSON payload to all connected clients."""
        message = json.dumps(payload, default=str)
        dead: list[WebSocket] = []
        for ws in self._connections:
            try:
                await ws.send_text(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.remove(ws)

    async def broadcast_dem_event(self, event: Any) -> None:
        """Broadcast a DEM event dict."""
        payload = {
            "type": "dem_event",
            "event_id": event.event_id,
            "severity": event.severity.value,
            "description": event.description,
            "swr_ref": event.swr_ref,
            "timestamp": event.timestamp,
            "data": event.data,
        }
        await self.broadcast(payload)

    async def broadcast_ecu_state(self, state_dict: dict) -> None:
        """Broadcast an ECU state change."""
        await self.broadcast({"type": "ecu_state", **state_dict})


manager = ConnectionManager()
