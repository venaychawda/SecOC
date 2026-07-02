"""SecOC simulation FastAPI backend (Phase 1, Step 5)."""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from api.routers import auth, diagnostics, secoc, test_scenarios
from api.state import state
from api.websocket import manager

app = FastAPI(title="SecOC Simulation API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(diagnostics.router)
app.include_router(secoc.router)
app.include_router(test_scenarios.router)


@app.get("/")
async def root() -> dict:
    """Health/info endpoint."""
    return {
        "service": "SecOC Simulation API",
        "ecu_state": state.get_status(),
    }


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> None:
    """Real-time DEM event + ECU state stream."""
    await manager.connect(websocket)
    try:
        await manager.broadcast_ecu_state(state.get_status())
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
