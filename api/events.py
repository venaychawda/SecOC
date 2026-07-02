"""Helper to push DEM/ECU-state updates to connected WebSocket clients."""
from api.state import state
from api.websocket import manager


async def broadcast_updates() -> None:
    """Broadcast any new DEM events and the current ECU state."""
    for event in state.new_dem_events():
        await manager.broadcast_dem_event(event)
    await manager.broadcast_ecu_state(state.get_status())
