"""ECU state, reset, DEM event log, and telemetry endpoints."""
from fastapi import APIRouter

from api.events import broadcast_updates
from api.state import state
from sim import performance_profiler

router = APIRouter(tags=["diagnostics"])


@router.get("/ecu/state")
async def get_ecu_state() -> dict:
    """Return the current ECU/SecOC status."""
    return state.get_status()


@router.post("/ecu/reset")
async def reset_ecu() -> dict:
    """Reset the ECU to NORMAL_OPERATION and clear fault/lockout state."""
    state.reset_ecu()
    await broadcast_updates()
    return state.get_status()


@router.get("/events")
async def get_events(limit: int = 50) -> list[dict]:
    """Return the most recent DEM events.

    Args:
        limit: Maximum number of events to return (most recent last).
    """
    events = state.dem.get_events()[-limit:]
    return [
        {
            "event_id": e.event_id,
            "severity": e.severity.value,
            "description": e.description,
            "swr_ref": e.swr_ref,
            "timestamp": e.timestamp,
            "data": e.data,
        }
        for e in events
    ]


@router.get("/telemetry")
async def get_telemetry() -> dict:
    """Return combined ECU state, DEM summary, CAN bus, and profiler telemetry."""
    events = state.dem.get_events()
    severity_counts: dict[str, int] = {}
    for e in events:
        severity_counts[e.severity.value] = severity_counts.get(e.severity.value, 0) + 1

    return {
        "ecu_state": state.get_status(),
        "dem": {
            "total_events": len(events),
            "by_severity": severity_counts,
        },
        "can_bus": {
            "running": state.can_bus.is_running(),
            "queue_depth": len(state.can_bus._queue),
            "last_frames": {
                str(pdu_id): data.hex() for pdu_id, data in state.can_bus._last_frames.items()
            },
        },
        "performance": performance_profiler.get_summary(),
    }
