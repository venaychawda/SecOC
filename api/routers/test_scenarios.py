"""VTC scenario listing/run/result endpoints (SR-18)."""
from fastapi import APIRouter, HTTPException

from api.events import broadcast_updates
from api.state import state
from sim import scenario_runner

router = APIRouter(tags=["test_scenarios"])


def _result_to_dict(result: scenario_runner.ScenarioResult) -> dict:
    return {
        "vtc_id": result.vtc_id,
        "status": result.status.value,
        "steps": result.steps,
        "error_message": result.error_message,
    }


@router.get("/test/scenarios")
async def list_scenarios() -> list[str]:
    """Return all VTC-SR-01..20 scenario IDs."""
    return scenario_runner.list_scenarios()


@router.post("/test/{vtc_id}/run")
async def run_scenario(vtc_id: str) -> dict:
    """Run the scenario for vtc_id and return its result."""
    try:
        result = scenario_runner.run_scenario(vtc_id)
    except scenario_runner.UnknownScenarioError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    finally:
        # scenario_runner.reset_environment() resets the shared CanBus
        # singleton; restore the live bus to "running" for API clients.
        state.can_bus._running = True

    await broadcast_updates()
    return _result_to_dict(result)


@router.get("/test/{vtc_id}/result")
async def get_result(vtc_id: str) -> dict:
    """Return the most recently recorded result for vtc_id."""
    if vtc_id not in scenario_runner.list_scenarios():
        raise HTTPException(status_code=404, detail=f"unknown scenario id: {vtc_id}")

    result = scenario_runner.get_result(vtc_id)
    if result is None:
        raise HTTPException(status_code=404, detail=f"scenario {vtc_id} has not been run yet")
    return _result_to_dict(result)
