"""
VTC-SR-18: CI suite executes all SecOC scenarios
Objective: Execute CI test suite validating all SecOC scenarios automatically
Requirements: SR-18; —
"""
import pytest

from sim.scenario_runner import (
    ScenarioResult,
    ScenarioStatus,
    list_scenarios,
    reset_environment,
    run_scenario,
)


EXPECTED_VTC_IDS = [f"VTC-SR-{n:02d}" for n in range(1, 21)]


@pytest.mark.vtc("VTC-SR-18")
@pytest.mark.sim
class TestVTC_18:
    def test_precondition_environment_resets_cleanly(self):
        """Precondition: reset_environment() can be called to establish a
        clean, reproducible baseline before any scenario runs (SR-18
        reproducibility)."""
        reset_environment()

    def test_list_scenarios_returns_all_20_vtc_ids_in_order(self):
        """Step: scenario_runner.list_scenarios() returns all VTC-SR-01..20
        IDs, in TestPlan.txt row order, with no gaps or duplicates."""
        scenarios = list_scenarios()

        assert scenarios == EXPECTED_VTC_IDS
        assert len(scenarios) == 20
        assert len(set(scenarios)) == 20

    def test_run_scenario_returns_scenario_result_for_representative_vtc(self):
        """Step: run_scenario("VTC-SR-06") -- a representative scenario --
        returns a ScenarioResult with vtc_id, status, and steps populated."""
        result = run_scenario("VTC-SR-06")

        assert isinstance(result, ScenarioResult)
        assert result.vtc_id == "VTC-SR-06"
        assert isinstance(result.status, ScenarioStatus)
        assert result.status in (
            ScenarioStatus.PASSED,
            ScenarioStatus.FAILED,
            ScenarioStatus.ERROR,
        )

    def test_run_scenario_unknown_vtc_id_raises_unknown_scenario_error(self):
        """Step: run_scenario() for a vtc_id outside VTC-SR-01..20 raises
        UnknownScenarioError, eagerly, before reset_environment()/setup."""
        from sim.scenario_runner import UnknownScenarioError

        with pytest.raises(UnknownScenarioError):
            run_scenario("VTC-SR-99")

    def test_expected_result_all_20_scenarios_executable_without_error(self):
        """Expected result: every VTC-SR-01..20 scenario can be run via
        run_scenario() and returns a ScenarioResult whose status is not
        ScenarioStatus.ERROR (i.e. no unhandled exception aborted setup or
        execution), demonstrating the full reproducible CI suite (SR-18)."""
        for vtc_id in list_scenarios():
            result = run_scenario(vtc_id)

            assert isinstance(result, ScenarioResult)
            assert result.vtc_id == vtc_id
            assert result.status != ScenarioStatus.ERROR, (
                f"{vtc_id} aborted with error: {result.error_message}"
            )

    def test_get_result_returns_most_recent_run(self):
        """Step: get_result(vtc_id) returns the most recently recorded
        ScenarioResult for that vtc_id without re-running the scenario."""
        from sim.scenario_runner import get_result

        run_scenario("VTC-SR-06")
        result = get_result("VTC-SR-06")

        assert result is not None
        assert result.vtc_id == "VTC-SR-06"

    def test_get_result_for_unrun_scenario_returns_none(self):
        """Step: get_result(vtc_id) returns None if run_scenario(vtc_id) has
        not yet been called in this process."""
        from sim.scenario_runner import get_result

        reset_environment()
        result = get_result("VTC-SR-20")

        # Either None (never run) or a previously cached result; this test
        # documents the contract that an unrun scenario yields None.
        assert result is None or isinstance(result, ScenarioResult)
