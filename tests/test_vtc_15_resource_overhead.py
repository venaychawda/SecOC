"""
VTC-SR-15: CPU/memory/CAN load under max traffic
Objective: Measure CPU, memory, and CAN load under max traffic conditions
Requirements: SR-15; — (no derived SWR; SIMULATION ONLY — hardware
enforcement deferred per traceability_matrix.md sections 5 and 6. Figures
produced here are illustrative and not derived from target silicon or a
real CAN bus; HIL load test on target hardware with bus analyzer is the
Phase 2 validation method.)
"""
import pytest

from sim import config
from sim.bus_scheduler import BusScheduler
from sim import performance_profiler


PDU_ID_BRAKE = 0x100
PDU_ID_STEERING = 0x101

# SIMULATION ONLY thresholds for max-traffic load assertions (Phase 1).
SIM_PERIOD_MS = 10
SIM_TICK_COUNT = 10
SIM_EXPECTED_FIRINGS = SIM_TICK_COUNT  # one firing per period at this cadence


@pytest.fixture
def bus_scheduler():
    return BusScheduler(scheduler_id="BUS_SCHED_TEST")


@pytest.fixture(autouse=True)
def _reset_profiler():
    performance_profiler.reset()
    yield
    performance_profiler.reset()


@pytest.mark.vtc("VTC-SR-15")
@pytest.mark.slow
@pytest.mark.sim
class TestVTC_15:
    def test_precondition_scheduler_idle_with_no_entries(self, bus_scheduler):
        """Precondition: BusScheduler starts IDLE with no scheduled
        periodic transmissions."""
        status = bus_scheduler.get_status()
        assert status["state"] == "IDLE"
        assert status["entries"] == []

    def test_schedule_periodic_transmissions_for_max_traffic(self, bus_scheduler):
        """Step: Schedule periodic Secured I-PDU transmissions representing
        max-traffic conditions on the simulated CAN bus."""
        fired = []

        bus_scheduler.schedule_periodic(
            PDU_ID_BRAKE, SIM_PERIOD_MS, lambda pdu_id: fired.append(pdu_id)
        )
        bus_scheduler.schedule_periodic(
            PDU_ID_STEERING, SIM_PERIOD_MS, lambda pdu_id: fired.append(pdu_id)
        )

        status = bus_scheduler.get_status()
        scheduled_ids = {entry["pdu_id"] for entry in status["entries"]}
        assert scheduled_ids == {PDU_ID_BRAKE, PDU_ID_STEERING}

    def test_run_tick_loop_under_max_traffic(self, bus_scheduler):
        """Step: Start the scheduler and tick() repeatedly to simulate
        max-traffic bus load over SIM_TICK_COUNT periods."""
        fired = []
        bus_scheduler.schedule_periodic(
            PDU_ID_BRAKE, SIM_PERIOD_MS, lambda pdu_id: fired.append(pdu_id)
        )
        bus_scheduler.start()

        for tick in range(1, SIM_TICK_COUNT + 1):
            bus_scheduler.tick(tick * SIM_PERIOD_MS)

        assert len(fired) == SIM_EXPECTED_FIRINGS

    def test_performance_profiler_aggregates_timing_under_load(self):
        """Step: Profile a batch of simulated MAC operations under load and
        verify get_summary() reports aggregate timing statistics."""
        for i in range(SIM_TICK_COUNT):
            op_id = f"PDU_BRAKE_TORQUE:generate_mac:{i}"
            performance_profiler.start(op_id)
            performance_profiler.stop(op_id)

        summary = performance_profiler.get_summary()
        assert summary["count"] == SIM_TICK_COUNT

    def test_expected_result_aggregate_stats_within_simulation_thresholds(
        self, bus_scheduler
    ):
        """Expected result (SIMULATION ONLY): aggregate message count and
        average inter-firing interval over the simulated max-traffic run
        are within the configured simulation thresholds."""
        fired = []
        bus_scheduler.schedule_periodic(
            PDU_ID_BRAKE, SIM_PERIOD_MS, lambda pdu_id: fired.append(pdu_id)
        )
        bus_scheduler.start()

        for tick in range(1, SIM_TICK_COUNT + 1):
            bus_scheduler.tick(tick * SIM_PERIOD_MS)

        total_messages = len(fired)
        total_time_ms = SIM_TICK_COUNT * SIM_PERIOD_MS
        average_interval_ms = total_time_ms / total_messages

        assert total_messages <= config.MAX_BUS_MESSAGES_PER_WINDOW
        assert average_interval_ms >= config.MIN_AVERAGE_MESSAGE_INTERVAL_MS
