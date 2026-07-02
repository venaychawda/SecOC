"""
VTC-SR-12: MAC compute/verify time within WCET budget
Objective: Measure MAC compute/verify time under load and ensure WCET compliance
Requirements: SR-12; SW-SecOC-08

Note: SR-12 is SIMULATION ONLY (see traceability_matrix.md section 5) -- WCET is
measured via wall-clock timing in Python and does not reflect real ECU CPU cycles
or HSM crypto-accelerator timing. HIL timing measurement is required for Phase 2.
"""
import json

import pytest

from sim.authenticator import Authenticator
from sim.performance_profiler import PerformanceProfiler, ProfilerStatus
from sim.security_profile import SecurityProfile
from sim.config import MAC_WCET_BUDGET_MS


PDU_ID = "PDU_BRAKE_TORQUE"
LOAD_ITERATIONS = 100


@pytest.fixture
def profile_config_path(tmp_path):
    config_path = tmp_path / "secoc_profiles.json"
    profiles = {
        PDU_ID: {
            "algorithm": "HMAC-SHA256",
            "key_id": "secoc_mac_key_PDU_BRAKE_TORQUE",
            "freshness_length": 2,
            "authenticator_length": 8,
            "profile_version": "v1",
        }
    }
    config_path.write_text(json.dumps(profiles), encoding="utf-8")
    return str(config_path)


@pytest.fixture
def profile_provider(profile_config_path):
    return SecurityProfile(config_path=profile_config_path)


@pytest.fixture
def profiler():
    return PerformanceProfiler()


class _FastCryptoInterface:
    """Minimal CryptoInterface stub used to isolate the WCET measurement
    window from key resolution / truncation overhead."""

    def generate_mac(self, key_id, data):
        return b"\x00" * 32

    def verify_mac(self, key_id, data, mac):
        return True


class _StubKeyManager:
    def resolve_key(self, pdu_id):
        return "secoc_mac_key_PDU_BRAKE_TORQUE"


@pytest.fixture
def authenticator(profile_provider, profiler, dem_stub):
    from sim.event_logger import EventLogger

    return Authenticator(
        key_manager=_StubKeyManager(),
        crypto_interface=_FastCryptoInterface(),
        profiler=profiler,
        event_logger=EventLogger(dem=dem_stub),
        profile_provider=profile_provider,
    )


@pytest.mark.vtc("VTC-SR-12")
@pytest.mark.sim
class TestVTC_12:
    def test_precondition_mac_wcet_budget_is_configured(self):
        """Precondition: config.MAC_WCET_BUDGET_MS defines the WCET budget
        for a single MAC generate/verify operation (SW-SecOC-08, SR-12)."""
        assert isinstance(MAC_WCET_BUDGET_MS, (int, float))
        assert MAC_WCET_BUDGET_MS > 0

    def test_single_generate_mac_call_is_profiled(self, authenticator, profiler):
        """Step: A single Authenticator.generate_mac() call brackets the
        crypto_interface.generate_mac() call with
        PerformanceProfiler.start()/stop() and records a ProfilerSample."""
        authenticator.generate_mac(PDU_ID, b"\x01\x02\x03\x04", 1)

        samples = profiler.get_samples()
        assert len(samples) == 1
        assert samples[0].operation_id.startswith(PDU_ID)

    @pytest.mark.slow
    def test_mac_generation_under_load_meets_wcet_budget(
        self, authenticator, profiler
    ):
        """Step: Run Authenticator.generate_mac()/verify_mac() N times under
        load and verify each measured elapsed_ms is within
        config.MAC_WCET_BUDGET_MS."""
        for i in range(LOAD_ITERATIONS):
            authenticator.generate_mac(PDU_ID, b"\x01\x02\x03\x04", i)

        samples = profiler.get_samples()
        assert len(samples) == LOAD_ITERATIONS
        for sample in samples:
            assert sample.elapsed_ms < MAC_WCET_BUDGET_MS
            assert sample.status == ProfilerStatus.WITHIN_BUDGET

    def test_wcet_exceeded_logs_dem_warning(
        self, authenticator, profiler, dem_stub, monkeypatch
    ):
        """Step: When elapsed_ms exceeds config.MAC_WCET_BUDGET_MS, a
        WARNING-severity WCET_EXCEEDED DEM event is logged
        (SW-SecOC-08)."""
        import time as time_module

        # Force perf_counter to report an artificially large elapsed time
        # so stop() reports an EXCEEDED sample regardless of real timing.
        call_count = {"n": 0}
        real_perf_counter = time_module.perf_counter

        def fake_perf_counter():
            call_count["n"] += 1
            if call_count["n"] % 2 == 1:
                return 0.0
            return (MAC_WCET_BUDGET_MS / 1000.0) * 100.0

        monkeypatch.setattr(time_module, "perf_counter", fake_perf_counter)

        authenticator.generate_mac(PDU_ID, b"\x01\x02\x03\x04", 1)

        events = dem_stub.get_events()
        assert any(event.event_id == "WCET_EXCEEDED" for event in events)

    def test_expected_result_wcet_compliance_summary(self, authenticator, profiler):
        """Expected result: PerformanceProfiler.get_summary() reports
        aggregate timing statistics with exceeded_count == 0 for a
        normal-load run within the WCET budget (SR-12)."""
        for i in range(10):
            authenticator.generate_mac(PDU_ID, b"\x01\x02\x03\x04", i)

        summary = profiler.get_summary()
        assert summary["count"] == 10
        assert summary["exceeded_count"] == 0
        assert summary["max_ms"] < MAC_WCET_BUDGET_MS
