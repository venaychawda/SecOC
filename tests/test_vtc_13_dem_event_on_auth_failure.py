"""
VTC-SR-13: Auth failure -> DEM event logged
Objective: Trigger authentication failure and verify DEM event logging
Requirements: SR-13; SW-SecOC-06
"""
import pytest

from sim.dem import Severity
from sim.event_logger import EventLogger
from sim.security_events import RejectionReason, SecurityEvents
from sim.fault_manager import FaultManager
from sim.security_policy_engine import SecurityPolicyEngine
from sim.ecu_state import EcuState


PDU_ID = "PDU_BRAKE_TORQUE"


@pytest.fixture
def ecu_state():
    return EcuState()


@pytest.fixture
def event_logger(dem_stub, security_events):
    return EventLogger(dem=dem_stub, security_events=security_events)


@pytest.fixture
def security_policy_engine(ecu_state, dem_stub):
    return SecurityPolicyEngine(
        ecu_state=ecu_state,
        event_logger=EventLogger(dem=dem_stub, security_events=None),
    )


@pytest.fixture
def fault_manager(security_policy_engine):
    return FaultManager(security_policy_engine=security_policy_engine)


@pytest.fixture
def security_events(fault_manager):
    return SecurityEvents(fault_manager=fault_manager)


@pytest.mark.vtc("VTC-SR-13")
@pytest.mark.sim
class TestVTC_13:
    def test_precondition_dem_starts_empty(self, dem_stub):
        """Precondition: DEM has no recorded events before any rejection."""
        assert dem_stub.get_events() == []

    def test_trigger_authentication_failure(self, event_logger, dem_stub):
        """Step: Trigger an authentication failure (MAC_MISMATCH) on
        PDU_BRAKE_TORQUE and route it through EventLogger.log_rejection()."""
        evt = event_logger.log_rejection(PDU_ID, RejectionReason.MAC_MISMATCH)

        assert evt is not None
        assert evt.severity == Severity.CRITICAL

    def test_dem_event_logged_with_critical_severity(self, event_logger, dem_stub):
        """Step: Verify the DEM now contains a CRITICAL-severity event for
        the authentication failure."""
        event_logger.log_rejection(PDU_ID, RejectionReason.MAC_MISMATCH)

        critical_events = dem_stub.get_events_by_severity(Severity.CRITICAL)
        assert len(critical_events) >= 1

    def test_dem_event_has_secoc_auth_fail_code(self, event_logger, dem_stub):
        """Step: Verify the recorded DEM event carries the SECOC_AUTH_FAIL
        event code, classified per security_events.classify(MAC_MISMATCH)."""
        event_logger.log_rejection(PDU_ID, RejectionReason.MAC_MISMATCH)

        events = dem_stub.get_events()
        assert any("SECOC_AUTH_FAIL" in e.event_id for e in events)

    def test_dem_event_payload_contains_pdu_id(self, event_logger, dem_stub):
        """Step: Verify the DEM event payload references the rejected
        pdu_id for traceability."""
        event_logger.log_rejection(PDU_ID, RejectionReason.MAC_MISMATCH)

        events = dem_stub.get_events()
        matching = [e for e in events if "SECOC_AUTH_FAIL" in e.event_id]
        assert any(e.data.get("pdu_id") == PDU_ID for e in matching)

    def test_expected_result_classification_table_matches(self, security_events):
        """Expected result: classify(MAC_MISMATCH) returns
        (CRITICAL, SECOC_AUTH_FAIL) per the SW-SecOC-06 / SR-13
        classification table."""
        severity, code = security_events.classify(RejectionReason.MAC_MISMATCH)

        assert severity == Severity.CRITICAL
        assert code == "SECOC_AUTH_FAIL"
