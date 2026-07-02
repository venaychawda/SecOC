"""
VTC-SR-14: Repeated crypto failure -> safe state transition
Objective: Force repeated crypto failures and verify safe state transition
Requirements: SR-14; — (no derived SWR; implemented by design intent, see
traceability_matrix.md section 6 — SW-SecOC-11 recommended)
"""
import pytest

from sim.dem import Severity
from sim.event_logger import EventLogger
from sim.security_events import RejectionReason, SecurityEvents
from sim.fault_manager import FailureCategory, FaultManager
from sim.security_policy_engine import SecurityPolicyEngine
from sim.ecu_state import EcuState, EcuStateValue
from sim.config import MAX_AUTH_FAILURES
from sim.secoc import SecOC
from sim.pdu_manager import PduManager
from sim.authenticator import Authenticator
from sim.freshness_manager import FreshnessManager
from sim.security_profile import SecurityProfile
from sim.can_bus import CanBus
from sim.can_interface import CanInterface
from sim.can_fd_interface import CanFdInterface
from sim.pdu_router import PduRouter
from sim.sender_ecu import SenderECU


PDU_ID = "PDU_BRAKE_TORQUE"


@pytest.fixture
def ecu_state():
    return EcuState()


@pytest.fixture
def event_logger(dem_stub):
    return EventLogger(dem=dem_stub, security_events=None)


@pytest.fixture
def security_policy_engine(ecu_state, event_logger):
    return SecurityPolicyEngine(ecu_state=ecu_state, event_logger=event_logger)


@pytest.fixture
def fault_manager(security_policy_engine):
    return FaultManager(security_policy_engine=security_policy_engine)


@pytest.fixture
def security_events(fault_manager):
    return SecurityEvents(fault_manager=fault_manager)


@pytest.fixture
def secoc(nvm_stub, dem_stub, hsm_stub, cryif_stub, csm_stub, ecu_state):
    profile_provider = SecurityProfile(config_path="config/secoc_profiles.json")
    freshness_manager = FreshnessManager(nvm=nvm_stub, window_size=16, freshness_length=2)
    authenticator = Authenticator(
        key_manager=None,
        crypto_interface=None,
        profiler=None,
        event_logger=EventLogger(dem=dem_stub),
        profile_provider=profile_provider,
    )
    pdu_manager = PduManager(serializer=None)
    return SecOC(
        profile_provider=profile_provider,
        freshness_manager=freshness_manager,
        authenticator=authenticator,
        pdu_manager=pdu_manager,
        event_logger=EventLogger(dem=dem_stub),
        ecu_state=ecu_state,
    )


@pytest.fixture
def sender_ecu(secoc, ecu_state):
    bus = CanBus()
    bus.start()
    can_if = CanInterface(ecu_id="ECU_TX", bus=bus)
    can_fd_if = CanFdInterface(ecu_id="ECU_TX", bus=bus)
    router = PduRouter(ecu_id="ECU_TX", can_if=can_if, can_fd_if=can_fd_if)
    ecu = SenderECU(
        ecu_id="ECU_TX",
        secoc=secoc,
        pdu_router=router,
        ecu_state=ecu_state,
        managed_pdu_ids=(PDU_ID,),
    )
    ecu.on_startup()
    return ecu


@pytest.mark.vtc("VTC-SR-14")
@pytest.mark.sim
class TestVTC_14:
    def test_precondition_ecu_starts_in_normal_operation(self, ecu_state):
        """Precondition: ECU starts in NORMAL_OPERATION before any crypto
        failures are recorded."""
        assert ecu_state.current_state == EcuStateValue.NORMAL_OPERATION

    def test_precondition_failure_counter_starts_at_zero(self, fault_manager):
        """Precondition: fault_manager has no recorded failures for
        PDU_BRAKE_TORQUE."""
        assert fault_manager.get_failure_count(PDU_ID) == 0

    def test_force_repeated_crypto_failures(self, fault_manager):
        """Step: Force MAX_AUTH_FAILURES consecutive AUTH-category crypto
        failures (MAC_MISMATCH) on PDU_BRAKE_TORQUE."""
        for _ in range(MAX_AUTH_FAILURES):
            fault_manager.record_failure(PDU_ID, FailureCategory.AUTH)

        assert fault_manager.get_failure_count(PDU_ID) == MAX_AUTH_FAILURES

    def test_security_policy_engine_evaluates_lockout(
        self, fault_manager, security_policy_engine
    ):
        """Step: Once the failure count reaches MAX_AUTH_FAILURES,
        SecurityPolicyEngine.evaluate() transitions the ECU into
        SECURITY_VIOLATION_LOCKOUT."""
        for _ in range(MAX_AUTH_FAILURES):
            fault_manager.record_failure(PDU_ID, FailureCategory.AUTH)

        assert security_policy_engine.is_locked_out() is True

    def test_expected_result_ecu_state_security_violation_lockout(
        self, fault_manager, ecu_state
    ):
        """Expected result: ECUState.current_state ==
        SECURITY_VIOLATION_LOCKOUT after repeated crypto failures (SR-14)."""
        for _ in range(MAX_AUTH_FAILURES):
            fault_manager.record_failure(PDU_ID, FailureCategory.AUTH)

        assert ecu_state.current_state == EcuStateValue.SECURITY_VIOLATION_LOCKOUT

    def test_expected_result_safe_state_entered_dem_event_logged(
        self, fault_manager, dem_stub
    ):
        """Expected result: a CRITICAL SAFE_STATE_ENTERED DEM event is
        logged exactly once when the lockout threshold is crossed."""
        for _ in range(MAX_AUTH_FAILURES):
            fault_manager.record_failure(PDU_ID, FailureCategory.AUTH)

        events = dem_stub.get_events_by_severity(Severity.CRITICAL)
        safe_state_events = [e for e in events if "SAFE_STATE_ENTERED" in e.event_id]
        assert len(safe_state_events) == 1

    def test_repeated_evaluation_after_lockout_is_idempotent(
        self, fault_manager, security_policy_engine, dem_stub
    ):
        """Step: Additional failures recorded after lockout do not produce
        duplicate SAFE_STATE_ENTERED events (idempotent re-evaluation)."""
        for _ in range(MAX_AUTH_FAILURES + 2):
            fault_manager.record_failure(PDU_ID, FailureCategory.AUTH)

        events = dem_stub.get_events_by_severity(Severity.CRITICAL)
        safe_state_events = [e for e in events if "SAFE_STATE_ENTERED" in e.event_id]
        assert len(safe_state_events) == 1
        assert security_policy_engine.is_locked_out() is True

    def test_reset_recovers_from_lockout_to_normal_operation(
        self, fault_manager, security_policy_engine, ecu_state
    ):
        """Step: After lockout, SecurityPolicyEngine.reset() (used by
        ECUBase.on_reset(), SR-14 recovery) clears lockout and returns the
        ECU to NORMAL_OPERATION."""
        for _ in range(MAX_AUTH_FAILURES):
            fault_manager.record_failure(PDU_ID, FailureCategory.AUTH)
        assert security_policy_engine.is_locked_out() is True

        security_policy_engine.reset()

        assert security_policy_engine.is_locked_out() is False
        assert ecu_state.current_state == EcuStateValue.NORMAL_OPERATION

    def test_reset_allows_lockout_to_be_re_evaluated_after_recovery(
        self, fault_manager, security_policy_engine, dem_stub
    ):
        """Step: After reset(), a fresh run of MAX_AUTH_FAILURES failures can
        re-trigger lockout and log a new SAFE_STATE_ENTERED event."""
        for _ in range(MAX_AUTH_FAILURES):
            fault_manager.record_failure(PDU_ID, FailureCategory.AUTH)
        security_policy_engine.reset()

        for _ in range(MAX_AUTH_FAILURES):
            fault_manager.record_failure(PDU_ID, FailureCategory.AUTH)

        assert security_policy_engine.is_locked_out() is True
        events = dem_stub.get_events_by_severity(Severity.CRITICAL)
        safe_state_events = [e for e in events if "SAFE_STATE_ENTERED" in e.event_id]
        assert len(safe_state_events) == 2

    @pytest.mark.asyncio
    async def test_sender_ecu_send_signal_suppressed_when_locked_out(
        self, fault_manager, sender_ecu
    ):
        """Expected result (SenderECU layer): send_signal() returns False
        (transmission suppressed) once the ECU is in
        SECURITY_VIOLATION_LOCKOUT, without raising (design/lld/LLD_sender_ecu.md)."""
        for _ in range(MAX_AUTH_FAILURES):
            fault_manager.record_failure(PDU_ID, FailureCategory.AUTH)

        sent = await sender_ecu.send_signal(PDU_ID, b"\x01\x02\x03\x04")

        assert sent is False
        assert sender_ecu.tx_count[PDU_ID] == 0
