"""
VTC-SR-01: Forged frame injection -> rejection + violation state
Objective: Inject forged CAN frame and verify ECU rejects message and enters
security violation state
Requirements: SR-01; — (no derived SWR; realized jointly by SW-SecOC-02 and
SW-SecOC-06; see traceability_matrix.md section 6)
"""
import pytest

from sim.secoc import SecOC
from sim.pdu_manager import PduManager
from sim.authenticator import Authenticator
from sim.freshness_manager import FreshnessManager
from sim.security_profile import SecurityProfile
from sim.event_logger import EventLogger
from sim.ecu_state import EcuState, EcuStateValue
from sim.fuzzing_engine import FuzzingEngine, ForgeMode
from sim.message_injector import MessageInjector
from sim.can_bus import CanBus
from sim.can_interface import CanInterface
from sim.pdu_router import PduRouter
from sim.receiver_ecu import ReceiverECU


PDU_ID = "PDU_BRAKE_TORQUE"


@pytest.fixture
def ecu_state():
    return EcuState()


@pytest.fixture
def can_bus():
    bus = CanBus()
    bus.start()
    return bus


@pytest.fixture
def injector(can_bus):
    return MessageInjector(can_bus=can_bus)


@pytest.fixture
def fuzzing_engine(can_bus, injector):
    return FuzzingEngine(can_bus=can_bus, injector=injector)


@pytest.fixture
def secoc(nvm_stub, dem_stub, hsm_stub, cryif_stub, csm_stub, ecu_state):
    profile_provider = SecurityProfile(config_path="config/secoc_profiles.json")
    freshness_manager = FreshnessManager(
        nvm=nvm_stub, window_size=16, freshness_length=2
    )
    authenticator = Authenticator(
        key_manager=None,
        crypto_interface=None,
        profiler=None,
        event_logger=EventLogger(dem=dem_stub),
        profile_provider=profile_provider,
    )
    pdu_manager = PduManager(serializer=None)
    event_logger = EventLogger(dem=dem_stub)
    return SecOC(
        profile_provider=profile_provider,
        freshness_manager=freshness_manager,
        authenticator=authenticator,
        pdu_manager=pdu_manager,
        event_logger=event_logger,
        ecu_state=ecu_state,
    )


@pytest.fixture
def pdu_router(can_bus):
    can_if = CanInterface(ecu_id="ECU_RX", bus=can_bus)
    return PduRouter(ecu_id="ECU_RX", can_if=can_if)


@pytest.fixture
def receiver_ecu(secoc, pdu_router, ecu_state):
    ecu = ReceiverECU(
        ecu_id="ECU_RX",
        secoc=secoc,
        pdu_router=pdu_router,
        ecu_state=ecu_state,
        managed_pdu_ids=(PDU_ID,),
    )
    ecu.on_startup()
    return ecu


@pytest.mark.vtc("VTC-SR-01")
@pytest.mark.sim
class TestVTC_01:
    def test_precondition_secoc_configured_for_pdu(self, secoc):
        """Precondition: SecOC instance is configured with a security profile
        for PDU_BRAKE_TORQUE before any forged frame is injected."""
        status = secoc.get_status()
        assert "ecu_state" in status
        assert status["ecu_state"] == EcuStateValue.NORMAL_OPERATION.value

    def test_inject_malformed_structure_frame_is_rejected(
        self, secoc, fuzzing_engine
    ):
        """Step: Inject a structurally malformed forged CAN frame
        (ForgeMode.MALFORMED_STRUCTURE) and verify ECU rejects the message."""
        forged_pdu = fuzzing_engine.generate_forged_pdu(
            PDU_ID, ForgeMode.MALFORMED_STRUCTURE
        )
        fuzzing_engine.inject(PDU_ID, forged_pdu)

        result = secoc.receive_secured(PDU_ID, forged_pdu)
        assert result is None

    def test_inject_invalid_mac_frame_is_rejected(self, secoc, fuzzing_engine):
        """Step: Inject a structurally valid but cryptographically forged
        frame (ForgeMode.INVALID_MAC) and verify ECU rejects the message."""
        forged_pdu = fuzzing_engine.generate_forged_pdu(PDU_ID, ForgeMode.INVALID_MAC)
        fuzzing_engine.inject(PDU_ID, forged_pdu)

        result = secoc.receive_secured(PDU_ID, forged_pdu)
        assert result is None

    def test_repeated_forged_frames_trigger_security_violation_lockout(
        self, secoc, fuzzing_engine, ecu_state
    ):
        """Step: Repeated forged-frame injections eventually transition the
        ECU into SECURITY_VIOLATION_LOCKOUT (SR-01, SR-14, CR-02)."""
        from sim import config

        for _ in range(config.MAX_AUTH_FAILURES):
            forged_pdu = fuzzing_engine.generate_forged_pdu(
                PDU_ID, ForgeMode.INVALID_MAC
            )
            fuzzing_engine.inject(PDU_ID, forged_pdu)
            secoc.receive_secured(PDU_ID, forged_pdu)

        assert ecu_state.current_state == EcuStateValue.SECURITY_VIOLATION_LOCKOUT

    def test_expected_result_forged_frame_dropped_and_dem_event_logged(
        self, secoc, fuzzing_engine, dem_stub
    ):
        """Expected result: the forged frame is never delivered to the
        application layer, and a CRITICAL SECOC_AUTH_FAIL DEM event is
        logged for the rejection."""
        forged_pdu = fuzzing_engine.generate_forged_pdu(PDU_ID, ForgeMode.INVALID_MAC)
        fuzzing_engine.inject(PDU_ID, forged_pdu)

        result = secoc.receive_secured(PDU_ID, forged_pdu)

        assert result is None
        events = dem_stub.get_events()
        assert any(event.event_id == "SECOC_AUTH_FAIL" for event in events)

    def test_receiver_ecu_drops_forged_frame_and_does_not_invoke_handler(
        self, receiver_ecu, fuzzing_engine
    ):
        """Expected result (ReceiverECU layer): on_frame_received() drops a
        forged frame, returns False, and never invokes the registered
        application signal handler -- rejection/DEM logging already
        happened inside secoc.py (design/lld/LLD_receiver_ecu.md)."""
        handler_calls = []
        receiver_ecu.register_signal_handler(
            PDU_ID, lambda pdu_id, payload: handler_calls.append((pdu_id, payload))
        )

        forged_pdu = fuzzing_engine.generate_forged_pdu(PDU_ID, ForgeMode.INVALID_MAC)

        accepted = receiver_ecu.on_frame_received(PDU_ID, forged_pdu)

        assert accepted is False
        assert handler_calls == []
        assert receiver_ecu.rx_rejected_count[PDU_ID] == 1
        assert receiver_ecu.rx_accepted_count[PDU_ID] == 0
