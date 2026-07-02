"""
VTC-SR-02: Payload tamper -> integrity failure detection
Objective: Modify payload bit in transit and verify integrity failure
detection
Requirements: SR-02; — (no derived SWR; realized as a side-effect of
SW-SecOC-04 MAC integrity coverage; see traceability_matrix.md section 6)
"""
import pytest

from sim.secoc import SecOC
from sim.pdu_manager import PduManager
from sim.authenticator import Authenticator
from sim.freshness_manager import FreshnessManager
from sim.security_profile import SecurityProfile
from sim.event_logger import EventLogger
from sim.ecu_state import EcuState
from sim.mitm_attack import MitmAttack
from sim.message_injector import MessageInjector
from sim.can_bus import CanBus
from sim.message_frame import MessageFrame
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
def mitm_attack(can_bus, injector):
    return MitmAttack(can_bus=can_bus, injector=injector, bit_flip_mask=0x01)


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


@pytest.mark.vtc("VTC-SR-02")
@pytest.mark.sim
class TestVTC_02:
    def test_precondition_legitimate_secured_pdu_can_be_built(self, secoc):
        """Precondition: SecOC.transmit_secured() produces a valid Secured
        I-PDU for PDU_BRAKE_TORQUE (the frame that MitmAttack will tamper)."""
        authentic_pdu = b"\x10\x20\x30\x40"
        secured_pdu = secoc.transmit_secured(PDU_ID, authentic_pdu)
        assert isinstance(secured_pdu, (bytes, bytearray))
        assert len(secured_pdu) > len(authentic_pdu)

    def test_mitm_intercept_flips_payload_bit_without_changing_mac(
        self, secoc, mitm_attack
    ):
        """Step: MitmAttack intercepts the legitimate Secured I-PDU and flips
        a single bit in authentic_pdu, leaving freshness and MAC unchanged."""
        authentic_pdu = b"\x10\x20\x30\x40"
        secured_pdu = secoc.transmit_secured(PDU_ID, authentic_pdu)

        frame = MessageFrame(pdu_id=PDU_ID, data=secured_pdu, timestamp=0.0)
        tampered_frame = mitm_attack.intercept(frame)

        assert tampered_frame.tampered_raw_bytes != tampered_frame.original_raw_bytes
        # MAC and freshness trailer bytes must be byte-identical
        mac_len = 8  # profile.authenticator_length per illustrative profile
        assert (
            tampered_frame.tampered_raw_bytes[-mac_len:]
            == tampered_frame.original_raw_bytes[-mac_len:]
        )

    def test_mitm_forward_tampered_frame_is_rejected_by_receiver(
        self, secoc, mitm_attack
    ):
        """Step: MitmAttack forwards the tampered frame onto the bus; the
        receiver's SecOC.receive_secured() rejects it (MAC mismatch)."""
        authentic_pdu = b"\x10\x20\x30\x40"
        secured_pdu = secoc.transmit_secured(PDU_ID, authentic_pdu)

        frame = MessageFrame(pdu_id=PDU_ID, data=secured_pdu, timestamp=0.0)
        tampered_frame = mitm_attack.intercept(frame)
        mitm_attack.forward(tampered_frame)

        result = secoc.receive_secured(PDU_ID, tampered_frame.tampered_raw_bytes)
        assert result is None

    def test_expected_result_integrity_failure_logged_as_mac_mismatch(
        self, secoc, mitm_attack, dem_stub
    ):
        """Expected result: a tampered (integrity-violated) frame is dropped
        and a CRITICAL MAC_MISMATCH / SECOC_AUTH_FAIL DEM event is logged
        (SR-02, SW-SecOC-06)."""
        authentic_pdu = b"\x10\x20\x30\x40"
        secured_pdu = secoc.transmit_secured(PDU_ID, authentic_pdu)

        frame = MessageFrame(pdu_id=PDU_ID, data=secured_pdu, timestamp=0.0)
        tampered_frame = mitm_attack.intercept(frame)
        mitm_attack.forward(tampered_frame)

        result = secoc.receive_secured(PDU_ID, tampered_frame.tampered_raw_bytes)

        assert result is None
        events = dem_stub.get_events()
        assert any(event.event_id == "SECOC_AUTH_FAIL" for event in events)

    def test_receiver_ecu_drops_tampered_frame_and_does_not_invoke_handler(
        self, secoc, mitm_attack, receiver_ecu
    ):
        """Expected result (ReceiverECU layer): a MITM-tampered frame fails
        MAC verification inside secoc.py; on_frame_received() drops it,
        returns False, and never invokes the application signal handler."""
        handler_calls = []
        receiver_ecu.register_signal_handler(
            PDU_ID, lambda pdu_id, payload: handler_calls.append((pdu_id, payload))
        )

        authentic_pdu = b"\x10\x20\x30\x40"
        secured_pdu = secoc.transmit_secured(PDU_ID, authentic_pdu)
        frame = MessageFrame(pdu_id=PDU_ID, data=secured_pdu, timestamp=0.0)
        tampered_frame = mitm_attack.intercept(frame)

        accepted = receiver_ecu.on_frame_received(PDU_ID, tampered_frame.tampered_raw_bytes)

        assert accepted is False
        assert handler_calls == []
        assert receiver_ecu.rx_rejected_count[PDU_ID] == 1
