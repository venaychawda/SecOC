"""
VTC-SR-03: Replay with old counter -> freshness rejection
Objective: Replay same message with old counter and verify freshness
rejection
Requirements: SR-03; SW-SecOC-01, SW-SecOC-03
"""
import pytest

from sim.secoc import SecOC
from sim.pdu_manager import PduManager
from sim.authenticator import Authenticator
from sim.freshness_manager import FreshnessManager
from sim.security_profile import SecurityProfile
from sim.event_logger import EventLogger
from sim.ecu_state import EcuState
from sim.replay_attack import ReplayAttack
from sim.message_injector import MessageInjector
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
def can_bus():
    bus = CanBus()
    bus.start()
    return bus


@pytest.fixture
def injector(can_bus):
    return MessageInjector(can_bus=can_bus)


@pytest.fixture
def replay_attack(can_bus, injector):
    return ReplayAttack(can_bus=can_bus, injector=injector)


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
    can_if = CanInterface(ecu_id="ECU_TX", bus=can_bus)
    can_fd_if = CanFdInterface(ecu_id="ECU_TX", bus=can_bus)
    return PduRouter(ecu_id="ECU_TX", can_if=can_if, can_fd_if=can_fd_if)


@pytest.fixture
def sender_ecu(secoc, pdu_router, ecu_state):
    ecu = SenderECU(
        ecu_id="ECU_TX",
        secoc=secoc,
        pdu_router=pdu_router,
        ecu_state=ecu_state,
        managed_pdu_ids=(PDU_ID,),
    )
    ecu.on_startup()
    return ecu


@pytest.mark.vtc("VTC-SR-03")
@pytest.mark.sim
class TestVTC_03:
    def test_precondition_first_legitimate_message_is_accepted(
        self, secoc, can_bus
    ):
        """Precondition: a legitimate Secured I-PDU with freshness counter N
        is transmitted and accepted by the receiver, advancing
        last_valid_freshness."""
        authentic_pdu = b"\xAA\xBB\xCC\xDD"
        secured_pdu = secoc.transmit_secured(PDU_ID, authentic_pdu)

        result = secoc.receive_secured(PDU_ID, secured_pdu)
        assert result == authentic_pdu

    def test_capture_legitimate_frame_for_replay(
        self, secoc, can_bus, replay_attack
    ):
        """Step: ReplayAttack captures the most recently observed valid
        Secured I-PDU for PDU_BRAKE_TORQUE."""
        authentic_pdu = b"\xAA\xBB\xCC\xDD"
        secured_pdu = secoc.transmit_secured(PDU_ID, authentic_pdu)
        secoc.receive_secured(PDU_ID, secured_pdu)

        captured = replay_attack.capture(PDU_ID)
        assert captured.pdu_id == PDU_ID
        assert captured.raw_bytes == secured_pdu

    def test_legitimate_message_with_newer_freshness_advances_counter(
        self, secoc, can_bus, replay_attack
    ):
        """Step: a second legitimate message with freshness N+1 is
        transmitted and accepted, so the captured frame's freshness (N) is
        now stale relative to last_valid_freshness."""
        authentic_pdu_1 = b"\xAA\xBB\xCC\xDD"
        secured_pdu_1 = secoc.transmit_secured(PDU_ID, authentic_pdu_1)
        secoc.receive_secured(PDU_ID, secured_pdu_1)
        replay_attack.capture(PDU_ID)

        authentic_pdu_2 = b"\x01\x02\x03\x04"
        secured_pdu_2 = secoc.transmit_secured(PDU_ID, authentic_pdu_2)
        result_2 = secoc.receive_secured(PDU_ID, secured_pdu_2)

        assert result_2 == authentic_pdu_2

    def test_replay_captured_frame_with_old_counter_is_rejected(
        self, secoc, can_bus, replay_attack
    ):
        """Step: ReplayAttack replays the captured (now-stale) frame
        unmodified; the receiver's freshness check rejects it
        (freshness_ok=False, replay detected)."""
        authentic_pdu_1 = b"\xAA\xBB\xCC\xDD"
        secured_pdu_1 = secoc.transmit_secured(PDU_ID, authentic_pdu_1)
        secoc.receive_secured(PDU_ID, secured_pdu_1)
        replay_attack.capture(PDU_ID)

        authentic_pdu_2 = b"\x01\x02\x03\x04"
        secured_pdu_2 = secoc.transmit_secured(PDU_ID, authentic_pdu_2)
        secoc.receive_secured(PDU_ID, secured_pdu_2)

        replay_attack.replay(PDU_ID)

        result = secoc.receive_secured(PDU_ID, secured_pdu_1)
        assert result is None

    def test_expected_result_freshness_rejection_logged_to_dem(
        self, secoc, can_bus, replay_attack, dem_stub
    ):
        """Expected result: the replayed frame is dropped and a
        FRESHNESS_OUT_OF_WINDOW / SECOC_AUTH_FAIL DEM event is logged
        (SR-03, CR-04)."""
        authentic_pdu_1 = b"\xAA\xBB\xCC\xDD"
        secured_pdu_1 = secoc.transmit_secured(PDU_ID, authentic_pdu_1)
        secoc.receive_secured(PDU_ID, secured_pdu_1)
        replay_attack.capture(PDU_ID)

        authentic_pdu_2 = b"\x01\x02\x03\x04"
        secured_pdu_2 = secoc.transmit_secured(PDU_ID, authentic_pdu_2)
        secoc.receive_secured(PDU_ID, secured_pdu_2)

        replay_attack.replay(PDU_ID)
        result = secoc.receive_secured(PDU_ID, secured_pdu_1)

        assert result is None
        events = dem_stub.get_events()
        assert any(
            event.event_id in ("SECOC_AUTH_FAIL", "FRESHNESS_OUT_OF_WINDOW")
            for event in events
        )

    @pytest.mark.asyncio
    async def test_sender_ecu_repeated_send_signal_advances_freshness_per_cycle(
        self, sender_ecu, secoc, can_bus
    ):
        """Expected result (SenderECU layer): each send_signal()/receive
        cycle for the same pdu_id is accepted with a strictly increasing
        freshness value (SW-SecOC-01, SW-SecOC-03), matching the same
        transmit-then-commit pattern used directly on secoc.py elsewhere in
        this file (design/lld/LLD_sender_ecu.md)."""
        # Use get_last() (not consume()) because secoc.receive_secured()
        # re-publishes the accepted frame onto CanBus as a side effect
        # (existing sim/secoc.py behavior); get_last() always reflects the
        # most recently transmitted frame for pdu_id regardless of that.
        ok1 = await sender_ecu.send_signal(PDU_ID, b"\x01")
        secured_pdu_1 = can_bus.get_last(PDU_ID)
        result1 = secoc.receive_secured(PDU_ID, secured_pdu_1)

        ok2 = await sender_ecu.send_signal(PDU_ID, b"\x02")
        secured_pdu_2 = can_bus.get_last(PDU_ID)
        result2 = secoc.receive_secured(PDU_ID, secured_pdu_2)

        assert ok1 is True
        assert ok2 is True
        assert result1 == b"\x01"
        assert result2 == b"\x02"
        assert secured_pdu_1 != secured_pdu_2
        assert sender_ecu.tx_count[PDU_ID] == 2
