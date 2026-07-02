"""
Unit tests for the ECU object model (sim/ecu_base.py, sim/sender_ecu.py,
sim/receiver_ecu.py, sim/pdu_router.py) -- shared infrastructure supporting
SW-SecOC-01/02, no dedicated VTC of its own. See design/lld/LLD_ecu_base.md,
LLD_sender_ecu.md, LLD_receiver_ecu.md, LLD_pdu_router.md.
"""
import pytest

from sim.can_bus import CanBus
from sim.can_fd_interface import CanFdInterface
from sim.can_interface import CanInterface
from sim.dem import DEM
from sim.ecu_base import ECUBaseError
from sim.ecu_state import EcuState, EcuStateValue
from sim.event_logger import EventLogger
from sim.pdu_router import PduRouter
from sim.receiver_ecu import ReceiverECU, ReceiverECUError
from sim.security_profile import SecurityProfile
from sim.sender_ecu import SenderECU, SenderECUError
from sim.authenticator import Authenticator
from sim.freshness_manager import FreshnessManager
from sim.nvm import NvM
from sim.pdu_manager import PduManager
from sim.secoc import SecOC

PDU_ID = "PDU_BRAKE_TORQUE"
OTHER_PDU_ID = "PDU_STEERING_ANGLE"


@pytest.fixture
def ecu_state():
    return EcuState()


@pytest.fixture
def can_bus():
    bus = CanBus()
    bus.start()
    return bus


@pytest.fixture
def pdu_router(can_bus):
    can_if = CanInterface(ecu_id="ECU_A", bus=can_bus)
    can_fd_if = CanFdInterface(ecu_id="ECU_A", bus=can_bus)
    return PduRouter(ecu_id="ECU_A", can_if=can_if, can_fd_if=can_fd_if)


@pytest.fixture
def secoc(tmp_nvm_path, ecu_state):
    nvm = NvM(path=tmp_nvm_path)
    dem = DEM()
    profile_provider = SecurityProfile(config_path="config/secoc_profiles.json")
    freshness_manager = FreshnessManager(nvm=nvm, window_size=16, freshness_length=2)
    event_logger = EventLogger(dem=dem)
    authenticator = Authenticator(
        key_manager=None,
        crypto_interface=None,
        profiler=None,
        event_logger=event_logger,
        profile_provider=profile_provider,
    )
    return SecOC(
        profile_provider=profile_provider,
        freshness_manager=freshness_manager,
        authenticator=authenticator,
        pdu_manager=PduManager(serializer=None),
        event_logger=event_logger,
        ecu_state=ecu_state,
    )


@pytest.fixture
def sender_ecu(secoc, pdu_router, ecu_state):
    return SenderECU(
        ecu_id="ECU_A",
        secoc=secoc,
        pdu_router=pdu_router,
        ecu_state=ecu_state,
        managed_pdu_ids=(PDU_ID,),
    )


@pytest.fixture
def receiver_ecu(secoc, pdu_router, ecu_state):
    return ReceiverECU(
        ecu_id="ECU_A",
        secoc=secoc,
        pdu_router=pdu_router,
        ecu_state=ecu_state,
        managed_pdu_ids=(PDU_ID,),
    )


class TestECUBaseLifecycle:
    def test_on_startup_registers_with_pdu_router(self, sender_ecu, pdu_router):
        assert pdu_router.is_registered("ECU_A") is False
        sender_ecu.on_startup()
        assert pdu_router.is_registered("ECU_A") is True

    def test_on_startup_twice_raises(self, sender_ecu):
        sender_ecu.on_startup()
        with pytest.raises(ECUBaseError):
            sender_ecu.on_startup()

    def test_shutdown_deregisters_and_is_idempotent(self, sender_ecu, pdu_router):
        sender_ecu.on_startup()
        sender_ecu.shutdown()
        assert pdu_router.is_registered("ECU_A") is False
        sender_ecu.shutdown()  # idempotent, no error

    def test_state_mirrors_shared_ecu_state(self, sender_ecu, ecu_state):
        assert sender_ecu.state == EcuStateValue.NORMAL_OPERATION
        ecu_state.transition(EcuStateValue.SECURITY_VIOLATION_LOCKOUT)
        assert sender_ecu.state == EcuStateValue.SECURITY_VIOLATION_LOCKOUT

    def test_on_reset_recovers_from_lockout(self, sender_ecu, ecu_state):
        ecu_state.transition(EcuStateValue.SECURITY_VIOLATION_LOCKOUT)
        sender_ecu.on_reset()
        assert sender_ecu.state == EcuStateValue.NORMAL_OPERATION

    def test_get_status_reports_ecu_id_and_state(self, sender_ecu):
        status = sender_ecu.get_status()
        assert status["ecu_id"] == "ECU_A"
        assert status["state"] == EcuStateValue.NORMAL_OPERATION.value
        assert "secoc_status" in status


class TestSenderECU:
    @pytest.mark.asyncio
    async def test_send_signal_rejects_unmanaged_pdu_id(self, sender_ecu):
        sender_ecu.on_startup()
        with pytest.raises(SenderECUError):
            await sender_ecu.send_signal(OTHER_PDU_ID, b"\x01")

    @pytest.mark.asyncio
    async def test_transmit_periodic_rejects_unmanaged_pdu_id(self, sender_ecu):
        sender_ecu.on_startup()
        with pytest.raises(SenderECUError):
            await sender_ecu.transmit_periodic(OTHER_PDU_ID, lambda: b"\x01")

    @pytest.mark.asyncio
    async def test_transmit_periodic_calls_provider_and_sends(self, sender_ecu):
        sender_ecu.on_startup()
        calls = []

        def provider():
            calls.append(1)
            return b"\x09"

        await sender_ecu.transmit_periodic(PDU_ID, provider)

        assert len(calls) == 1
        assert sender_ecu.tx_count[PDU_ID] == 1

    def test_on_frame_received_is_a_noop(self, sender_ecu):
        assert sender_ecu.on_frame_received(PDU_ID, b"\x00") is None

    def test_get_status_includes_tx_count(self, sender_ecu):
        status = sender_ecu.get_status()
        assert status["tx_count"] == {PDU_ID: 0}
        assert status["managed_pdu_ids"] == [PDU_ID]


class TestReceiverECU:
    def test_register_signal_handler_rejects_unmanaged_pdu_id(self, receiver_ecu):
        with pytest.raises(ReceiverECUError):
            receiver_ecu.register_signal_handler(OTHER_PDU_ID, lambda p, v: None)

    def test_on_frame_received_drops_unmanaged_pdu_id(self, receiver_ecu):
        assert receiver_ecu.on_frame_received(OTHER_PDU_ID, b"\x00") is False

    def test_on_frame_received_drops_when_not_normal_operation(
        self, receiver_ecu, ecu_state
    ):
        ecu_state.transition(EcuStateValue.SECURITY_VIOLATION_LOCKOUT)
        accepted = receiver_ecu.on_frame_received(PDU_ID, b"\x00\x00\x00\x00")
        assert accepted is False
        assert receiver_ecu.rx_rejected_count[PDU_ID] == 1

    def test_end_to_end_accept_invokes_handler_and_updates_counters(
        self, secoc, receiver_ecu
    ):
        secured_pdu = secoc.transmit_secured(PDU_ID, b"\xAA\xBB")
        handler_calls = []
        receiver_ecu.register_signal_handler(
            PDU_ID, lambda pdu_id, payload: handler_calls.append((pdu_id, payload))
        )

        accepted = receiver_ecu.on_frame_received(PDU_ID, secured_pdu)

        assert accepted is True
        assert handler_calls == [(PDU_ID, b"\xAA\xBB")]
        assert receiver_ecu.rx_accepted_count[PDU_ID] == 1
        assert receiver_ecu.rx_rejected_count[PDU_ID] == 0

    def test_get_status_includes_rx_counters(self, receiver_ecu):
        status = receiver_ecu.get_status()
        assert status["rx_accepted_count"] == {PDU_ID: 0}
        assert status["rx_rejected_count"] == {PDU_ID: 0}
        assert status["managed_pdu_ids"] == [PDU_ID]


class TestPduRouter:
    def test_register_and_deregister_ecu(self, pdu_router, sender_ecu):
        pdu_router.register_ecu("ECU_A", sender_ecu)
        assert pdu_router.is_registered("ECU_A") is True
        pdu_router.deregister_ecu("ECU_A")
        assert pdu_router.is_registered("ECU_A") is False

    def test_route_from_bus_drops_when_no_ecu_registered(self, pdu_router):
        assert pdu_router.route_from_bus(PDU_ID, b"\x00") is False

    def test_route_from_bus_dispatches_to_registered_ecu(self, pdu_router, receiver_ecu):
        pdu_router.register_ecu("ECU_A", receiver_ecu)
        delivered = pdu_router.route_from_bus(PDU_ID, b"\x00\x00\x00\x00")
        assert delivered is True
        assert receiver_ecu.rx_rejected_count[PDU_ID] == 1  # malformed, rejected

    def test_get_status_reports_transports(self, pdu_router):
        status = pdu_router.get_status()
        assert status["ecu_id"] == "ECU_A"
        assert status["has_can_fd"] is True
        assert status["transports"]["CLASSIC_CAN"]["transport"] == "CLASSIC_CAN"
        assert status["transports"]["CAN_FD"]["transport"] == "CAN_FD"
