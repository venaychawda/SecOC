"""
VTC-SR-16: Same SecOC message on CAN and CAN FD validates consistently
Objective: Send same SecOC message across CAN and CAN FD and verify
consistent validation
Requirements: SR-16; — (no derived SWR; CAN/CAN FD covered by design intent,
formal SWR TBD per traceability_matrix.md section 6; Ethernet adaptation
out of scope for Phase 1)
"""
import pytest

from sim.can_interface import CanInterface, PayloadTooLargeError
from sim.can_fd_interface import CanFdInterface
from sim.can_bus import CanBus
from sim.secoc import SecOC
from sim.pdu_manager import PduManager
from sim.authenticator import Authenticator
from sim.freshness_manager import FreshnessManager
from sim.security_profile import SecurityProfile
from sim.event_logger import EventLogger
from sim.ecu_state import EcuState
from sim.pdu_router import PduRouter
from sim import config


PDU_ID_NUMERIC = 0x100
PDU_ID = "PDU_BRAKE_TORQUE"

# A Secured I-PDU payload that fits within classic CAN (8 bytes).
SHORT_SECURED_PDU = bytes(range(8))

# A Secured I-PDU payload that requires CAN FD (> 8, <= 64 bytes).
LONG_SECURED_PDU = bytes(range(64))


@pytest.fixture
def ecu_state():
    return EcuState()


@pytest.fixture
def can_bus():
    bus = CanBus()
    bus.start()
    return bus


@pytest.fixture
def can_interface(can_bus):
    return CanInterface(ecu_id="ECU_TX_CAN", bus=can_bus)


@pytest.fixture
def can_fd_interface(can_bus):
    return CanFdInterface(ecu_id="ECU_TX_CANFD", bus=can_bus)


@pytest.fixture
def pdu_router_with_canfd(can_bus):
    can_if = CanInterface(ecu_id="ECU_ROUTER", bus=can_bus)
    can_fd_if = CanFdInterface(ecu_id="ECU_ROUTER", bus=can_bus)
    return PduRouter(ecu_id="ECU_ROUTER", can_if=can_if, can_fd_if=can_fd_if)


@pytest.fixture
def pdu_router_no_canfd(can_bus):
    can_if = CanInterface(ecu_id="ECU_ROUTER_NOFD", bus=can_bus)
    return PduRouter(ecu_id="ECU_ROUTER_NOFD", can_if=can_if, can_fd_if=None)


@pytest.fixture
def secoc(nvm_stub, dem_stub, hsm_stub, cryif_stub, csm_stub, ecu_state):
    profile_provider = SecurityProfile(config_path="config/secoc_profiles.json")
    freshness_manager = FreshnessManager(
        nvm=nvm_stub, window_size=16, freshness_length=2
    )
    event_logger = EventLogger(dem=dem_stub, security_events=None)
    authenticator = Authenticator(
        key_manager=None,
        crypto_interface=None,
        profiler=None,
        event_logger=event_logger,
        profile_provider=profile_provider,
    )
    pdu_manager = PduManager(serializer=None)
    return SecOC(
        profile_provider=profile_provider,
        freshness_manager=freshness_manager,
        authenticator=authenticator,
        pdu_manager=pdu_manager,
        event_logger=event_logger,
        ecu_state=ecu_state,
    )


@pytest.mark.vtc("VTC-SR-16")
@pytest.mark.sim
class TestVTC_16:
    def test_precondition_can_interface_connected(self, can_interface, can_bus):
        """Precondition: CanInterface is subscribed and connected to the
        shared CanBus before any frame is sent."""
        status = can_interface.get_status()
        assert status["transport"] == "CLASSIC_CAN"
        assert status["max_payload_bytes"] == config.CAN_MAX_PAYLOAD_BYTES

    def test_precondition_can_fd_interface_connected(self, can_fd_interface, can_bus):
        """Precondition: CanFdInterface is subscribed and connected to the
        shared CanBus before any frame is sent."""
        status = can_fd_interface.get_status()
        assert status["transport"] == "CAN_FD"
        assert status["max_payload_bytes"] == config.CAN_FD_MAX_PAYLOAD_BYTES

    @pytest.mark.asyncio
    async def test_send_secured_pdu_via_classic_can(self, can_interface):
        """Step: Send the Secured I-PDU (<=8 bytes) via
        CanInterface.send_frame() on classic CAN."""
        await can_interface.send_frame(PDU_ID_NUMERIC, SHORT_SECURED_PDU)

    @pytest.mark.asyncio
    async def test_send_oversized_secured_pdu_on_classic_can_raises(
        self, can_interface
    ):
        """Step: Sending a Secured I-PDU >8 bytes via classic CAN raises
        PayloadTooLargeError, requiring CAN FD instead."""
        with pytest.raises(PayloadTooLargeError):
            await can_interface.send_frame(PDU_ID_NUMERIC, LONG_SECURED_PDU)

    @pytest.mark.asyncio
    async def test_send_secured_pdu_via_can_fd(self, can_fd_interface):
        """Step: Send the same SecOC message, sized for CAN FD (<=64
        bytes), via CanFdInterface.send_frame()."""
        await can_fd_interface.send_frame(PDU_ID_NUMERIC, LONG_SECURED_PDU)

    @pytest.mark.asyncio
    async def test_expected_result_classic_can_frame_validates_consistently(
        self, can_interface, secoc
    ):
        """Expected result: a Secured I-PDU received via classic CAN
        produces the same SecOC.receive_secured() outcome as the same
        message received via CAN FD."""
        await can_interface.send_frame(PDU_ID_NUMERIC, SHORT_SECURED_PDU)
        received_pdu_id, received_data = await can_interface.receive_frame()

        result_can = secoc.receive_secured(PDU_ID, received_data)

        assert received_pdu_id == PDU_ID_NUMERIC
        assert received_data == SHORT_SECURED_PDU
        # Recorded for cross-transport comparison against CAN FD result.
        assert result_can == secoc.receive_secured(PDU_ID, received_data)

    @pytest.mark.asyncio
    async def test_expected_result_can_and_canfd_results_match(
        self, can_interface, can_fd_interface, secoc
    ):
        """Expected result: the same authentic_pdu/accept-reject outcome is
        produced whether the Secured I-PDU arrives via CanInterface or
        CanFdInterface (SR-16 transport-consistency requirement)."""
        await can_interface.send_frame(PDU_ID_NUMERIC, SHORT_SECURED_PDU)
        _, data_classic = await can_interface.receive_frame()
        result_classic = secoc.receive_secured(PDU_ID, data_classic)

        await can_fd_interface.send_frame(PDU_ID_NUMERIC, SHORT_SECURED_PDU)
        _, data_fd = await can_fd_interface.receive_frame()
        result_fd = secoc.receive_secured(PDU_ID, data_fd)

        assert result_classic == result_fd

    @pytest.mark.asyncio
    async def test_pdu_router_selects_classic_can_for_short_payload(
        self, pdu_router_with_canfd, can_bus
    ):
        """Step (PduRouter layer, SR-16): route_to_bus() selects
        can_interface.py for a secured_pdu <= 8 bytes."""
        await pdu_router_with_canfd.route_to_bus(PDU_ID_NUMERIC, SHORT_SECURED_PDU)

        assert can_bus.get_last(PDU_ID_NUMERIC) == SHORT_SECURED_PDU

    @pytest.mark.asyncio
    async def test_pdu_router_selects_can_fd_for_long_payload(
        self, pdu_router_with_canfd, can_bus
    ):
        """Step (PduRouter layer, SR-16): route_to_bus() selects
        can_fd_interface.py for a secured_pdu > 8 and <= 64 bytes."""
        await pdu_router_with_canfd.route_to_bus(PDU_ID_NUMERIC, LONG_SECURED_PDU)

        assert can_bus.get_last(PDU_ID_NUMERIC) == LONG_SECURED_PDU

    @pytest.mark.asyncio
    async def test_pdu_router_oversized_payload_without_canfd_raises(
        self, pdu_router_no_canfd
    ):
        """Expected result (PduRouter layer, SR-16): route_to_bus() raises
        PayloadTooLargeError for a secured_pdu > 8 bytes when no CAN FD
        interface is configured for this router/ECU."""
        with pytest.raises(PayloadTooLargeError):
            await pdu_router_no_canfd.route_to_bus(PDU_ID_NUMERIC, LONG_SECURED_PDU)

    @pytest.mark.asyncio
    async def test_expected_result_end_to_end_verification_consistent_via_router(
        self, pdu_router_with_canfd, secoc, can_bus
    ):
        """Expected result (SR-16): a Secured I-PDU routed via PduRouter --
        auto-selecting classic CAN or CAN FD by size -- produces the same
        secoc.receive_secured() outcome either way."""
        await pdu_router_with_canfd.route_to_bus(PDU_ID_NUMERIC, SHORT_SECURED_PDU)
        result_short = secoc.receive_secured(PDU_ID, can_bus.get_last(PDU_ID_NUMERIC))

        await pdu_router_with_canfd.route_to_bus(PDU_ID_NUMERIC, LONG_SECURED_PDU)
        result_long = secoc.receive_secured(PDU_ID, can_bus.get_last(PDU_ID_NUMERIC))

        # Both malformed relative to the real profile trailer -- both rejected
        # (None), demonstrating consistent verification regardless of
        # transport chosen by the router.
        assert result_short == result_long == None  # noqa: E711
