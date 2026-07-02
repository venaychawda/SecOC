"""
VTC-SR-04: Out-of-window message -> rejection per policy
Objective: Send messages outside freshness window and verify rejection
policy enforcement
Requirements: SR-04; SW-SecOC-02, SW-SecOC-03, SW-SecOC-05
"""
import pytest

from sim.freshness_manager import FreshnessManager
from sim.fuzzing_engine import FuzzingEngine, ForgeMode
from sim.message_injector import MessageInjector
from sim.can_bus import CanBus
from sim import config


PDU_ID = "PDU_BRAKE_TORQUE"
WINDOW_SIZE = 16
FRESHNESS_LENGTH = 2


@pytest.fixture
def freshness_manager(nvm_stub):
    return FreshnessManager(
        nvm=nvm_stub, window_size=WINDOW_SIZE, freshness_length=FRESHNESS_LENGTH
    )


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


@pytest.mark.vtc("VTC-SR-04")
@pytest.mark.sim
class TestVTC_04:
    def test_precondition_freshness_manager_initialized_unsynced(
        self, freshness_manager
    ):
        """Precondition: a fresh FreshnessManager has no committed last-valid
        freshness for PDU_BRAKE_TORQUE (UNSYNCED state, load returns 0)."""
        last_valid = freshness_manager.load_last_valid_freshness(PDU_ID)
        assert last_valid == 0

    def test_message_within_window_is_accepted(self, freshness_manager):
        """Step: a message whose reconstructed freshness is within
        [last_valid, last_valid + window_size] is accepted."""
        truncated = 1  # first valid increment, well within window
        freshness_ok, full_value = freshness_manager.validate_freshness(
            PDU_ID, truncated
        )
        assert freshness_ok is True
        assert full_value == 1

        freshness_manager.commit_freshness(PDU_ID, full_value)

    def test_message_beyond_window_size_is_rejected(self, freshness_manager):
        """Step: send a message whose freshness value is
        last_valid + window_size + 1 (just outside the configured sliding
        window) and verify rejection per policy (SR-04)."""
        # Establish a baseline last_valid value.
        freshness_manager.commit_freshness(PDU_ID, 10)

        out_of_window_truncated = 10 + WINDOW_SIZE + 1
        freshness_ok, full_value = freshness_manager.validate_freshness(
            PDU_ID, out_of_window_truncated
        )

        assert freshness_ok is False
        assert full_value == 0

    def test_stale_replayed_freshness_value_is_rejected(self, freshness_manager):
        """Step: send a message whose freshness value is <= last_valid
        (stale / replayed) and verify rejection per anti-replay policy."""
        freshness_manager.commit_freshness(PDU_ID, 10)

        stale_truncated = 10  # not strictly greater than last_valid
        freshness_ok, full_value = freshness_manager.validate_freshness(
            PDU_ID, stale_truncated
        )

        assert freshness_ok is False
        assert full_value == 0

    def test_fuzzing_engine_wrong_freshness_forged_pdu_is_rejected(
        self, freshness_manager, fuzzing_engine
    ):
        """Step: FuzzingEngine generates a forged PDU with
        ForgeMode.WRONG_FRESHNESS (out-of-window freshness value) and injects
        it onto the bus; the receiver's freshness validation rejects it."""
        freshness_manager.commit_freshness(PDU_ID, 10)

        forged_pdu = fuzzing_engine.generate_forged_pdu(
            PDU_ID, ForgeMode.WRONG_FRESHNESS
        )
        fuzzing_engine.inject(PDU_ID, forged_pdu)

        # Extract the truncated freshness field per the illustrative profile
        # layout: authentic_pdu || freshness(2 bytes) || mac(8 bytes)
        freshness_bytes = forged_pdu[-(FRESHNESS_LENGTH + 8) : -8]
        truncated_freshness = int.from_bytes(freshness_bytes, "big", signed=False)

        freshness_ok, full_value = freshness_manager.validate_freshness(
            PDU_ID, truncated_freshness
        )
        assert freshness_ok is False
        assert full_value == 0

    def test_expected_result_out_of_window_message_does_not_advance_last_valid(
        self, freshness_manager
    ):
        """Expected result: an out-of-window/replayed message is rejected and
        does NOT update freshness_<pdu_id>_last_valid in NvM (SW-SecOC-05)."""
        freshness_manager.commit_freshness(PDU_ID, 10)
        baseline = freshness_manager.load_last_valid_freshness(PDU_ID)

        out_of_window_truncated = 10 + WINDOW_SIZE + 1
        freshness_ok, _ = freshness_manager.validate_freshness(
            PDU_ID, out_of_window_truncated
        )
        assert freshness_ok is False

        after = freshness_manager.load_last_valid_freshness(PDU_ID)
        assert after == baseline
