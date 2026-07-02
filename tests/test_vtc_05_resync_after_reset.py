"""
VTC-SR-05: ECU reset -> resynchronization restores comms
Objective: Simulate ECU reset and verify resynchronization procedure restores
secure communication
Requirements: SR-05; SW-SecOC-05, SW-SecOC-09
"""
import pytest

from sim.freshness_manager import FreshnessManager

PDU_ID = "PDU_0x100"
WINDOW_SIZE = 16
FRESHNESS_LENGTH = 2


@pytest.fixture
def freshness_manager(nvm_stub):
    return FreshnessManager(
        nvm=nvm_stub,
        window_size=WINDOW_SIZE,
        freshness_length=FRESHNESS_LENGTH,
    )


@pytest.mark.vtc("VTC-SR-05")
@pytest.mark.sim
class TestVTC_05:
    def test_precondition_last_valid_freshness_persisted(self, freshness_manager, nvm_stub):
        """Precondition: a prior session committed a last-valid freshness value to NvM."""
        freshness_manager.commit_freshness(PDU_ID, 100)

        assert nvm_stub.read(f"freshness_{PDU_ID}_last_valid") == 100

    def test_simulated_ecu_reset_loads_last_valid_freshness(self, nvm_stub):
        """Simulate ECU reset: a fresh FreshnessManager instance backed by the same
        NvM store must recover the previously committed last-valid freshness."""
        original = FreshnessManager(
            nvm=nvm_stub,
            window_size=WINDOW_SIZE,
            freshness_length=FRESHNESS_LENGTH,
        )
        original.commit_freshness(PDU_ID, 250)

        # Simulate ECU reset -> new instance, same NvM backend.
        rebooted = FreshnessManager(
            nvm=nvm_stub,
            window_size=WINDOW_SIZE,
            freshness_length=FRESHNESS_LENGTH,
        )

        assert rebooted.load_last_valid_freshness(PDU_ID) == 250

    def test_first_boot_returns_zero(self, freshness_manager):
        """A PDU never committed before returns 0 on load (first boot, no NvM entry)."""
        assert freshness_manager.load_last_valid_freshness("PDU_0x200") == 0

    def test_resync_reinitializes_window(self, freshness_manager, nvm_stub):
        """Action: resynchronization procedure (SW-SecOC-09) reinitializes the
        anti-replay window using the peer's current freshness value."""
        freshness_manager.commit_freshness(PDU_ID, 100)

        resync_value = 500
        freshness_manager.reinitialize_window(PDU_ID, resync_value)

        assert nvm_stub.read(f"freshness_{PDU_ID}_last_valid") == resync_value
        assert nvm_stub.read(f"freshness_{PDU_ID}_anti_replay_window") == []

    def test_expected_result_post_resync_accepts_only_values_above_resync_baseline(
        self, freshness_manager
    ):
        """Expected result: after resync, only freshness values strictly greater
        than the resynced baseline are accepted; stale/old values are rejected."""
        resync_value = 500
        freshness_manager.reinitialize_window(PDU_ID, resync_value)

        # A value at or below the resync baseline is rejected (replay/stale).
        ok_stale, full_stale = freshness_manager.validate_freshness(
            PDU_ID, resync_value & 0xFFFF
        )
        assert ok_stale is False
        assert full_stale == 0

        # A value strictly greater than the resync baseline (within window) is accepted.
        new_truncated = (resync_value + 1) & 0xFFFF
        ok_new, full_new = freshness_manager.validate_freshness(PDU_ID, new_truncated)
        assert ok_new is True
        assert full_new == resync_value + 1

    def test_expected_result_communication_resumes_after_resync(self, freshness_manager):
        """Expected result: secure communication resumes — a subsequent valid
        message (within the new window) is accepted and can be committed."""
        resync_value = 500
        freshness_manager.reinitialize_window(PDU_ID, resync_value)

        next_truncated = (resync_value + 1) & 0xFFFF
        ok, full_value = freshness_manager.validate_freshness(PDU_ID, next_truncated)
        assert ok is True

        freshness_manager.commit_freshness(PDU_ID, full_value)
        assert freshness_manager.load_last_valid_freshness(PDU_ID) == full_value
