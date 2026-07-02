"""Per-PDU freshness/anti-replay management (SR-03, SR-04, SR-05, SW-SecOC-09)."""
from sim.nvm import NvM


class FreshnessManager:
    """Manages per-PDU monotonic freshness counters and a sliding anti-replay window."""

    def __init__(self, nvm: NvM, window_size: int, freshness_length: int) -> None:
        self._nvm = nvm
        self._window_size = window_size
        self._freshness_length = freshness_length
        self._modulus = 1 << (freshness_length * 8)

    def _last_valid_key(self, pdu_id: str) -> str:
        return f"freshness_{pdu_id}_last_valid"

    def _window_key(self, pdu_id: str) -> str:
        return f"freshness_{pdu_id}_anti_replay_window"

    def load_last_valid_freshness(self, pdu_id: str) -> int:
        """Return the last committed full freshness value for pdu_id.

        Args:
            pdu_id: Logical PDU identifier.

        Returns:
            The last committed value, or 0 if never committed (first boot).
        """
        return self._nvm.read(self._last_valid_key(pdu_id), 0)

    def validate_freshness(self, pdu_id: str, truncated: int) -> tuple[bool, int]:
        """Validate a received truncated freshness value (SR-03, SR-04).

        Reconstructs the full freshness value from the truncated field and
        the last committed value, then checks it falls strictly within
        (last_valid, last_valid + window_size].

        Args:
            pdu_id: Logical PDU identifier.
            truncated: Truncated freshness value as received on the wire.

        Returns:
            (True, full_value) if accepted, otherwise (False, 0).
        """
        last_valid = self.load_last_valid_freshness(pdu_id)

        base = (last_valid // self._modulus) * self._modulus
        candidate = base + truncated
        if candidate <= last_valid:
            candidate += self._modulus

        delta = candidate - last_valid
        if 0 < delta <= self._window_size:
            return True, candidate
        return False, 0

    def commit_freshness(self, pdu_id: str, full_value: int) -> None:
        """Persist full_value as the new last-valid freshness for pdu_id.

        Args:
            pdu_id: Logical PDU identifier.
            full_value: Full (untruncated) freshness counter value.
        """
        self._nvm.write(self._last_valid_key(pdu_id), full_value)
        self._nvm.write(self._window_key(pdu_id), [])

    def reinitialize_window(self, pdu_id: str, resync_value: int) -> None:
        """Resynchronize: reset last-valid and anti-replay window (SW-SecOC-09).

        Args:
            pdu_id: Logical PDU identifier.
            resync_value: Full freshness value reported by the peer.
        """
        self._nvm.write(self._last_valid_key(pdu_id), resync_value)
        self._nvm.write(self._window_key(pdu_id), [])
