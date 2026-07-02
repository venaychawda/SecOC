"""Tracks per-PDU failure counts and drives security policy evaluation."""
from enum import Enum

from sim.security_policy_engine import SecurityPolicyEngine


class FailureCategory(str, Enum):
    """Category of a recorded crypto/protocol failure."""

    AUTH = "AUTH"
    FRESHNESS = "FRESHNESS"
    CRYPTO = "CRYPTO"


class FaultManager:
    """Records per-PDU failures and triggers SecurityPolicyEngine evaluation."""

    def __init__(self, security_policy_engine: SecurityPolicyEngine) -> None:
        self._security_policy_engine = security_policy_engine
        self._counts: dict[str, int] = {}

    def record_failure(self, pdu_id: str, category: FailureCategory) -> int:
        """Record a failure for pdu_id and evaluate security policy.

        Args:
            pdu_id: Logical PDU identifier.
            category: FailureCategory of the failure.

        Returns:
            The updated failure count for pdu_id.
        """
        self._counts[pdu_id] = self._counts.get(pdu_id, 0) + 1
        if category == FailureCategory.AUTH:
            self._security_policy_engine.evaluate(self._counts[pdu_id])
        return self._counts[pdu_id]

    def get_failure_count(self, pdu_id: str) -> int:
        """Return the current failure count for pdu_id.

        Args:
            pdu_id: Logical PDU identifier.

        Returns:
            Failure count (0 if none recorded).
        """
        return self._counts.get(pdu_id, 0)
