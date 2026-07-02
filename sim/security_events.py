"""SecOC rejection-reason classification table (SR-13, SW-SecOC-06)."""
from enum import Enum

from sim.dem import Severity


class RejectionReason(str, Enum):
    """Reasons a received Secured I-PDU may be rejected."""

    MAC_MISMATCH = "MAC_MISMATCH"
    FRESHNESS_OUT_OF_WINDOW = "FRESHNESS_OUT_OF_WINDOW"
    MALFORMED_STRUCTURE = "MALFORMED_STRUCTURE"


_CLASSIFICATION_TABLE: dict[RejectionReason, tuple[Severity, str]] = {
    RejectionReason.MAC_MISMATCH: (Severity.CRITICAL, "SECOC_AUTH_FAIL"),
    RejectionReason.FRESHNESS_OUT_OF_WINDOW: (Severity.CRITICAL, "SECOC_AUTH_FAIL"),
    RejectionReason.MALFORMED_STRUCTURE: (Severity.CRITICAL, "SECOC_AUTH_FAIL"),
}


def classify(reason: RejectionReason) -> tuple[Severity, str]:
    """Classify a rejection reason into (severity, DEM event code).

    Args:
        reason: The RejectionReason to classify.

    Returns:
        (Severity, event_id) per the SW-SecOC-06 / SR-13 classification table.
    """
    return _CLASSIFICATION_TABLE.get(reason, (Severity.WARNING, "SECOC_UNKNOWN_REJECTION"))


class SecurityEvents:
    """Classifies rejection reasons for DEM logging and fault escalation."""

    def __init__(self, fault_manager=None) -> None:
        self._fault_manager = fault_manager

    def classify(self, reason: RejectionReason) -> tuple[Severity, str]:
        """Classify reason into (severity, DEM event code).

        Args:
            reason: The RejectionReason to classify.

        Returns:
            (Severity, event_id) per the SW-SecOC-06 / SR-13 classification table.
        """
        return classify(reason)
