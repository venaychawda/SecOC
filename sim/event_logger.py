"""Routes security/diagnostic events to DEM with classification support."""
from sim.dem import DEM, Severity
from sim.security_events import RejectionReason, SecurityEvents, classify


class EventLogger:
    """Logs DEM events directly or via SecurityEvents classification."""

    def __init__(self, dem: DEM, security_events: SecurityEvents | None = None) -> None:
        self._dem = dem
        self._security_events = security_events

    def log(self, severity: Severity, event_id: str, swr_ref: str = ""):
        """Log a DEM event with an explicit severity and event_id.

        Args:
            severity: DEM Severity.
            event_id: DEM event code.
            swr_ref: Software requirement reference.

        Returns:
            The recorded DemEvent.
        """
        return self._dem.log(event_id, severity, event_id, swr_ref=swr_ref)

    def log_rejection(self, pdu_id: str, reason: RejectionReason):
        """Log a Secured I-PDU rejection, classified per security_events table.

        Args:
            pdu_id: Logical PDU identifier of the rejected message.
            reason: RejectionReason for the rejection.

        Returns:
            The recorded DemEvent.
        """
        if self._security_events is not None:
            severity, event_id = self._security_events.classify(reason)
        else:
            severity, event_id = classify(reason)

        return self._dem.log(
            event_id,
            severity,
            f"Rejected pdu_id={pdu_id}: {reason.value}",
            data={"pdu_id": pdu_id},
        )
