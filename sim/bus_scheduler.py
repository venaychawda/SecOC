"""Periodic transmission scheduler for simulated bus load (SR-15)."""
from typing import Callable


class BusScheduler:
    """Schedules periodic PDU transmissions and fires them on tick()."""

    def __init__(self, scheduler_id: str) -> None:
        self._scheduler_id = scheduler_id
        self._running = False
        self._entries: list[dict] = []

    def schedule_periodic(self, pdu_id, period_ms: int, callback: Callable) -> None:
        """Register a periodic transmission.

        Args:
            pdu_id: Logical or numeric PDU identifier.
            period_ms: Period between firings, in milliseconds.
            callback: Callable invoked with pdu_id when the entry fires.
        """
        self._entries.append({
            "pdu_id": pdu_id,
            "period_ms": period_ms,
            "callback": callback,
            "last_fired_ms": 0,
        })

    def start(self) -> None:
        """Mark the scheduler as running."""
        self._running = True

    def tick(self, now_ms: int) -> None:
        """Advance simulated time, firing any due periodic entries.

        Args:
            now_ms: Current simulated time in milliseconds.
        """
        if not self._running:
            return
        for entry in self._entries:
            if now_ms - entry["last_fired_ms"] >= entry["period_ms"]:
                entry["last_fired_ms"] = now_ms
                entry["callback"](entry["pdu_id"])

    def get_status(self) -> dict:
        """Return the scheduler's current state and registered entries.

        Returns:
            Dict with "state" ("RUNNING"/"IDLE") and "entries" (list of
            dicts with "pdu_id" and "period_ms").
        """
        return {
            "state": "RUNNING" if self._running else "IDLE",
            "entries": [
                {"pdu_id": entry["pdu_id"], "period_ms": entry["period_ms"]}
                for entry in self._entries
            ],
        }
