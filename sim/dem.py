"""DEM — Diagnostic Event Manager simulation.

Drop-in stub for AUTOSAR DEM. Records security events with severity
classification for audit and forensic traceability.

Also contains HashChainedLog: a tamper-evident, append-only security audit
journal with SHA-256 chain linking. Use DEM for AUTOSAR diagnostic events;
use HashChainedLog for security journals (auth, tamper, lifecycle events).
"""
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sim.config import MAX_AUDIT_ENTRIES


class Severity(str, Enum):
    INFO = "INFO"
    WARNING = "WARNING"
    CRITICAL = "CRITICAL"


@dataclass
class DemEvent:
    event_id: str
    timestamp: float
    severity: Severity
    description: str
    swr_ref: str
    data: dict = field(default_factory=dict)


class DEM:
    """Records AUTOSAR-style diagnostic events for audit and forensic traceability."""

    def __init__(self) -> None:
        self._events: list[DemEvent] = []
        self._counter: int = 0

    def log(self, event_id: str, severity: Severity, description: str,
            swr_ref: str = "", data: dict[str, Any] | None = None) -> DemEvent:
        self._counter += 1
        evt = DemEvent(
            event_id=event_id,
            timestamp=time.monotonic(),
            severity=severity,
            description=description,
            swr_ref=swr_ref,
            data=data or {},
        )
        self._events.append(evt)
        return evt

    def get_events(self) -> list[DemEvent]:
        return list(self._events)

    def get_events_by_severity(self, severity: Severity) -> list[DemEvent]:
        return [e for e in self._events if e.severity == severity]

    def clear(self) -> None:
        """Clear all events (test use only)."""
        self._events.clear()
        self._counter = 0


class HashChainedLog:
    """Append-only, hash-chained event journal for security audit trails.

    Each entry is SHA-256 chained to the previous entry's hash, providing
    tamper evidence: any modification or deletion of a past entry breaks the
    chain and is detected by verify_integrity().

    Design rules (preserve in all projects):
    - No clear() API — entries are never deleted by software request.
    - FIFO eviction when max_entries is reached (oldest entries dropped).
    - verify_integrity() walks the full chain from genesis; must stay O(n).
    """

    def __init__(self, max_entries: int = MAX_AUDIT_ENTRIES):
        self._max = max_entries
        self._entries: list[dict] = []
        self._prev_hash = "0" * 64

    def log(self, event: str, detail: dict | None = None) -> None:
        entry = {
            "event": event,
            "timestamp": time.time(),
            "detail": detail or {},
        }
        entry["hash"] = self._chain_hash(entry)
        self._prev_hash = entry["hash"]
        self._entries.append(entry)
        if len(self._entries) > self._max:
            self._entries.pop(0)

    def entries(self, last_n: int = 50) -> list[dict]:
        return self._entries[-last_n:]

    def verify_integrity(self) -> bool:
        prev = "0" * 64
        for e in self._entries:
            expected = self._chain_hash({k: v for k, v in e.items() if k != "hash"}, prev)
            if e["hash"] != expected:
                return False
            prev = e["hash"]
        return True

    def _chain_hash(self, entry: dict, prev: str | None = None) -> str:
        if prev is None:
            prev = self._prev_hash
        payload = json.dumps({"prev": prev, "entry": entry}, sort_keys=True)
        return hashlib.sha256(payload.encode()).hexdigest()
