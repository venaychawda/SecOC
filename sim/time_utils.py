"""Simulation-time helpers: monotonic ms clock, sleep, and ISO-8601 display."""
import time
from datetime import datetime, timedelta, timezone

_epoch: datetime | None = None


def now_ms() -> int:
    """Returns the current simulated time in whole milliseconds.

    Backed by a monotonic clock (time.monotonic()), not wall-clock time.

    Returns:
        The current monotonic simulation time, in milliseconds.
    """
    return int(time.monotonic() * 1000)


def sleep_ms(duration_ms: int) -> None:
    """Blocks the calling thread for duration_ms milliseconds.

    Args:
        duration_ms: Number of milliseconds to sleep. Must be >= 0.

    Raises:
        ValueError: If duration_ms < 0.
    """
    if duration_ms < 0:
        raise ValueError("duration_ms must be >= 0")
    time.sleep(duration_ms / 1000.0)


def elapsed_ms(start_ms: int) -> int:
    """Returns the number of milliseconds elapsed since start_ms.

    Args:
        start_ms: A previous value returned by now_ms().

    Returns:
        now_ms() - start_ms.
    """
    return now_ms() - start_ms


def to_iso8601(ms: int) -> str:
    """Formats a now_ms()-style monotonic timestamp as an ISO-8601 string.

    Note:
        now_ms() is monotonic, not wall-clock, so the returned string is
        computed relative to the simulation's start epoch (captured at
        first use) purely for human-readable, monotonically increasing
        display timestamps.

    Args:
        ms: A monotonic timestamp in milliseconds, as returned by now_ms().

    Returns:
        An ISO-8601 formatted string.
    """
    global _epoch
    if _epoch is None:
        _epoch = datetime.now(timezone.utc) - timedelta(milliseconds=now_ms())
    return (_epoch + timedelta(milliseconds=ms)).isoformat()
