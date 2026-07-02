"""Operation timing profiler for WCET compliance checks (SR-12, SW-SecOC-08)."""
import time
from dataclasses import dataclass
from enum import Enum

from sim.config import MAC_WCET_BUDGET_MS


class ProfilerStatus(str, Enum):
    """Per-sample WCET compliance status."""

    WITHIN_BUDGET = "WITHIN_BUDGET"
    EXCEEDED = "EXCEEDED"


@dataclass
class ProfilerSample:
    """A single timed operation sample."""

    operation_id: str
    elapsed_ms: float
    status: ProfilerStatus


class PerformanceProfiler:
    """Brackets operations with start()/stop() and records timing samples."""

    def __init__(self, budget_ms: float = MAC_WCET_BUDGET_MS) -> None:
        self._budget_ms = budget_ms
        self._starts: dict[str, float] = {}
        self._samples: list[ProfilerSample] = []

    def start(self, operation_id: str) -> None:
        """Begin timing operation_id.

        Args:
            operation_id: Unique identifier for this timed operation.
        """
        self._starts[operation_id] = time.perf_counter()

    def stop(self, operation_id: str) -> float:
        """Stop timing operation_id and record a sample.

        Args:
            operation_id: Identifier previously passed to start().

        Returns:
            Elapsed time in milliseconds.
        """
        start = self._starts.pop(operation_id, None)
        if start is None:
            start = time.perf_counter()
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        status = (
            ProfilerStatus.EXCEEDED
            if elapsed_ms > self._budget_ms
            else ProfilerStatus.WITHIN_BUDGET
        )
        self._samples.append(ProfilerSample(operation_id, elapsed_ms, status))
        return elapsed_ms

    def get_samples(self) -> list[ProfilerSample]:
        """Return all recorded samples.

        Returns:
            List of ProfilerSample, in recording order.
        """
        return list(self._samples)

    def get_summary(self) -> dict:
        """Return aggregate timing statistics.

        Returns:
            Dict with count, max_ms, avg_ms, exceeded_count.
        """
        if not self._samples:
            return {"count": 0, "max_ms": 0.0, "avg_ms": 0.0, "exceeded_count": 0}
        elapsed = [s.elapsed_ms for s in self._samples]
        return {
            "count": len(self._samples),
            "max_ms": max(elapsed),
            "avg_ms": sum(elapsed) / len(elapsed),
            "exceeded_count": sum(
                1 for s in self._samples if s.status == ProfilerStatus.EXCEEDED
            ),
        }

    def reset(self) -> None:
        """Clear all recorded samples and pending start times."""
        self._starts.clear()
        self._samples.clear()


_default = PerformanceProfiler()


def start(operation_id: str) -> None:
    """Module-level convenience: start timing on the default profiler."""
    _default.start(operation_id)


def stop(operation_id: str) -> float:
    """Module-level convenience: stop timing on the default profiler."""
    return _default.stop(operation_id)


def get_samples() -> list[ProfilerSample]:
    """Module-level convenience: get samples from the default profiler."""
    return _default.get_samples()


def get_summary() -> dict:
    """Module-level convenience: get summary from the default profiler."""
    return _default.get_summary()


def reset() -> None:
    """Module-level convenience: reset the default profiler."""
    _default.reset()
