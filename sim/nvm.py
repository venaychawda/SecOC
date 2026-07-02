"""NvM simulator — JSON-backed persistent key-value store with monotonic counters.

Drop-in stub for AUTOSAR NvM. Atomic write via write-then-rename.
"""
import json
import os
from pathlib import Path
from typing import Any

_BYTES_MARKER = "__bytes_hex__"


class NvMError(Exception):
    pass


def _encode(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        return {_BYTES_MARKER: bytes(value).hex()}
    if isinstance(value, dict):
        return {k: _encode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_encode(v) for v in value]
    return value


def _decode(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value.keys()) == {_BYTES_MARKER}:
            return bytes.fromhex(value[_BYTES_MARKER])
        return {k: _decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_decode(v) for v in value]
    return value


class NvM:
    """Simulates AUTOSAR NvM using a JSON file with atomic write semantics."""

    _DEFAULT_PATH = Path(__file__).parent / "nvm_store.json"

    def __init__(self, path: str | None = None) -> None:
        self._path = Path(path) if path else self._DEFAULT_PATH
        self._store: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                self._store = _decode(raw)
            except (json.JSONDecodeError, OSError):
                self._store = {}

    def flush(self) -> None:
        """Atomic write: write to .tmp then rename."""
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(_encode(self._store), indent=2), encoding="utf-8")
        os.replace(tmp, self._path)

    def read(self, key: str, default: Any = None) -> Any:
        """Read a value from NvM.

        Args:
            key: NvM block identifier.
            default: Value returned if key absent.

        Returns:
            Stored value or default.
        """
        return self._store.get(key, default)

    def write(self, key: str, value: Any) -> None:
        """Write a value to NvM and flush.

        Args:
            key: NvM block identifier.
            value: Value to persist.
        """
        self._store[key] = value
        self.flush()

    def increment_counter(self, key: str) -> int:
        """Increment a monotonic counter by 1 and return new value.

        Args:
            key: Counter identifier.

        Returns:
            New counter value.

        Raises:
            NvMError: On overflow.
        """
        current = self._store.get(key, 0)
        if current >= 2**63 - 1:
            raise NvMError("counter_overflow")
        new_val = current + 1
        self._store[key] = new_val
        self.flush()
        return new_val

    def get_counter(self, key: str) -> int:
        """Return current counter value without incrementing.

        Args:
            key: Counter identifier.

        Returns:
            Current counter value (0 if never set).
        """
        return int(self._store.get(key, 0))

    def reset_to_defaults(self) -> None:
        """Clear all NvM contents and flush."""
        self._store = {}
        self.flush()
