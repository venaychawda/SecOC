"""Shared simulated CAN bus -- a process-wide singleton message medium."""


class CanBus:
    """Process-wide singleton simulated CAN bus.

    Maintains a FIFO delivery queue (consumed by CanInterface/CanFdInterface)
    and a per-pdu_id "last observed frame" registry (used by attack-simulation
    modules such as ReplayAttack).
    """

    _instance: "CanBus | None" = None

    def __new__(cls) -> "CanBus":
        if cls._instance is None:
            instance = super().__new__(cls)
            instance._running = False
            instance._last_frames = {}
            instance._queue = []
            cls._instance = instance
        return cls._instance

    def start(self) -> None:
        """Mark the bus as running and reset its message state.

        Models a bus power-on/reset: the FIFO delivery queue and the
        per-pdu_id "last observed" registry are cleared, giving each test
        that calls start() a clean shared-singleton baseline.
        """
        self._running = True
        self._last_frames = {}
        self._queue = []

    def is_running(self) -> bool:
        """Return True if the bus has been started.

        Returns:
            True if start() has been called.
        """
        return self._running

    def publish(self, pdu_id, data: bytes) -> None:
        """Publish a frame onto the bus.

        Args:
            pdu_id: Logical or numeric PDU identifier.
            data: Frame payload bytes.
        """
        self._last_frames[pdu_id] = data
        self._queue.append((pdu_id, data))

    def get_last(self, pdu_id):
        """Return the most recently published frame for pdu_id.

        Args:
            pdu_id: Logical or numeric PDU identifier.

        Returns:
            The most recently published payload bytes, or None.
        """
        return self._last_frames.get(pdu_id)

    def consume(self):
        """Pop and return the oldest queued (pdu_id, data) frame.

        Returns:
            (pdu_id, data) tuple, or None if the queue is empty.
        """
        if not self._queue:
            return None
        return self._queue.pop(0)
