"""Published HMAC-SHA256 test vectors (RFC 4231) for VTC-SR-06."""
from dataclasses import dataclass


@dataclass(frozen=True)
class TestVector:
    """A published HMAC-SHA256 test vector."""

    name: str
    key: bytes
    message: bytes
    expected_mac: bytes


_VECTORS: dict[str, TestVector] = {
    "rfc4231_case_2": TestVector(
        name="rfc4231_case_2",
        key=b"Jefe",
        message=b"what do ya want for nothing?",
        expected_mac=bytes.fromhex(
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        ),
    ),
}


def list_vector_names() -> list[str]:
    """Return the names of all available test vectors.

    Returns:
        List of vector names.
    """
    return list(_VECTORS.keys())


def get_vector(name: str) -> TestVector:
    """Look up a published test vector by name.

    Args:
        name: Vector name, e.g. "rfc4231_case_2".

    Returns:
        The TestVector.

    Raises:
        KeyError: If name is unknown.
    """
    return _VECTORS[name]


def expected_truncated_mac(vector: TestVector) -> bytes:
    """Return the expected MAC for a vector (full digest, no truncation).

    Args:
        vector: A TestVector.

    Returns:
        The expected MAC bytes.
    """
    return vector.expected_mac
