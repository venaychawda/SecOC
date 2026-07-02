"""JSON-driven SecOC security profile configuration (SR-10, SR-11, SR-17, SR-20, SR-21)."""
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from sim.config import SUPPORTED_ALGORITHMS


class Transport(str, Enum):
    """Wire transport a Secured I-PDU is being built/parsed for (SR-16, SR-21).

    CLASSIC_CAN uses the profile's tfv_length/tmac_length (fixed 8-byte
    frame budget, SW-SecOC-11). CAN_FD uses the existing
    freshness_length/authenticator_length pair, unaffected.
    """

    CLASSIC_CAN = "CLASSIC_CAN"
    CAN_FD = "CAN_FD"


class SecOCConfigError(Exception):
    """Raised for security-profile lookups/updates referencing an unknown PDU."""


class SecurityProfileConfigError(Exception):
    """Raised when a security profile entry is invalid or out of scope."""


@dataclass
class SecurityProfileEntry:
    """Authenticity/integrity-only SecOC security profile entry (SR-20).

    No confidentiality, cipher, or encryption fields are part of this
    schema -- AUTOSAR SecOC provides authenticity and integrity only.

    tfv_length/tmac_length are optional and only required for PDUs that will
    be transmitted over Classic CAN (SR-21): the Truncated Freshness Value
    (LSB of the freshness counter) and Truncated Authenticator/MAC (MSB of
    the computed MAC) byte lengths, which must sum to exactly 4 so that the
    Secured I-PDU (4-byte Authentic I-PDU + TFV + TMAC) fits the classic
    8-byte CAN frame. CAN FD continues to use freshness_length/
    authenticator_length, unaffected.
    """

    algorithm: str
    key_id: str
    freshness_length: int
    authenticator_length: int
    profile_version: str
    tfv_length: int | None = None
    tmac_length: int | None = None

    def truncation_lengths(self, transport: Transport) -> tuple[int, int]:
        """Returns the (freshness, authenticator) truncation lengths for transport.

        Args:
            transport: CLASSIC_CAN or CAN_FD.

        Returns:
            (freshness_trunc_length, authenticator_trunc_length) in bytes --
            (tfv_length, tmac_length) for CLASSIC_CAN, or
            (freshness_length, authenticator_length) for CAN_FD.

        Raises:
            SecurityProfileConfigError: If transport is CLASSIC_CAN and this
                profile has no tfv_length/tmac_length configured.
        """
        if transport == Transport.CLASSIC_CAN:
            if self.tfv_length is None or self.tmac_length is None:
                raise SecurityProfileConfigError(
                    "no tfv_length/tmac_length configured for CLASSIC_CAN transport"
                )
            return self.tfv_length, self.tmac_length
        return self.freshness_length, self.authenticator_length


_ALLOWED_FIELDS = {
    "algorithm",
    "key_id",
    "freshness_length",
    "authenticator_length",
    "profile_version",
    "tfv_length",
    "tmac_length",
}

_CLASSIC_CAN_TRUNC_BUDGET_BYTES = 4


class SecurityProfile:
    """Loads and provides per-PDU SecOC security profiles from JSON config."""

    def __init__(self, config_path: str) -> None:
        self._config_path = config_path
        self._profiles: dict[str, SecurityProfileEntry] = {}
        self.reload()

    def reload(self) -> None:
        """Reload security profiles from the JSON config file.

        Raises:
            SecurityProfileConfigError: If an entry uses an unsupported
                algorithm or declares fields outside the authenticity/
                integrity-only schema (e.g. confidentiality_enabled).
        """
        with open(self._config_path, "r", encoding="utf-8") as f:
            raw = json.load(f)

        profiles: dict[str, SecurityProfileEntry] = {}
        for pdu_id, entry in raw.items():
            extra_fields = set(entry.keys()) - _ALLOWED_FIELDS
            if extra_fields:
                raise SecurityProfileConfigError(
                    f"profile '{pdu_id}' declares unsupported fields: {extra_fields}"
                )
            if entry["algorithm"] not in SUPPORTED_ALGORITHMS:
                raise SecurityProfileConfigError(
                    f"profile '{pdu_id}' uses unsupported algorithm: {entry['algorithm']}"
                )

            tfv_length = entry.get("tfv_length")
            tmac_length = entry.get("tmac_length")
            if (tfv_length is None) != (tmac_length is None):
                raise SecurityProfileConfigError(
                    f"profile '{pdu_id}': tfv_length and tmac_length must both be "
                    f"set or both omitted"
                )
            if tfv_length is not None and tfv_length + tmac_length != _CLASSIC_CAN_TRUNC_BUDGET_BYTES:
                raise SecurityProfileConfigError(
                    f"profile '{pdu_id}': tfv_length + tmac_length must equal "
                    f"{_CLASSIC_CAN_TRUNC_BUDGET_BYTES} bytes (got {tfv_length}+{tmac_length})"
                )

            profiles[pdu_id] = SecurityProfileEntry(
                algorithm=entry["algorithm"],
                key_id=entry["key_id"],
                freshness_length=entry["freshness_length"],
                authenticator_length=entry["authenticator_length"],
                profile_version=entry["profile_version"],
                tfv_length=tfv_length,
                tmac_length=tmac_length,
            )
        self._profiles = profiles

    def get_profile(self, pdu_id: str) -> SecurityProfileEntry:
        """Return the security profile entry for pdu_id.

        Args:
            pdu_id: Logical PDU identifier.

        Returns:
            The SecurityProfileEntry.

        Raises:
            SecOCConfigError: If pdu_id has no configured profile.
        """
        try:
            return self._profiles[pdu_id]
        except KeyError as exc:
            raise SecOCConfigError(f"no security profile for pdu_id '{pdu_id}'") from exc

    def update_profile_version(self, pdu_id: str, profile_version: str) -> None:
        """Update and persist the profile_version for pdu_id (SR-17).

        Args:
            pdu_id: Logical PDU identifier.
            profile_version: New profile version string.

        Raises:
            SecOCConfigError: If pdu_id has no configured profile.
        """
        if pdu_id not in self._profiles:
            raise SecOCConfigError(f"no security profile for pdu_id '{pdu_id}'")

        entry = self._profiles[pdu_id]
        entry.profile_version = profile_version

        with open(self._config_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        raw[pdu_id]["profile_version"] = profile_version

        path = Path(self._config_path)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(raw, indent=2), encoding="utf-8")
        tmp.replace(path)
