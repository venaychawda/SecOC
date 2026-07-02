"""Secure boot integrity gate: blocks SecOC startup on firmware tamper (SR-19)."""
from sim.dem import Severity
from sim.event_logger import EventLogger
from sim.integrity_checker import IntegrityChecker
from sim.nvm import NvM

# Simulated current firmware/config/key-metadata snapshot, hashed and
# compared against the golden hashes provisioned in NvM at boot time.
_CURRENT_SNAPSHOT = b"SECOC_FIRMWARE_SNAPSHOT_V1::code+config+keymeta"

_COMPONENTS = (
    ("code", "boot_golden_hash_code"),
    ("config", "boot_golden_hash_config"),
    ("keys", "boot_golden_hash_keys"),
)


class SecureBoot:
    """Verifies firmware/config/key-metadata integrity before SecOC startup."""

    def __init__(self, integrity_checker: IntegrityChecker, nvm: NvM,
                 event_logger: EventLogger) -> None:
        self._integrity_checker = integrity_checker
        self._nvm = nvm
        self._event_logger = event_logger
        self._boot_integrity_ok: bool | None = None
        self._failed_component: str | None = None

    def _verify_component(self, golden_hash_key: str) -> bool:
        golden_hash = self._nvm.read(golden_hash_key)
        return self._integrity_checker.verify_integrity(_CURRENT_SNAPSHOT, golden_hash)

    def verify_code_integrity(self) -> bool:
        """Verify the code-snapshot hash against its golden value (SR-19)."""
        return self._verify_component("boot_golden_hash_code")

    def verify_config_integrity(self) -> bool:
        """Verify the config-snapshot hash against its golden value (SR-19)."""
        return self._verify_component("boot_golden_hash_config")

    def verify_keys_integrity(self) -> bool:
        """Verify the key-metadata-snapshot hash against its golden value (SR-19)."""
        return self._verify_component("boot_golden_hash_keys")

    def verify_boot_integrity(self) -> bool:
        """Run the fail-fast boot integrity check over code, config, keys.

        Returns:
            True if all components match their golden hashes; False if any
            mismatch is detected (boot is blocked).
        """
        for component_name, golden_hash_key in _COMPONENTS:
            if not self._verify_component(golden_hash_key):
                self._failed_component = component_name
                self._boot_integrity_ok = False
                self._event_logger.log(
                    Severity.CRITICAL, "BOOT_INTEGRITY_FAIL", swr_ref="SR-19"
                )
                return False

        self._failed_component = None
        self._boot_integrity_ok = True
        return True

    def get_status(self) -> dict:
        """Return the most recent boot integrity verdict.

        Returns:
            Dict with "boot_integrity_ok" and "failed_component".
        """
        return {
            "boot_integrity_ok": self._boot_integrity_ok,
            "failed_component": self._failed_component,
        }
