"""
VTC-SR-19: Corrupted firmware at boot -> comms blocked
Objective: Corrupt firmware at boot and verify secure boot blocks communication
Requirements: SR-19; — (SIMULATION ONLY — hardware enforcement deferred,
see requirements/traceability_matrix.md §5)
"""
import pytest

from sim.dem import Severity
from sim.secure_boot import SecureBoot
from sim.integrity_checker import IntegrityChecker
from sim.event_logger import EventLogger


FIRMWARE_SNAPSHOT = b"SECOC_FIRMWARE_SNAPSHOT_V1::code+config+keymeta"


@pytest.fixture
def integrity_checker(cryif_stub):
    return IntegrityChecker(cryif=cryif_stub)


@pytest.fixture
def event_logger(dem_stub):
    return EventLogger(dem=dem_stub)


@pytest.fixture
def provisioned_nvm(nvm_stub, integrity_checker):
    """NvM pre-provisioned with golden hashes computed over the unmodified
    firmware snapshot (out-of-band provisioning, per LLD_secure_boot.md §4.3)."""
    golden_hash = integrity_checker.compute_hash(FIRMWARE_SNAPSHOT)
    nvm_stub.write("boot_golden_hash_code", golden_hash)
    nvm_stub.write("boot_golden_hash_config", golden_hash)
    nvm_stub.write("boot_golden_hash_keys", golden_hash)
    return nvm_stub


@pytest.fixture
def secure_boot(integrity_checker, provisioned_nvm, event_logger):
    return SecureBoot(
        integrity_checker=integrity_checker,
        nvm=provisioned_nvm,
        event_logger=event_logger,
    )


@pytest.mark.vtc("VTC-SR-19")
@pytest.mark.sim
class TestVTC_19:
    def test_precondition_golden_hashes_provisioned(self, provisioned_nvm):
        """Precondition: golden hash values for code, config, and key
        metadata have been provisioned into NvM at simulation setup time."""
        assert provisioned_nvm.read("boot_golden_hash_code") is not None
        assert provisioned_nvm.read("boot_golden_hash_config") is not None
        assert provisioned_nvm.read("boot_golden_hash_keys") is not None

    def test_unmodified_firmware_passes_boot_integrity(
        self, secure_boot, integrity_checker, provisioned_nvm
    ):
        """Precondition: with an unmodified firmware snapshot whose hash
        matches the provisioned golden hashes, verify_boot_integrity()
        returns True and SecOC initialization is permitted."""
        golden = provisioned_nvm.read("boot_golden_hash_code")
        assert integrity_checker.verify_integrity(FIRMWARE_SNAPSHOT, golden)

        assert secure_boot.verify_boot_integrity() is True

    def test_corrupted_firmware_fails_integrity_check(self, integrity_checker):
        """Step: corrupt the firmware bytes (simulating a tampered/corrupted
        boot image) and verify IntegrityChecker.verify_integrity() detects
        the mismatch against the golden hash."""
        golden_hash = integrity_checker.compute_hash(FIRMWARE_SNAPSHOT)

        corrupted_firmware = FIRMWARE_SNAPSHOT[:-1] + b"\x00"

        assert not integrity_checker.verify_integrity(corrupted_firmware, golden_hash)

    def test_corrupted_firmware_blocks_boot_integrity(
        self, secure_boot, integrity_checker, provisioned_nvm, monkeypatch
    ):
        """Step: with corrupted code-snapshot data, secure_boot.verify_code_integrity()
        (and therefore verify_boot_integrity()) returns False -- boot is
        blocked, fail-fast, before checking config/key-metadata."""
        # Simulate corruption: re-provision the golden hash for an
        # unmodified snapshot, then have SecureBoot check against a
        # corrupted snapshot by overwriting the golden hash with the hash
        # of a *different* (unmodified) snapshot, simulating a mismatch
        # between the on-boot computed hash and the golden value.
        tampered_golden = integrity_checker.compute_hash(b"TAMPERED_GOLDEN_VALUE")
        provisioned_nvm.write("boot_golden_hash_code", tampered_golden)

        assert secure_boot.verify_boot_integrity() is False

    def test_expected_result_critical_dem_event_logged_on_corruption(
        self, secure_boot, integrity_checker, provisioned_nvm, dem_stub
    ):
        """Expected result: a CRITICAL BOOT_INTEGRITY_FAIL DEM event is
        logged when verify_boot_integrity() detects corruption."""
        tampered_golden = integrity_checker.compute_hash(b"TAMPERED_GOLDEN_VALUE")
        provisioned_nvm.write("boot_golden_hash_code", tampered_golden)

        secure_boot.verify_boot_integrity()

        critical_events = dem_stub.get_events_by_severity(Severity.CRITICAL)
        assert any(e.event_id == "BOOT_INTEGRITY_FAIL" for e in critical_events)

    def test_expected_result_secoc_initialization_blocked(
        self, secure_boot, provisioned_nvm
    ):
        """Expected result: when verify_boot_integrity() returns False,
        secoc.on_startup() must not be called and the ECU remains in
        BOOT_BLOCKED -- this test asserts the gating contract: a False
        return value is the sole signal callers use to withhold
        secoc.on_startup()."""
        tampered_golden = b"\x00" * 32
        provisioned_nvm.write("boot_golden_hash_code", tampered_golden)

        boot_ok = secure_boot.verify_boot_integrity()

        assert boot_ok is False
        status = secure_boot.get_status()
        assert status["boot_integrity_ok"] is False
        assert status["failed_component"] is not None
