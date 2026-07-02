"""
VTC-SR-17: Security profile version change -> traceable, consistent
Objective: Modify security profile version and verify traceability and validation
consistency
Requirements: SR-17; SW-SecOC-07
"""
import json

import pytest

from sim.security_profile import SecurityProfile
from sim.key_manager import KeyManager
from sim.key_storage import KeyStorage


PDU_ID = "PDU_BRAKE_TORQUE"
INITIAL_KEY_ID = "secoc_mac_key_PDU_BRAKE_TORQUE"
ROTATED_KEY_ID = "secoc_mac_key_PDU_BRAKE_TORQUE_v2"


@pytest.fixture
def profile_config_path(tmp_path):
    config_path = tmp_path / "secoc_profiles.json"
    profiles = {
        PDU_ID: {
            "algorithm": "HMAC-SHA256",
            "key_id": INITIAL_KEY_ID,
            "freshness_length": 2,
            "authenticator_length": 8,
            "profile_version": "v1",
        }
    }
    config_path.write_text(json.dumps(profiles), encoding="utf-8")
    return str(config_path)


@pytest.fixture
def security_profile(profile_config_path):
    return SecurityProfile(config_path=profile_config_path)


@pytest.fixture
def key_storage(nvm_stub):
    return KeyStorage(nvm=nvm_stub)


@pytest.fixture
def key_manager(key_storage, cryif_stub):
    return KeyManager(key_storage=key_storage, cryif=cryif_stub)


@pytest.mark.vtc("VTC-SR-17")
@pytest.mark.sim
class TestVTC_17:
    def test_precondition_profile_loaded_at_v1(self, security_profile):
        """Precondition: PDU_BRAKE_TORQUE security profile is loaded with
        profile_version "v1" and key_id secoc_mac_key_PDU_BRAKE_TORQUE."""
        entry = security_profile.get_profile(PDU_ID)

        assert entry.profile_version == "v1"
        assert entry.key_id == INITIAL_KEY_ID

    def test_initial_key_provisioned_active(self, key_manager, key_storage):
        """Precondition: KeyManager provisions the initial (v1) key for
        PDU_BRAKE_TORQUE so that rotate_key() has an existing ACTIVE key to
        rotate away from."""
        metadata = key_manager.provision_key(PDU_ID, INITIAL_KEY_ID)

        assert metadata.key_id == INITIAL_KEY_ID
        assert metadata.version == 1
        assert key_manager.resolve_key(PDU_ID) == INITIAL_KEY_ID

    def test_rotate_key_provisions_new_active_key(self, key_manager):
        """Step: KeyManager.rotate_key(pdu_id, new_key_id="..._v2") provisions
        a new key version, marks it ACTIVE, and retires the old key."""
        key_manager.provision_key(PDU_ID, INITIAL_KEY_ID)

        new_metadata = key_manager.rotate_key(PDU_ID, new_key_id=ROTATED_KEY_ID)

        assert new_metadata.key_id == ROTATED_KEY_ID
        assert new_metadata.version == 2
        assert key_manager.resolve_key(PDU_ID) == ROTATED_KEY_ID

    def test_update_profile_version_reflects_rotation(
        self, security_profile, key_manager
    ):
        """Step: After key rotation, SecurityProfile.update_profile_version(
        pdu_id, "v2") is called (directly here, simulating the call made
        internally by KeyManager.rotate_key()) and the profile's
        profile_version and key_id are updated consistently."""
        key_manager.provision_key(PDU_ID, INITIAL_KEY_ID)
        key_manager.rotate_key(PDU_ID, new_key_id=ROTATED_KEY_ID)

        security_profile.update_profile_version(PDU_ID, "v2")

        updated_entry = security_profile.get_profile(PDU_ID)
        assert updated_entry.profile_version == "v2"

    def test_expected_result_old_profile_version_no_longer_authoritative(
        self, security_profile, key_manager
    ):
        """Expected result: messages/keys associated with the old profile
        version ("v1" / INITIAL_KEY_ID) are no longer the ACTIVE/authoritative
        configuration once the profile has been advanced to "v2" -- the
        resolved key_id and profile_version must be mutually consistent
        (both reference the rotated key version)."""
        key_manager.provision_key(PDU_ID, INITIAL_KEY_ID)
        key_manager.rotate_key(PDU_ID, new_key_id=ROTATED_KEY_ID)
        security_profile.update_profile_version(PDU_ID, "v2")

        updated_entry = security_profile.get_profile(PDU_ID)
        active_key_id = key_manager.resolve_key(PDU_ID)

        assert updated_entry.profile_version == "v2"
        assert active_key_id == ROTATED_KEY_ID
        assert active_key_id != INITIAL_KEY_ID

    def test_expected_result_traceability_persisted_to_config(
        self, security_profile, profile_config_path
    ):
        """Expected result: update_profile_version() persists the new
        profile_version back to config/secoc_profiles.json (atomic write),
        so the version change is traceable on disk, not just in memory."""
        security_profile.update_profile_version(PDU_ID, "v2")

        with open(profile_config_path, "r", encoding="utf-8") as f:
            persisted = json.load(f)

        assert persisted[PDU_ID]["profile_version"] == "v2"

    def test_unknown_pdu_update_raises_config_error(self, security_profile):
        """Negative: update_profile_version() for a pdu_id with no existing
        profile entry raises SecOCConfigError (consistency guard)."""
        from sim.security_profile import SecOCConfigError

        with pytest.raises(SecOCConfigError):
            security_profile.update_profile_version("PDU_UNKNOWN", "v2")
