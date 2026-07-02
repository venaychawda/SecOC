"""
VTC-SR-20: Disabled confidentiality flag -> declared scope enforced
Objective: Disable confidentiality flag and verify system enforces declared
security scope only
Requirements: SR-20; — (Design constraint — AUTOSAR SecOC provides
authenticity/integrity only, no confidentiality; see HLD_SecOC.md §7)
"""
import dataclasses
import json

import pytest

from sim.security_profile import SecurityProfile, SecurityProfileEntry


PDU_ID = "PDU_BRAKE_TORQUE"


@pytest.fixture
def profile_config_path(tmp_path):
    config_path = tmp_path / "secoc_profiles.json"
    profiles = {
        PDU_ID: {
            "algorithm": "HMAC-SHA256",
            "key_id": "secoc_mac_key_PDU_BRAKE_TORQUE",
            "freshness_length": 2,
            "authenticator_length": 8,
            "profile_version": "v1",
        }
    }
    config_path.write_text(json.dumps(profiles), encoding="utf-8")
    return str(config_path)


@pytest.fixture
def profile_config_path_with_confidentiality_flag(tmp_path):
    config_path = tmp_path / "secoc_profiles_confidentiality.json"
    profiles = {
        PDU_ID: {
            "algorithm": "HMAC-SHA256",
            "key_id": "secoc_mac_key_PDU_BRAKE_TORQUE",
            "freshness_length": 2,
            "authenticator_length": 8,
            "profile_version": "v1",
            "confidentiality_enabled": True,
        }
    }
    config_path.write_text(json.dumps(profiles), encoding="utf-8")
    return str(config_path)


@pytest.mark.vtc("VTC-SR-20")
@pytest.mark.sim
class TestVTC_20:
    def test_precondition_profile_loads_with_authenticity_only_schema(
        self, profile_config_path
    ):
        """Precondition: a security profile with no confidentiality-related
        fields loads successfully -- authenticity/integrity-only is the
        default, valid scope."""
        profile_provider = SecurityProfile(config_path=profile_config_path)
        entry = profile_provider.get_profile(PDU_ID)

        assert entry is not None

    def test_security_profile_entry_schema_has_no_encryption_fields(self):
        """Step: inspect the SecurityProfileEntry dataclass fields and
        verify no field name contains "encrypt" or "confidential" -- the
        profile schema declares authenticity/integrity scope only, with no
        confidentiality-enable flag exposed."""
        field_names = [f.name for f in dataclasses.fields(SecurityProfileEntry)]

        for name in field_names:
            assert "encrypt" not in name.lower()
            assert "confidential" not in name.lower()

    def test_get_profile_does_not_expose_encryption_or_cipher_fields(
        self, profile_config_path
    ):
        """Step: SecurityProfile.get_profile(pdu_id) returns an entry whose
        attributes contain no encryption-key, cipher, or confidentiality
        identifiers for the SecOC-secured PDU path."""
        profile_provider = SecurityProfile(config_path=profile_config_path)
        entry = profile_provider.get_profile(PDU_ID)

        entry_dict = dataclasses.asdict(entry)
        for key in entry_dict:
            assert "encrypt" not in key.lower()
            assert "cipher" not in key.lower()
            assert "confidential" not in key.lower()

    def test_confidentiality_enabled_flag_in_config_raises_config_error(
        self, profile_config_path_with_confidentiality_flag
    ):
        """Step: a JSON profile entry that sets confidentiality_enabled=True
        is rejected at load time -- enforcing that confidentiality is out of
        SecOC's declared scope (SR-20)."""
        from sim.security_profile import SecurityProfileConfigError

        with pytest.raises(SecurityProfileConfigError):
            SecurityProfile(config_path=profile_config_path_with_confidentiality_flag)

    def test_expected_result_cryif_encryption_apis_not_used_for_secured_pdu_path(
        self, cryif_stub
    ):
        """Expected result: the Crypto Abstraction Layer exposes
        aes_gcm_encrypt/aes_gcm_decrypt (used elsewhere, e.g. for non-SecOC
        confidentiality use cases), but the SecOC-secured PDU authentication
        path (security_profile / authenticator) never invokes them --
        documented here by asserting these APIs exist on CryIf yet are not
        part of the SecurityProfileEntry contract (no key/cipher reference
        that would route a secured PDU through them)."""
        assert hasattr(cryif_stub, "aes_gcm_encrypt")
        assert hasattr(cryif_stub, "aes_gcm_decrypt")

        field_names = [f.name for f in dataclasses.fields(SecurityProfileEntry)]
        assert not any("aes" in name.lower() for name in field_names)
        assert not any("gcm" in name.lower() for name in field_names)

    def test_expected_result_declared_scope_is_authenticity_and_integrity_only(
        self, profile_config_path
    ):
        """Expected result: the loaded profile's fields are exactly the
        authenticity/integrity/freshness/versioning set defined by SR-11/
        SR-17/SR-21 -- algorithm, key_id, freshness_length,
        authenticator_length, profile_version, plus the optional
        tfv_length/tmac_length Classic CAN truncation lengths (SR-21) --
        with nothing additional that would imply a confidentiality scope."""
        profile_provider = SecurityProfile(config_path=profile_config_path)
        entry = profile_provider.get_profile(PDU_ID)

        field_names = {f.name for f in dataclasses.fields(entry)}
        assert field_names == {
            "algorithm",
            "key_id",
            "freshness_length",
            "authenticator_length",
            "profile_version",
            "tfv_length",
            "tmac_length",
        }
