"""
VTC-SR-08: Key extraction from application layer denied
Objective: Attempt key extraction from application layer and verify access denial
Requirements: SR-08; SW-SecOC-10
"""
import pytest

from sim.key_manager import KeyManager
from sim.key_storage import KeyStorage

PDU_ID = "PDU_0x100"
KEY_ID = "secoc_mac_key_PDU_0x100"


@pytest.fixture
def key_storage(nvm_stub, cryif_stub):
    ks = KeyStorage(nvm=nvm_stub)
    KeyManager(key_storage=ks, cryif=cryif_stub).provision_key(PDU_ID, KEY_ID)
    return ks


@pytest.fixture
def key_manager(key_storage, cryif_stub):
    return KeyManager(key_storage=key_storage, cryif=cryif_stub)


@pytest.mark.vtc("VTC-SR-08")
@pytest.mark.sim
class TestVTC_08:
    def test_precondition_pdu_has_provisioned_key(self, key_storage):
        """Precondition: the PDU has a provisioned, ACTIVE key in key_storage."""
        metadata = key_storage.get_key_metadata(PDU_ID)

        assert metadata is not None
        assert metadata.key_id == KEY_ID
        assert metadata.lifecycle_state.value == "ACTIVE"

    def test_resolve_key_returns_only_logical_key_id(self, key_manager):
        """Action: application layer calls KeyManager.resolve_key(pdu_id)."""
        resolved = key_manager.resolve_key(PDU_ID)

        assert isinstance(resolved, str)
        assert resolved == KEY_ID

    def test_expected_result_key_metadata_has_no_raw_key_fields(self, key_storage):
        """Expected result: KeyStorage metadata never contains raw key bytes
        under any plausible field name (SW-SecOC-10, SR-08)."""
        metadata = key_storage.get_key_metadata(PDU_ID)

        assert metadata is not None
        metadata_dict = vars(metadata)

        forbidden_fields = {"key_bytes", "raw_key", "secret", "key_material", "private_key"}
        assert forbidden_fields.isdisjoint(metadata_dict.keys())

    def test_expected_result_no_public_api_returns_raw_key_material(
        self, hsm_stub, cryif_stub
    ):
        """Expected result: there is no public API on hsm_stub/cryif_stub that
        returns raw key material to the application layer."""
        # No public "get raw key" style accessor exists on the HSM.
        assert getattr(hsm_stub, "get_raw_key", None) is None
        assert getattr(hsm_stub, "export_key", None) is None
        assert getattr(hsm_stub, "get_key_bytes", None) is None

        # Same for CryIf — it must not expose a raw-key passthrough either.
        assert getattr(cryif_stub, "get_raw_key", None) is None
        assert getattr(cryif_stub, "export_key", None) is None

    def test_expected_result_key_extraction_attempt_via_public_api_denied(
        self, key_manager, key_storage
    ):
        """Expected result: an application-layer attempt to "extract" the key
        for a PDU yields only a logical key_id / metadata, never raw bytes —
        the only way to reach raw key bytes is the private `hsm._key_store`,
        which is not part of the public contract of any module."""
        resolved_key_id = key_manager.resolve_key(PDU_ID)
        metadata = key_storage.get_key_metadata(PDU_ID)

        # Both results are strings/metadata objects, never bytes.
        assert isinstance(resolved_key_id, str)
        assert not isinstance(resolved_key_id, (bytes, bytearray))
        assert not isinstance(metadata.key_id, (bytes, bytearray))
