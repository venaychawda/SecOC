"""Security-profile and key-management endpoints (SR-08, SR-09, SR-10, SR-17)."""
from dataclasses import asdict

from fastapi import APIRouter, HTTPException

from api.events import broadcast_updates
from api.models import ProfileVersionRequest, ProvisionKeyRequest, RotateKeyRequest
from api.state import state
from sim.dem import Severity
from sim.security_profile import SecOCConfigError

router = APIRouter(tags=["auth"])


@router.get("/profiles")
async def list_profiles() -> dict:
    """Return all configured security profiles, keyed by pdu_id."""
    return {pdu_id: asdict(entry) for pdu_id, entry in state.profile_provider._profiles.items()}


@router.get("/profiles/{pdu_id}")
async def get_profile(pdu_id: str) -> dict:
    """Return the security profile for a single pdu_id."""
    try:
        return asdict(state.profile_provider.get_profile(pdu_id))
    except SecOCConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/profiles/{pdu_id}/version")
async def update_profile_version(pdu_id: str, body: ProfileVersionRequest) -> dict:
    """Update the profile_version for pdu_id (SR-17)."""
    try:
        state.profile_provider.update_profile_version(pdu_id, body.profile_version)
    except SecOCConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await broadcast_updates()
    return asdict(state.profile_provider.get_profile(pdu_id))


@router.get("/keys/{pdu_id}")
async def get_key_metadata(pdu_id: str) -> dict:
    """Return key metadata (never raw key bytes) for pdu_id (SR-08)."""
    metadata = state.key_storage.get_key_metadata(pdu_id)
    if metadata is None:
        raise HTTPException(status_code=404, detail=f"no key provisioned for pdu_id '{pdu_id}'")
    return {
        "pdu_id": metadata.pdu_id,
        "key_id": metadata.key_id,
        "version": metadata.version,
        "lifecycle_state": metadata.lifecycle_state.value,
    }


@router.post("/keys/{pdu_id}/provision")
async def provision_key(pdu_id: str, body: ProvisionKeyRequest) -> dict:
    """Provision the initial ACTIVE key for pdu_id."""
    metadata = state.key_manager.provision_key(pdu_id, body.key_id)
    await broadcast_updates()
    return {
        "pdu_id": metadata.pdu_id,
        "key_id": metadata.key_id,
        "version": metadata.version,
        "lifecycle_state": metadata.lifecycle_state.value,
    }


@router.post("/keys/{pdu_id}/rotate")
async def rotate_key(pdu_id: str, body: RotateKeyRequest) -> dict:
    """Rotate to a new ACTIVE key for pdu_id (SR-17)."""
    try:
        metadata = state.key_manager.rotate_key(pdu_id, new_key_id=body.new_key_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    state.event_logger.log(Severity.INFO, "KEY_ROTATED", swr_ref="SR-17")
    await broadcast_updates()
    return {
        "pdu_id": metadata.pdu_id,
        "key_id": metadata.key_id,
        "version": metadata.version,
        "lifecycle_state": metadata.lifecycle_state.value,
    }
