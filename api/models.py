"""Pydantic request/response models for the SecOC FastAPI backend."""
from pydantic import BaseModel


class TransmitRequest(BaseModel):
    """Request to build a Secured I-PDU for transmission."""

    pdu_id: str
    payload_hex: str
    transport: str = "CAN_FD"


class TransmitResponse(BaseModel):
    """Result of building a Secured I-PDU."""

    pdu_id: str
    secured_pdu_hex: str


class ReceiveRequest(BaseModel):
    """Request to validate/process a received Secured I-PDU."""

    pdu_id: str
    secured_pdu_hex: str
    transport: str = "CAN_FD"


class ReceiveResponse(BaseModel):
    """Result of validating/processing a Secured I-PDU."""

    pdu_id: str
    accepted: bool
    authentic_pdu_hex: str | None = None
    ecu_state: str
    locked_out: bool


class CanSendRequest(BaseModel):
    """Request to publish a raw frame onto the simulated CAN bus."""

    pdu_id: str
    data_hex: str


class ReplayCaptureRequest(BaseModel):
    """Request to capture the most recently observed frame for a PDU."""

    pdu_id: str


class ReplayReplayRequest(BaseModel):
    """Request to replay a previously captured frame."""

    pdu_id: str
    transport: str = "CAN_FD"


class MitmRequest(BaseModel):
    """Request to run a MITM tamper scenario against a fresh transmission."""

    pdu_id: str
    payload_hex: str = "01020304"
    transport: str = "CAN_FD"


class ForgeRequest(BaseModel):
    """Request to inject a fuzzer-generated forged Secured I-PDU."""

    pdu_id: str
    mode: str = "INVALID_MAC"


class ProvisionKeyRequest(BaseModel):
    """Request to provision the initial key for a PDU."""

    key_id: str


class RotateKeyRequest(BaseModel):
    """Request to rotate the active key for a PDU."""

    new_key_id: str


class ProfileVersionRequest(BaseModel):
    """Request to update a security profile's version string."""

    profile_version: str
