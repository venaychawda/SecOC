"""Primary SecOC operation, CAN transport, and attack-injection endpoints."""
import time

from fastapi import APIRouter, HTTPException

from api.events import broadcast_updates
from api.models import (
    CanSendRequest,
    ForgeRequest,
    MitmRequest,
    ReceiveRequest,
    ReceiveResponse,
    ReplayCaptureRequest,
    ReplayReplayRequest,
    TransmitRequest,
    TransmitResponse,
)
from api.state import state
from sim.fuzzing_engine import ForgeMode, FuzzingEngine
from sim.message_frame import MessageFrame
from sim.mitm_attack import MitmAttack
from sim.secoc import SecOCTransportError
from sim.security_profile import SecOCConfigError, Transport

router = APIRouter(tags=["secoc"])


def _parse_transport(value: str) -> Transport:
    try:
        return Transport(value)
    except ValueError as exc:
        valid = ", ".join(t.value for t in Transport)
        raise HTTPException(status_code=400, detail=f"transport must be one of: {valid}") from exc


@router.post("/secoc/transmit", response_model=TransmitResponse)
async def transmit_secured(body: TransmitRequest) -> TransmitResponse:
    """Build a Secured I-PDU for transmission (SW-SecOC-01, SR-21)."""
    try:
        authentic_pdu = bytes.fromhex(body.payload_hex)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="payload_hex is not valid hex") from exc

    transport = _parse_transport(body.transport)
    try:
        secured_pdu = state.secoc.transmit_secured(body.pdu_id, authentic_pdu, transport=transport)
    except SecOCConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SecOCTransportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await broadcast_updates()
    return TransmitResponse(pdu_id=body.pdu_id, secured_pdu_hex=secured_pdu.hex())


@router.post("/secoc/receive", response_model=ReceiveResponse)
async def receive_secured(body: ReceiveRequest) -> ReceiveResponse:
    """Validate and process a received Secured I-PDU (SW-SecOC-02..06, SR-21)."""
    try:
        secured_pdu = bytes.fromhex(body.secured_pdu_hex)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="secured_pdu_hex is not valid hex") from exc

    transport = _parse_transport(body.transport)
    try:
        authentic_pdu = state.secoc.receive_secured(body.pdu_id, secured_pdu, transport=transport)
    except SecOCConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    status = state.get_status()
    await broadcast_updates()
    return ReceiveResponse(
        pdu_id=body.pdu_id,
        accepted=authentic_pdu is not None,
        authentic_pdu_hex=authentic_pdu.hex() if authentic_pdu is not None else None,
        ecu_state=status["ecu_state"],
        locked_out=status["locked_out"],
    )


@router.post("/secoc/validate", response_model=ReceiveResponse)
async def validate_secured(body: ReceiveRequest) -> ReceiveResponse:
    """Validate a Secured I-PDU's MAC and freshness (alias of /secoc/receive).

    AUTOSAR's VerifySecuredI-PDU performs validation and, on success,
    commits the freshness state -- there is no separate "dry run" path.
    """
    return await receive_secured(body)


@router.post("/can/send")
async def can_send(body: CanSendRequest) -> dict:
    """Publish a raw frame onto the simulated CAN bus."""
    try:
        data = bytes.fromhex(body.data_hex)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="data_hex is not valid hex") from exc

    state.injector.inject(body.pdu_id, data)
    await broadcast_updates()
    return {"pdu_id": body.pdu_id, "queued": True}


@router.post("/attack/replay/capture")
async def replay_capture(body: ReplayCaptureRequest) -> dict:
    """Capture the most recently observed frame for pdu_id (SR-03)."""
    captured = state.replay_attack.capture(body.pdu_id)
    if captured.raw_bytes is None:
        raise HTTPException(status_code=404, detail=f"no frame observed yet for pdu_id '{body.pdu_id}'")
    return {"pdu_id": body.pdu_id, "captured_hex": captured.raw_bytes.hex()}


@router.post("/attack/replay/replay", response_model=ReceiveResponse)
async def replay_replay(body: ReplayReplayRequest) -> ReceiveResponse:
    """Re-inject the captured frame and attempt to process it (replay attack)."""
    state.replay_attack.replay(body.pdu_id)
    frame = state.can_bus.consume()
    if frame is None:
        raise HTTPException(status_code=404, detail=f"no captured frame to replay for pdu_id '{body.pdu_id}'")

    _, secured_pdu = frame
    return await receive_secured(
        ReceiveRequest(pdu_id=body.pdu_id, secured_pdu_hex=secured_pdu.hex(), transport=body.transport)
    )


@router.post("/attack/mitm", response_model=ReceiveResponse)
async def mitm_tamper(body: MitmRequest) -> ReceiveResponse:
    """Transmit a fresh Secured I-PDU, tamper it in transit, and process it (SR-02)."""
    try:
        authentic_pdu = bytes.fromhex(body.payload_hex)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="payload_hex is not valid hex") from exc

    transport = _parse_transport(body.transport)
    try:
        secured_pdu = state.secoc.transmit_secured(body.pdu_id, authentic_pdu, transport=transport)
    except SecOCConfigError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except SecOCTransportError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    mitm = MitmAttack(can_bus=state.can_bus, injector=state.injector)
    frame = MessageFrame(pdu_id=body.pdu_id, data=secured_pdu, timestamp=time.time())
    tampered = mitm.intercept(frame)

    return await receive_secured(
        ReceiveRequest(
            pdu_id=body.pdu_id,
            secured_pdu_hex=tampered.tampered_raw_bytes.hex(),
            transport=body.transport,
        )
    )


@router.post("/attack/forge", response_model=ReceiveResponse)
async def forge_inject(body: ForgeRequest) -> ReceiveResponse:
    """Generate and process a fuzzer-forged Secured I-PDU (SR-01, SR-04)."""
    try:
        mode = ForgeMode(body.mode)
    except ValueError as exc:
        valid = ", ".join(m.value for m in ForgeMode)
        raise HTTPException(status_code=400, detail=f"mode must be one of: {valid}") from exc

    fuzzer = FuzzingEngine(can_bus=state.can_bus, injector=state.injector)
    forged = fuzzer.generate_forged_pdu(body.pdu_id, mode)

    return await receive_secured(ReceiveRequest(pdu_id=body.pdu_id, secured_pdu_hex=forged.hex()))
