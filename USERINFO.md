# SecOC Live Monitor — User Guide

This guide explains how to use `dashboard/SecOC_Monitor.html` (the **Live
Monitor**) to exercise the SecOC simulation and visually validate secure
communication — legitimate traffic being accepted, and forged/tampered/replayed
traffic being rejected. It also documents every panel and control in the GUI.

The Live Monitor is laid out as a **Sender ECU → Attack Simulation →
Receiver ECU** pipeline: you build and transmit a Secured PDU on the left,
optionally attack it in the middle, and decode/verify it on the right — the
same way a real sending ECU, an attacker on the bus, and a real receiving
ECU relate to each other.

For the no-backend `dashboard/index.html` **Proof of Concept**, see
[PoC dashboard](#poc-dashboard-indexhtml) at the end — it has **not** been
updated to this layout; it keeps the original 4-panel design (see that
section for why).

---

## 1. Starting the Live Monitor

```bash
# Terminal 1 — backend (port 8000)
uvicorn api.main:app --reload --port 8000

# Terminal 2 — dashboard (port 3000)
python -m http.server 3000 --directory dashboard
```

Then open **http://localhost:3000/SecOC_Monitor.html**.

The top banner confirms the backend requirement. The connection status pill
next to the title reads **LIVE** (green) once the WebSocket to
`ws://localhost:8000/ws/events` is connected, or **DISCONNECTED** (with
automatic 2s retry) if the backend isn't reachable.

Every REST call the dashboard makes goes to `http://localhost:8000`. If a
call fails (backend down, 4xx/5xx), the failure is shown inline — panels
never throw silently.

---

## 2. What "validating secure communication" means here

SecOC secures a **Secured I-PDU**. The trailer layout depends on which
**transport** is selected in the Sender ECU panel:

- **CAN FD** (default) — `authentic_pdu || freshness || MAC`, where
  `freshness` and `MAC` are truncated to the PDU's configured
  `freshness_length`/`authenticator_length` bytes (variable-length payload,
  up to the CAN FD 64-byte frame budget).
- **Classic CAN** (SR-21 / SW-SecOC-11) — a fixed 8-byte frame:
  `authentic_pdu(4 bytes, zero-padded) || TFV || TMAC`, where **TFV**
  (Truncated Freshness Value, taken from the low-order bytes of the
  freshness counter) and **TMAC** (Truncated Authenticator, taken from the
  high-order bytes of the computed MAC) are configured per PDU in
  `config/secoc_profiles.json` and must sum to exactly 4 bytes. You may
  supply 0-4 bytes of real payload; anything shorter is right-padded with
  zero bytes on transmit (padding is not stripped on decode).

"Validating secure communication" means using the dashboard to prove three
things, live, against the real `sim/` implementation, in **either**
transport mode:

1. A legitimate transmit → receive round trip is **accepted**.
2. A tampered, forged, or replayed frame is **rejected**, and the rejection
   is logged as a DEM security event.
3. Repeated rejections drive the ECU into **SECURITY_VIOLATION_LOCKOUT**
   (a safe state), and `Reset ECU` recovers it.

---

## 3. Panel Reference

### ECU State Monitor

Shows the live security/lifecycle state of the simulated ECU, polled via
`GET /telemetry` and pushed in real time over the WebSocket whenever a DEM
event or ECU state change occurs (the panel border flashes on update).

| Element | Meaning |
|---|---|
| **State badge** (top) | Current `ecu_state`: `NORMAL_OPERATION` (green), `SECURITY_VIOLATION_LOCKOUT` (red), or `BOOT_BLOCKED` (red) — see `sim/ecu_state.py`. |
| **Locked Out** | `true`/`false` — whether `SecurityPolicyEngine` has tripped the SR-14 lockout (5 consecutive AUTH-category failures by default, `config.MAX_AUTH_FAILURES`). |
| **Secure Boot** | `VERIFIED`/`FAILED` — result of the `sim/secure_boot.py` integrity check (SR-19). |
| **CAN Bus** | `RUNNING`/`STOPPED` — whether the simulated `CanBus` singleton is active. |
| **Queue Depth** | Number of frames currently queued on the CAN bus. |
| **DEM Events by Severity** | Live bar chart of `INFO`/`WARNING`/`CRITICAL` DEM event counts, with a running total. |
| **Reset ECU** button | `POST /ecu/reset` — clears lockout/fault state and returns the ECU to `NORMAL_OPERATION`. Use this after intentionally driving the ECU into lockout (see §4.4). |
| **Refresh Telemetry** button | Manually re-pulls `GET /telemetry` (state also updates automatically via WebSocket). |

### Sender ECU — Build & Transmit (left)

Builds and transmits a Secured I-PDU for a chosen PDU and transport.

| Element | Meaning |
|---|---|
| **Transport** toggle | `CAN FD` / `CLASSIC CAN` pill switch. Selects which wire-format scheme `POST /secoc/transmit` uses (see §2). Also determines what the Receiver ECU panel expects when decoding, and what the Attack Simulation panel targets. |
| **PDU** dropdown | Which logical PDU to operate on. Populated from `GET /profiles` (falls back to `PDU_BRAKE_TORQUE`, `PDU_0x100`, `PDU_0x200` if the backend is unreachable when the page loads). Each PDU has its own independent freshness counter and MAC key. |
| **Authentic I-PDU (hex)** field | The payload bytes to secure, as hex (default `01020304`). Under `CLASSIC CAN`, the field is capped at 8 hex chars (4 bytes) and a hint below it explains the 0-4 byte / zero-pad rule; under `CAN FD` it accepts any length. |
| **Secured PDU byte breakdown** | After a Transmit, shows the resulting Secured I-PDU split into its **Authentic PDU** / **TFV or Freshness** / **TMAC or MAC** segments (labels and lengths adapt to the selected transport, using `tfv_length`/`tmac_length` or `freshness_length`/`authenticator_length` from `GET /profiles`). |
| **Activity line / Result banner** | Green = built successfully (shows `secured_pdu_hex`), amber = request error (e.g. payload too long for Classic CAN). |
| **Transmit** button | `POST /secoc/transmit` (SW-SecOC-01 / SW-SecOC-11) — builds the Secured I-PDU and remembers it as "last transmitted" for this PDU, ready for the Receiver ECU panel or an attack. |

### Attack Simulation (middle)

Attacks always target whatever PDU/transport is currently selected in
Sender ECU (shown at the top of this panel), and each attack call both
tampers/forges/replays **and** submits the result for verification in one
step — the outcome is shown here and mirrored into the Receiver ECU panel.

| Element | Meaning |
|---|---|
| **MITM Tamper** button | `POST /attack/mitm` — transmits a fresh Secured I-PDU, flips a bit in transit (`sim/mitm_attack.py`), and submits the tampered frame for verification. Demonstrates SR-02 (integrity tamper detection) — expect **rejected**. |
| **Replay: Capture** button | `POST /attack/replay/capture` — captures the most recently observed frame on the bus for this PDU (`sim/replay_attack.py`). |
| **Replay: Replay** button | `POST /attack/replay/replay` — re-injects the captured frame and submits it for verification. If newer traffic has since been accepted, the captured frame is now stale and freshness rejects it. Demonstrates SR-03 (replay rejection) — expect **rejected** once a fresher frame has been sent. |
| **Forge Mode** dropdown + **Forge & Inject** button | `POST /attack/forge` — generates a forged Secured I-PDU via `sim/fuzzing_engine.py` and submits it. Modes: `INVALID_MAC` (correct structure, wrong MAC), `WRONG_FRESHNESS` (stale/out-of-window counter), `MALFORMED_STRUCTURE` (too short to contain the freshness+MAC trailer). Demonstrates SR-01/SR-04 — always **rejected**. Note: forging currently always uses the CAN FD trailer lengths regardless of the Sender's transport toggle. |
| **CAN Send Raw** button | `POST /can/send` — queues arbitrary raw bytes directly onto the simulated CAN bus, bypassing SecOC entirely. Useful for bus-level experimentation; does not itself invoke verification. |

### Receiver ECU — Verify & Decode (right)

Decodes and verifies the last Secured I-PDU seen (whether from a legitimate
Sender transmission or an attack), using the transport currently selected
in Sender ECU (shown at the top of this panel — a receiver must know which
scheme it's listening on, exactly as the Sender must know which it's
sending on).

| Element | Meaning |
|---|---|
| **Interpreting frames as** | Read-only, mirrors the Sender ECU transport toggle. |
| **Recovered Payload** | The decoded `authentic_pdu` bytes on acceptance (4 zero-padded bytes for Classic CAN); `--` if nothing decoded yet or the last frame was rejected. |
| **Activity line / Result banner** | Green `✓ ACCEPTED` with the recovered payload, or red `✗ REJECTED` with the current `ecu_state`/`locked_out`. |
| **Receive Last** button | `POST /secoc/receive` (SW-SecOC-02..06 / SW-SecOC-11) — feeds the last-transmitted Secured I-PDU through verification. On a clean round trip (no attack in between) this is **accepted**. |

### Event Log (DEM)

A live, timestamped feed of every DEM (Diagnostic Event Manager) security
event raised by `sim/dem.py`, newest first. Populated on load via
`GET /events?limit=50` and appended to in real time over the WebSocket.

Each row shows: timestamp, severity (`INFO`/`WARNING`/`CRITICAL`, colour
coded), the `event_id` (e.g. `SECOC_AUTH_FAIL`, `SAFE_STATE_ENTERED`,
`BOOT_INTEGRITY_FAIL`, `KEY_ROTATED`), a human description, and the
originating requirement ID (`swr_ref`, e.g. `SR-01`) when set.

---

## 4. Walkthroughs

### 4.1 Happy path — legitimate message is accepted (CAN FD)

1. Sender ECU: leave **Transport** = `CAN FD`, **PDU** = `PDU_BRAKE_TORQUE`,
   **Authentic I-PDU** = `01020304`.
2. Click **Transmit** → result banner turns green, shows `secured_pdu_hex`,
   and the Authentic PDU / Freshness / MAC breakdown appears.
3. Receiver ECU: click **Receive Last** → result banner turns green:
   `✓ ACCEPTED`, recovered payload = `01020304`.
4. Event Log shows no new CRITICAL events for this exchange.

### 4.2 Happy path — Classic CAN 8-byte frame

1. Sender ECU: click the **CLASSIC CAN** toggle. The payload field caps at
   8 hex chars and the hint explains the 0-4 byte rule.
2. Set **Authentic I-PDU** = `0102` (2 bytes — will be zero-padded to 4).
3. Click **Transmit** → the byte breakdown now shows **TFV**/**TMAC**
   segments instead of Freshness/MAC, and `secured_pdu_hex` is exactly 8
   bytes (16 hex chars).
4. Receiver ECU: click **Receive Last** → `✓ ACCEPTED`, recovered payload
   = `01020000` (the zero-padding is visible and not stripped).

### 4.3 Integrity attack — tampered payload is rejected

1. Attack Simulation panel (any transport): click **MITM Tamper**.
2. Result banner (here and mirrored in Receiver ECU) turns red:
   `✗ REJECTED`.
3. Event Log logs a `SECOC_AUTH_FAIL` CRITICAL event (SR-02).

### 4.4 Replay attack — stale frame is rejected

1. Sender ECU: **Transmit**; Receiver ECU: **Receive Last** (accepts,
   advances freshness).
2. Attack Simulation: click **Replay: Capture** (captures that frame).
3. Sender ECU: **Transmit** again; Receiver ECU: **Receive Last** (a
   *newer* frame is now accepted, making the captured one stale).
4. Attack Simulation: click **Replay: Replay** → red `✗ REJECTED`
   (freshness/replay rejection, SR-03).

### 4.5 Forging attack → safe-state lockout → recovery

1. Attack Simulation: set **Forge Mode** = `INVALID_MAC`, click
   **Forge & Inject** repeatedly (5 times by default —
   `config.MAX_AUTH_FAILURES`).
2. Watch ECU State Monitor: **State badge** flips to
   `SECURITY_VIOLATION_LOCKOUT`, **Locked Out** turns `true`, and Event Log
   logs a CRITICAL `SAFE_STATE_ENTERED` event (SR-14).
3. Any further Transmit/Receive on any PDU now reports the locked-out
   `ecu_state` in its result banner.
4. Click **Reset ECU** in ECU State Monitor → state returns to
   `NORMAL_OPERATION`, **Locked Out** turns `false`, secure communication
   resumes.

> The formal VTC-SR-01..21 suite is no longer runnable from this GUI (the
> Test Scenario Runner panel was removed). It still exists and passes via
> `pytest tests/ --runslow` and the `GET /test/scenarios` /
> `POST /test/{vtc_id}/run` / `GET /test/{vtc_id}/result` API endpoints —
> see §5 below if you want to drive it via `curl` or a script instead.

---

## 5. REST API quick reference

All endpoints are served at `http://localhost:8000` (see `api/routers/`).

| Method & Path | Purpose |
|---|---|
| `GET /` | Health check + current ECU status. |
| `GET /ecu/state` | Current `ecu_state`/`locked_out`. |
| `POST /ecu/reset` | Reset ECU to `NORMAL_OPERATION`. |
| `GET /events?limit=N` | Most recent DEM events. |
| `GET /telemetry` | Combined ECU state, DEM summary, CAN bus, profiler stats. |
| `GET /profiles`, `GET /profiles/{pdu_id}` | Configured security profiles, including `tfv_length`/`tmac_length` (SR-21). |
| `POST /profiles/{pdu_id}/version` | Update a profile's version (SR-17). |
| `GET /keys/{pdu_id}` | Key metadata (never raw key bytes). |
| `POST /keys/{pdu_id}/provision` | Provision the initial key for a PDU. |
| `POST /keys/{pdu_id}/rotate` | Rotate to a new key. |
| `POST /secoc/transmit` | Build a Secured I-PDU (`{pdu_id, payload_hex, transport}`). `transport` is `"CAN_FD"` (default) or `"CLASSIC_CAN"`. |
| `POST /secoc/receive` / `/secoc/validate` | Verify a Secured I-PDU (`{pdu_id, secured_pdu_hex, transport}`). |
| `POST /can/send` | Queue a raw frame on the CAN bus. |
| `POST /attack/replay/capture` | Capture the last frame for a PDU. |
| `POST /attack/replay/replay` | Re-inject and verify the captured frame (`{pdu_id, transport}`). |
| `POST /attack/mitm` | Transmit, bit-flip in transit, and verify (`{pdu_id, payload_hex, transport}`). |
| `POST /attack/forge` | Generate and verify a forged frame (`{pdu_id, mode}`) — always CAN FD lengths. |
| `GET /test/scenarios` | List all VTC IDs (not surfaced in the GUI; still usable directly). |
| `POST /test/{vtc_id}/run` | Run a VTC scenario. |
| `GET /test/{vtc_id}/result` | Last recorded result for a VTC. |
| `WS /ws/events` | Live DEM event + ECU state stream. |

`transport` values: `"CLASSIC_CAN"` or `"CAN_FD"`; an invalid value returns
`400`. An `authentic_pdu`/`payload_hex` longer than 4 bytes with
`transport="CLASSIC_CAN"` also returns `400`.

---

## 6. PoC dashboard (`index.html`)

`dashboard/index.html` still uses the **original 4-panel layout**
(ECU State Monitor, Primary Operation Console, Test Scenario Runner, Event
Log) and requires **no backend** — it's a self-contained HTML+JS file with
a scripted state machine simulating the happy path and a negative
scenario, suitable for a walkthrough with no environment setup.
Double-click it to open in any browser. It has **not** been updated to the
Sender/Attack/Receiver layout or the Classic CAN transport mode described
above — that was scoped to the Live Monitor only. Its data is
pre-scripted/animated, not live — use the Live Monitor (this guide, §1–5)
for real validation against the actual `sim/` implementation.
