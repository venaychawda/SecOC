# ASPICE SWE.1 — Software Requirements Analysis

**Document ID:** ASPICE-SWE1-SecOC-001
**Version:** 1.0
**Date:** 2026-06-11
**Author:** TBD
**ASPICE Process:** SWE.1 (Software Requirements Analysis)
**Project:** SecOC — AUTOSAR Classic Secure Onboard Communication Simulation, Phase 1

| Version | Date | Author | Change |
|---|---|---|---|
| 1.0 | 2026-06-11 | TBD | Initial release — Phase 1, Step 7 (post-qualification) |

---

## 1. Purpose & Scope

This document summarizes the requirements analysis performed for the SecOC simulation
project and references the authoritative requirement artifacts in `requirements/`. It
provides:

- A traceability summary from Customer Requirements (CR) through System Requirements
  (SR), Software Requirements (SWR, `SecOC-*`/`SW-SecOC-*`), and Verification Test Cases
  (VTC-SR-01..20).
- A gap analysis identifying requirements with no derived software requirement, and
  requirements that cannot be fully validated in simulation (hardware-only).

The authoritative, machine-traceable record is `requirements/traceability_matrix.md`
(Document ID `TRACE-SecOC-001`). This document is a qualitative summary for ASPICE
SWE.1 evidence purposes and does not duplicate the full matrix.

---

## 2. Source Artifacts

| File | Content | Row Count |
|---|---|---|
| `requirements/CustomerRequirements.txt` | CR-01..CR-08 | 8 |
| `requirements/SystemRequirements.txt` | SR-01..SR-20, each mapped to one VTC-SR-NN | 20 |
| `requirements/SoftwareRequirements.txt` | SW-SecOC-01..SW-SecOC-10, each mapped to 1-2 SRs | 10 |
| `requirements/TestPlan.txt` | VTC-SR-01..VTC-SR-20 verification steps | 20 |
| `requirements/traceability_matrix.md` | Bidirectional CR → SR → SWR → Module → VTC matrix | 20 SR rows |

---

## 3. Requirement Set Summary

### 3.1 Customer Requirements (CR-01..CR-08)

| CR-ID | Summary |
|---|---|
| CR-01 | Secure airbag deployment signals (freshness + MAC, receiver verification) |
| CR-02 | Secure brake-torque request communication; reject and lock invalid messages |
| CR-03 | Secure sensor (camera/radar/status) messages; integrity + freshness gating |
| CR-04 | Prevent replay attacks via freshness mismatch detection, with security event lock |
| CR-05 | Secure ECU reprogramming trigger messages before UDS flashing |
| CR-06 | Support secure key rotation without disrupting vehicle operation |
| CR-07 | Restore secure communication after ECU reset via freshness resynchronization |
| CR-08 | Multi-ECU secure CAN communication; per-message freshness + MAC |

### 3.2 System Requirements (SR-01..SR-20)

All 20 system requirements are defined in `requirements/SystemRequirements.txt`, each
pre-mapped 1:1 to a verification test case `VTC-SR-NN`. Representative groupings:

| Theme | SR-IDs |
|---|---|
| Authenticity / integrity / forged-frame handling | SR-01, SR-02, SR-07 |
| Freshness, replay, resynchronization | SR-03, SR-04, SR-05 |
| MAC generation/verification via CSM | SR-06, SR-07 |
| Key management (provisioning, rotation, HSM-only access) | SR-08, SR-09 |
| Configurability (algorithm agility, security profiles) | SR-10, SR-11, SR-17 |
| Performance (WCET, resource overhead) | SR-12, SR-15 |
| Diagnostics & fault escalation | SR-13, SR-14 |
| Transport (CAN / CAN FD) | SR-16 |
| CI / process | SR-18 |
| Boot integrity | SR-19 |
| Confidentiality scope declaration | SR-20 |

### 3.3 Software Requirements (SW-SecOC-01..10)

All 10 software requirements are defined in `requirements/SoftwareRequirements.txt`,
each mapped to one or two SRs:

| SWR-ID | Summary | Mapped SR(s) |
|---|---|---|
| SW-SecOC-01 | `SendSecuredI-PDU` API — attach authenticator + freshness | SR-06, SR-03 |
| SW-SecOC-02 | `VerifySecuredI-PDU` API — validate authenticator + freshness | SR-07, SR-04 |
| SW-SecOC-03 | Freshness module — monotonic counter per message ID | SR-03, SR-04 |
| SW-SecOC-04 | SecOC ↔ CSM interaction for MAC gen/verify | SR-06, SR-07 |
| SW-SecOC-05 | Store last valid freshness per peer ECU in secure RAM | SR-04, SR-05 |
| SW-SecOC-06 | Reject message + trigger DEM event on auth failure | SR-13 |
| SW-SecOC-07 | Configurable security profile per PDU via JSON config | SR-10, SR-17 |
| SW-SecOC-08 | Deterministic execution time for MAC operations | SR-12 |
| SW-SecOC-09 | Resynchronization service after restart/comm loss | SR-05 |
| SW-SecOC-10 | Keys accessed only via Crypto Abstraction Layer | SR-08, SR-09 |

---

## 4. Traceability Summary

Per `requirements/traceability_matrix.md` v0.2:

| Total SRs | Verified (✅) | In Progress | Pending | Blocked |
|---|---|---|---|---|
| 20 (SR-01..SR-20) | 20 | 0 | 0 | 0 |

Every SR-ID has at least one VTC (`VTC-SR-01..20`), and every VTC is implemented as a
dedicated pytest test module (`tests/test_vtc_NN_*.py`). All 20 VTCs are `✅ VERIFIED`
(passing under `pytest tests/ -v --runslow` → 112 passed, 0 failed, 0 errors — see
`docs/ASPICE_SWE4_UnitVerification.md`).

All 10 SWRs (`SW-SecOC-01..10`) are `✅ VERIFIED` and each is covered by at least one VTC
(traceability matrix §2).

---

## 5. Gap Analysis

### 5.1 SRs with no derived SWR (formal requirements gap)

Per traceability matrix §6, the following SRs are realized by design intent but have no
1:1 `SW-SecOC-*` software requirement. Each carries a documented disposition; none block
Phase 1 closure, but a requirements update is recommended before further phases extend
these areas.

| SR-ID | Disposition |
|---|---|
| SR-01 | Realized jointly by SW-SecOC-02 (verify) + SW-SecOC-06 (reject/DEM); a formal SWR for "violation handling state" is TBD |
| SR-02 | Implemented as a side-effect of SW-SecOC-04 (MAC also provides integrity); formal SWR TBD |
| SR-11 | Implemented as part of SW-SecOC-07 (security profile config); formal SWR TBD |
| SR-14 | New SWR (e.g. `SW-SecOC-11`) recommended for fault-escalation/safe-state behavior |
| SR-15 | No SWR; **SIMULATION ONLY** — hardware enforcement deferred (§5.2) |
| SR-16 | Ethernet adaptation out of scope for Phase 1 (no Ethernet module in `sim.txt`); CAN/CAN FD covered by design intent, formal SWR TBD |
| SR-18 | Process requirement — satisfied by the pytest suite + CI wiring; no SWR needed |
| SR-19 | No SWR; **SIMULATION ONLY** — hardware enforcement deferred (§5.2) |
| SR-20 | Design constraint (AUTOSAR SecOC = authenticity/integrity only); no SWR needed |

### 5.2 Requirements that cannot be fully validated in simulation

Per traceability matrix §5, the following SRs are validated functionally in Phase 1 but
require Phase 2 Hardware-In-the-Loop (HIL) validation for full closure:

| SR-ID | Reason | Phase 2 Validation Method |
|---|---|---|
| SR-09 | Application-layer key access denial enforced logically by `cryif.py`/`hsm.py`; a real HSM enforces this at a hardware trust boundary | HIL key-extraction attempt via debug/JTAG against real HSM/SHE |
| SR-12 | WCET measured via Python wall-clock, not real ECU CPU/HSM crypto-accelerator timing | HIL timing measurement with logic analyzer / trace tooling |
| SR-15 | CPU/memory/CAN load figures are illustrative, not derived from target silicon | HIL load test on target hardware with bus analyzer |
| SR-19 | Secure boot modeled in software; real secure boot is rooted in immutable Boot ROM / HSM trust anchor | HIL secure boot test with corrupted firmware image on target ECU |

These four SRs remain `✅ VERIFIED` for Phase 1 (simulation-level) but are flagged
`SIMULATION ONLY — hardware enforcement deferred` pending Phase 2.

---

## 6. Conclusion

All 20 system requirements (SR-01..SR-20) and all 10 software requirements
(SW-SecOC-01..10) are traced to implementing `sim/` modules and verified by passing
VTC-SR-01..20 test modules. No `⚠ NO TEST` gaps remain. Four requirements (SR-09, SR-12,
SR-15, SR-19) carry a documented Phase-2 HIL validation dependency; this does not block
Phase 1 closure per the traceability matrix's stated disposition.
