# SecOC — Secure Onboard Communication Simulation

AUTOSAR Classic SecOC simulation project: secured I-PDU authentication,
freshness management, and key handling for inter-ECU CAN communication,
following ISO/SAE 21434, AUTOSAR Classic, and UN R155.

## Status

**Phase 1 — Simulation** (active). All `sim/` modules listed in `requirements/sim.txt` are implemented,
including the ECU object model (`ecu_base.py`, `sender_ecu.py`,
`receiver_ecu.py`), `pdu_router.py`, `signal_packager.py`, `logger.py`, and
`time_utils.py`.

## Quick Start

```bash
# Install (editable install so `sim`/`api` resolve for pytest)
pip install -e .
pip install -r requirements.txt

# Run tests
pytest tests/ -v --tb=short      # fast suite
pytest tests/ --runslow -v       # + timer-dependent tests
```

## Running the Dashboard

**Proof of Concept** — standalone, no backend, pure JS animation: [▶ Live Demo](https://venaychawda.github.io/SecOC/)

```bash
open dashboard/index.html
```

**Live Monitor** — connects to the real FastAPI backend:

```bash
# Terminal 1
uvicorn api.main:app --reload --port 8000

# Terminal 2
python -m http.server 3000 --directory dashboard
# then open http://localhost:3000/SecOC_Monitor.html
```

Alternatively, on Windows, just double-click **`start.bat`** — it sets up the
virtual environment, installs dependencies, starts the backend and dashboard
servers in their own windows, and opens the Live Monitor in your browser
automatically.

See **`USERINFO.md`** for how to use the Live Monitor to validate secure
communication (transmit/receive, attack injection, VTC scenario runs) and a
full reference of every panel in the GUI.

## Layout

- `requirements/` — customer/system/software requirements and test plan (CSV, `.txt`)
- `design/` — architecture, HLD, LLDs, sequence diagrams (Mermaid)
- `sim/` — SecOC simulation modules
- `api/` — FastAPI backend
- `dashboard/` — PoC and live monitor dashboards
- `tests/` — pytest VTC test suites
- `docs/` — ASPICE process documents
