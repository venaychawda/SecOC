"""Tunable constants for the SecOC simulation.

All magic numbers used across sim/ modules must be defined here
(per CLAUDE.md coding standards).
"""
import logging

# sim.dem.HashChainedLog -- max entries kept in the tamper-evident audit journal
MAX_AUDIT_ENTRIES = 1000

# --- SecOC protected-region / wire-format defaults (illustrative profile) ---
DEFAULT_FRESHNESS_LENGTH = 2
DEFAULT_AUTHENTICATOR_LENGTH = 8

# --- Algorithm agility (SR-10, SW-SecOC-07) ---
SUPPORTED_ALGORITHMS = ("HMAC-SHA256", "HMAC-SHA512")

# --- Fault escalation / safe-state (SR-14, SW-SecOC-11) ---
MAX_AUTH_FAILURES = 5

# --- Performance / WCET budget (SR-12, SW-SecOC-08) ---
MAC_WCET_BUDGET_MS = 5.0

# --- Resource / load thresholds (SR-15, SIMULATION ONLY) ---
MAX_BUS_MESSAGES_PER_WINDOW = 1000
MIN_AVERAGE_MESSAGE_INTERVAL_MS = 1.0

# --- CAN / CAN FD transport limits (SR-16) ---
CAN_MAX_PAYLOAD_BYTES = 8
CAN_FD_MAX_PAYLOAD_BYTES = 64

# --- Security profile config location ---
DEFAULT_SECURITY_PROFILE_PATH = "config/secoc_profiles.json"

# --- Trace/debug logging (sim/logger.py) -- non-security, separate from dem.py ---
LOG_LEVEL = logging.INFO
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_FILE_PATH: str | None = None
