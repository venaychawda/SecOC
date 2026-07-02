"""Generic non-security trace/debug logging, shared by all sim/ modules.

Explicitly separate from sim/dem.py: security events (auth failures, freshness
violations, WCET overruns, DEM-classified events) MUST go through dem.py /
event_logger.py / security_events.py, never through this module. This module
is reserved for non-security debug/trace output only.
"""
import logging

from sim.config import LOG_FILE_PATH, LOG_FORMAT, LOG_LEVEL

_configured = False


def _attach_handlers(level: int, log_format: str, log_file_path: str | None) -> None:
    root = logging.getLogger("secoc")
    root.handlers.clear()
    root.setLevel(level)
    formatter = logging.Formatter(log_format)

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    root.addHandler(handler)

    if log_file_path:
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Returns a configured logging.Logger for the given module name.

    Args:
        name: Dotted module name, conventionally __name__ of the caller.

    Returns:
        A logging.Logger named "secoc.<name>", configured per config.py
        defaults on first call (idempotent thereafter).
    """
    global _configured
    if not _configured:
        _attach_handlers(LOG_LEVEL, LOG_FORMAT, LOG_FILE_PATH)
        _configured = True
    return logging.getLogger(f"secoc.{name}")


def set_level(level: int) -> None:
    """Overrides the effective log level for the entire secoc logger hierarchy.

    Args:
        level: A standard logging level constant (e.g. logging.DEBUG).
    """
    logging.getLogger("secoc").setLevel(level)


def configure(
    level: int | None = None,
    log_format: str | None = None,
    log_file_path: str | None = None,
) -> None:
    """(Re-)applies logging configuration, overriding config.py defaults.

    Args:
        level: Optional override for config.LOG_LEVEL.
        log_format: Optional override for config.LOG_FORMAT.
        log_file_path: Optional override for config.LOG_FILE_PATH.
    """
    global _configured
    _attach_handlers(
        level if level is not None else LOG_LEVEL,
        log_format if log_format is not None else LOG_FORMAT,
        log_file_path,
    )
    _configured = True
