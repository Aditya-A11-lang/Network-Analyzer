"""Shared helpers: logging, safe-error wrapping, small numeric utilities."""
from __future__ import annotations

import logging
import functools
from typing import Any, Callable, TypeVar

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

T = TypeVar("T")

# Friendly, non-technical messages shown to end users when something fails.
FRIENDLY_MESSAGES = {
    "empty_pcap": "The uploaded file contains no readable packets.",
    "invalid_pcap": "Please upload a valid PCAP or PCAPNG file.",
    "insufficient_data": "Insufficient traffic data for anomaly analysis.",
    "insufficient_baseline": "Unable to establish a baseline from the supplied traffic.",
    "capture_permission": "Live capture requires appropriate permissions on this machine.",
    "no_interface": "No usable network interface was found for live capture.",
    "model_unavailable": "The anomaly model is not yet available. Analyze more traffic first.",
    "generic": "Something went wrong while processing this request.",
}


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def safe_call(logger: logging.Logger, friendly_key: str = "generic"):
    """Decorator that logs full exceptions but returns a friendly message
    tuple (success: bool, result_or_message) instead of raising, so the
    Streamlit UI never shows a raw traceback."""

    def decorator(fn: Callable[..., T]) -> Callable[..., tuple[bool, Any]]:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                result = fn(*args, **kwargs)
                return True, result
            except Exception as exc:  # noqa: BLE001 - intentional broad catch at boundary
                logger.exception("Error in %s: %s", fn.__name__, exc)
                return False, FRIENDLY_MESSAGES.get(friendly_key, FRIENDLY_MESSAGES["generic"])

        return wrapper

    return decorator


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def safe_div(numerator: float, denominator: float, default: float = 0.0) -> float:
    if not denominator:
        return default
    return numerator / denominator


def pct_change(baseline: float, current: float) -> float:
    """Percentage change from baseline to current. Handles baseline == 0."""
    if baseline == 0:
        if current == 0:
            return 0.0
        return 100.0 * 3  # treat "from zero" as a large, flagged jump (300%)
    return ((current - baseline) / baseline) * 100.0
