"""Local live packet capture using Scapy.

This module ONLY captures traffic on the local machine it runs on, for
authorized network monitoring. It never injects, modifies, replays, or
sends packets, and it never inspects payload contents - only metadata
(handled downstream by packet_parser.py).

Live capture is intentionally unavailable in cloud deployments: a
cloud-hosted Streamlit app has no access to a visitor's local network
interface. `is_cloud_environment()` lets the UI detect this and disable
the Live Analyzer page with an explanation instead of pretending to
capture traffic.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .utils import get_logger

logger = get_logger(__name__)
MAX_CAPTURE_PACKETS = 50_000


class CapturePermissionError(Exception):
    """Raised when the OS denies permission to capture on an interface."""


class NoInterfaceError(Exception):
    """Raised when no usable network interface can be found."""


def is_cloud_environment() -> bool:
    """Best-effort detection of a Streamlit Community Cloud deployment,
    where raw packet capture is not possible."""
    return bool(
        os.environ.get("STREAMLIT_RUNTIME_ENV") == "cloud"
        or os.environ.get("HOSTNAME", "").startswith("streamlit-")
        or os.environ.get("STREAMLIT_SHARING_MODE")
        or os.environ.get("IS_STREAMLIT_CLOUD")
    )


def list_interfaces() -> list[str]:
    """Return available network interface names/descriptions for the
    interface selector. Never assumes a fixed interface name."""
    try:
        from scapy.all import get_if_list

        interfaces = get_if_list()
        return interfaces or []
    except Exception as exc:
        logger.warning("Could not list interfaces: %s", exc)
        return []


@dataclass
class CaptureState:
    """Shared state for an in-progress metadata-only live capture.
    Streamlit reruns the script on every interaction, so this object is
    kept in st.session_state by the caller (app.py) rather than here.
    """
    running: bool = False
    start_time: Optional[float] = None
    stop_time: Optional[float] = None
    max_duration: int = 60
    packet_count: int = 0
    total_bytes: int = 0
    error: Optional[str] = None
    records: list[dict] = field(default_factory=list)
    _stop_event: Optional[threading.Event] = None
    _thread: Optional[threading.Thread] = None

    def elapsed(self) -> float:
        if not self.start_time:
            return 0.0
        end_time = self.stop_time if self.stop_time is not None else time.time()
        return end_time - self.start_time


def _capture_worker(state: CaptureState, interface: Optional[str], stop_event: threading.Event) -> None:
    try:
        from scapy.all import sniff
        from .packet_parser import packet_to_row

        def _on_packet(pkt):
            if stop_event.is_set():
                return
            if state.packet_count >= MAX_CAPTURE_PACKETS:
                state.error = "packet_limit"
                stop_event.set()
                return
            row = packet_to_row(pkt)
            if row is None:
                return
            state.records.append(row)
            state.packet_count += 1
            state.total_bytes += row["length"]
            if state.packet_count >= MAX_CAPTURE_PACKETS:
                state.error = "packet_limit"
                stop_event.set()

        while not stop_event.is_set():
            remaining = state.max_duration - state.elapsed()
            if remaining <= 0:
                stop_event.set()
                break
            sniff(
                iface=interface if interface else None,
                prn=_on_packet,
                store=False,
                timeout=min(1.0, remaining),
            )
    except PermissionError as exc:
        state.error = "capture_permission"
        logger.error("Capture permission denied: %s", exc)
    except OSError as exc:
        state.error = "no_interface"
        logger.error("Capture interface error: %s", exc)
    except Exception as exc:  # noqa: BLE001 - boundary catch, never crash the app
        state.error = "generic"
        logger.exception("Unexpected capture error: %s", exc)
    finally:
        state.running = False
        state.stop_time = time.time()


def start_capture(
    state: CaptureState,
    interface: Optional[str] = None,
    max_duration: int = 60,
) -> CaptureState:
    """Start a background live capture thread. Only usable when running
    locally (see is_cloud_environment()). Captures only on machines the
    operator is authorized to monitor."""
    if is_cloud_environment():
        raise RuntimeError(
            "Live capture requires running the application locally on an "
            "authorized machine. Cloud deployments support PCAP upload and analysis."
        )

    if state.running:
        return state
    if not 1 <= max_duration <= 3600:
        raise ValueError("Capture duration must be between 1 and 3600 seconds.")

    state.running = True
    state.start_time = time.time()
    state.stop_time = None
    state.max_duration = max_duration
    state.packet_count = 0
    state.total_bytes = 0
    state.error = None
    state.records = []
    state._stop_event = threading.Event()
    state._thread = threading.Thread(
        target=_capture_worker, args=(state, interface, state._stop_event), daemon=True
    )
    state._thread.start()
    return state


def stop_capture(state: CaptureState) -> CaptureState:
    """Signal the capture thread to stop and wait briefly for it to exit."""
    if state._stop_event is not None:
        state._stop_event.set()
    if state._thread is not None:
        state._thread.join(timeout=3)
    state.running = False
    if state.start_time is not None and state.stop_time is None:
        state.stop_time = time.time()
    return state
