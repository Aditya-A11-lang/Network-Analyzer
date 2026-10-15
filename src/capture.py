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
from typing import List, Optional

from .utils import get_logger

logger = get_logger(__name__)


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


def list_interfaces() -> List[str]:
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
    """Thread-safe-ish shared state for an in-progress live capture.
    Streamlit reruns the script on every interaction, so this object is
    kept in st.session_state by the caller (app.py) rather than here.
    """
    running: bool = False
    start_time: Optional[float] = None
    packet_count: int = 0
    total_bytes: int = 0
    error: Optional[str] = None
    packets: list = field(default_factory=list)
    _stop_event: Optional[threading.Event] = None
    _thread: Optional[threading.Thread] = None

    def elapsed(self) -> float:
        if not self.start_time:
            return 0.0
        return time.time() - self.start_time


def _capture_worker(state: CaptureState, interface: Optional[str], stop_event: threading.Event) -> None:
    try:
        from scapy.all import sniff

        def _on_packet(pkt):
            if stop_event.is_set():
                return
            state.packets.append(pkt)
            state.packet_count += 1
            state.total_bytes += int(len(pkt))

        sniff(
            iface=interface if interface else None,
            prn=_on_packet,
            store=False,
            stop_filter=lambda _pkt: stop_event.is_set(),
            timeout=1,  # re-checked in a loop below so stop is responsive
        )
        # sniff() with a short timeout returns; loop until stopped so the
        # UI's STOP button takes effect promptly rather than blocking.
        while not stop_event.is_set():
            sniff(
                iface=interface if interface else None,
                prn=_on_packet,
                store=False,
                stop_filter=lambda _pkt: stop_event.is_set(),
                timeout=1,
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


def start_capture(state: CaptureState, interface: Optional[str] = None) -> CaptureState:
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

    state.running = True
    state.start_time = time.time()
    state.packet_count = 0
    state.total_bytes = 0
    state.error = None
    state.packets = []
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
    return state
