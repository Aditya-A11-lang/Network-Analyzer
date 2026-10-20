import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import scapy.all
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from src import capture
from src.packet_parser import COLUMNS


def test_capture_worker_retains_only_metadata(monkeypatch):
    packet = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=443) / b"payload"
    monkeypatch.setattr(capture, "is_cloud_environment", lambda: False)

    def fake_sniff(**kwargs):
        kwargs["prn"](packet)
        time.sleep(0.01)

    monkeypatch.setattr(scapy.all, "sniff", fake_sniff)
    state = capture.CaptureState()
    try:
        capture.start_capture(state, max_duration=5)
        deadline = time.monotonic() + 1
        while state.packet_count == 0 and time.monotonic() < deadline:
            time.sleep(0.01)
        capture.stop_capture(state)
    finally:
        if state.running:
            capture.stop_capture(state)

    assert state.packet_count > 0
    assert set(state.records[0]) == set(COLUMNS)
    assert "payload" not in state.records[0]
    assert state.total_bytes == sum(row["length"] for row in state.records)


def test_elapsed_time_stops_increasing_after_capture_stops():
    state = capture.CaptureState(start_time=time.time() - 1)

    capture.stop_capture(state)
    elapsed = state.elapsed()
    time.sleep(0.02)

    assert state.elapsed() == elapsed
