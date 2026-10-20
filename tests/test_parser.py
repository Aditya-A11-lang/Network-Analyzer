import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from scapy.all import Ether, IP, TCP, UDP

from src.packet_parser import (
    EmptyCaptureError,
    metadata_rows_to_dataframe,
    packet_to_row,
    packets_to_dataframe,
)


def _tcp_packet(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=443, size_pad=0):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport)
    if size_pad:
        pkt = pkt / ("A" * size_pad)
    return pkt


def _udp_dns_packet(src="10.0.0.1", dst="8.8.8.8"):
    return Ether() / IP(src=src, dst=dst) / UDP(sport=5353, dport=53)


def test_packet_to_row_extracts_metadata():
    pkt = _tcp_packet()
    row = packet_to_row(pkt)
    assert row is not None
    assert row["src_ip"] == "10.0.0.1"
    assert row["dst_ip"] == "10.0.0.2"
    assert row["protocol"] == "TCP"
    assert row["dst_port"] == 443


def test_packet_to_row_skips_non_ip():
    row = packet_to_row(Ether())
    assert row is None


def test_packets_to_dataframe_builds_expected_columns():
    packets = [_tcp_packet(), _udp_dns_packet()]
    df = packets_to_dataframe(packets)
    assert len(df) == 2
    assert set(["timestamp", "src_ip", "dst_ip", "protocol", "length"]).issubset(df.columns)
    assert df["protocol"].isin(["TCP", "UDP"]).all()


def test_packets_to_dataframe_empty_raises():
    with pytest.raises(EmptyCaptureError):
        packets_to_dataframe([])


def test_dns_udp_packet_flagged():
    df = packets_to_dataframe([_udp_dns_packet()])
    assert bool(df.iloc[0]["is_dns"]) is True


def test_metadata_rows_are_normalized_without_payload_fields():
    df = metadata_rows_to_dataframe(
        [
            {
                "timestamp": 12.5,
                "src_ip": "10.0.0.1",
                "dst_ip": "10.0.0.2",
                "src_port": 1234,
                "dst_port": 443,
                "protocol": "TCP",
                "length": 96,
                "is_dns": False,
                "payload": "must not be retained",
            },
            {
                "timestamp": 15.0,
                "src_ip": "10.0.0.2",
                "dst_ip": "10.0.0.1",
                "src_port": 443,
                "dst_port": 1234,
                "protocol": "TCP",
                "length": 104,
                "is_dns": False,
            },
        ]
    )
    assert df["timestamp"].tolist() == [0.0, 2.5]
    assert "payload" not in df.columns
    assert df["length"].tolist() == [96, 104]
