"""Parse PCAP/PCAPNG files or in-memory Scapy packet lists into a
metadata-only pandas DataFrame.

Privacy note: only headers/metadata are read (src/dst IP, ports,
protocol, packet length, timestamp). Payload bytes are never extracted
or stored.
"""
from __future__ import annotations

from typing import Iterable, Optional

import pandas as pd

from .utils import get_logger

logger = get_logger(__name__)

COLUMNS = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "length",
    "is_dns",
]


class InvalidPcapError(Exception):
    """Raised when a PCAP file cannot be parsed."""


class EmptyCaptureError(Exception):
    """Raised when a capture/file contains zero usable packets."""


def _protocol_name(pkt) -> str:
    """Best-effort protocol classification without touching payloads."""
    try:
        from scapy.layers.inet import TCP, UDP, ICMP  # local import: optional at import time

        if pkt.haslayer(TCP):
            return "TCP"
        if pkt.haslayer(UDP):
            return "UDP"
        if pkt.haslayer(ICMP):
            return "ICMP"
    except Exception:  # scapy not fully available in some environments
        pass
    return "OTHER"


def _is_dns(pkt) -> bool:
    try:
        from scapy.layers.dns import DNS

        if pkt.haslayer(DNS):
            return True
    except Exception:
        pass
    # fallback: port 53 heuristic, checked by caller with src/dst ports
    return False


def packet_to_row(pkt) -> Optional[dict]:
    """Extract metadata from a single Scapy packet. Returns None for
    packets without an IP layer (nothing meaningful to analyze)."""
    try:
        from scapy.layers.inet import IP, TCP, UDP

        if not pkt.haslayer(IP):
            return None

        ip_layer = pkt[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        length = int(len(pkt))
        timestamp = float(getattr(pkt, "time", 0.0))

        src_port = dst_port = None
        protocol = _protocol_name(pkt)

        if pkt.haslayer(TCP):
            src_port = int(pkt[TCP].sport)
            dst_port = int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            src_port = int(pkt[UDP].sport)
            dst_port = int(pkt[UDP].dport)

        is_dns = _is_dns(pkt) or src_port == 53 or dst_port == 53

        return {
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "length": length,
            "is_dns": is_dns,
        }
    except Exception as exc:  # skip malformed individual packets, don't kill the batch
        logger.debug("Skipping unparsable packet: %s", exc)
        return None


def packets_to_dataframe(packets: Iterable) -> pd.DataFrame:
    """Convert an iterable of Scapy packets (from a live capture or a
    read PCAP) into a metadata-only DataFrame."""
    rows = [r for r in (packet_to_row(p) for p in packets) if r is not None]
    if not rows:
        raise EmptyCaptureError("No IP packets with extractable metadata were found.")
    df = pd.DataFrame(rows, columns=COLUMNS)
    # normalize timestamps to start at 0 for consistent rate calculations
    if not df.empty:
        df["timestamp"] = df["timestamp"] - df["timestamp"].min()
    return df


def parse_pcap_file(file_path: str) -> pd.DataFrame:
    """Read a .pcap/.pcapng file from disk and return a metadata DataFrame."""
    try:
        from scapy.utils import rdpcap
    except Exception as exc:
        raise InvalidPcapError(f"Scapy is unavailable to read PCAP files: {exc}") from exc

    try:
        packets = rdpcap(file_path)
    except Exception as exc:
        raise InvalidPcapError(f"Unable to read PCAP file: {exc}") from exc

    if len(packets) == 0:
        raise EmptyCaptureError("The PCAP file contains zero packets.")

    return packets_to_dataframe(packets)


def parse_pcap_bytes(file_bytes: bytes, tmp_path: str) -> pd.DataFrame:
    """Write uploaded bytes to a temp path, then parse. Used for Streamlit
    file_uploader objects, which provide bytes rather than a filesystem path."""
    if not file_bytes:
        raise EmptyCaptureError("The uploaded file is empty.")
    with open(tmp_path, "wb") as f:
        f.write(file_bytes)
    return parse_pcap_file(tmp_path)
