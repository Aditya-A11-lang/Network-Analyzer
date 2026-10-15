"""Aggregate per-packet metadata into per-device numerical behavioral
features, used for both fingerprinting and anomaly detection."""
from __future__ import annotations

import pandas as pd
import numpy as np

from .utils import safe_div, get_logger

logger = get_logger(__name__)

FEATURE_COLUMNS = [
    "packets_per_second",
    "bytes_per_second",
    "average_packet_size",
    "unique_destination_ips",
    "unique_destination_ports",
    "unique_source_ports",
    "tcp_ratio",
    "udp_ratio",
    "icmp_ratio",
    "dns_ratio",
    "connection_count",
    "protocol_diversity",
    "destination_diversity",
    "port_diversity",
]


def _diversity(count_unique: int, total: int) -> float:
    """Simple diversity ratio in [0, 1]: unique values relative to total
    observations (capped at 1.0)."""
    return min(1.0, safe_div(count_unique, total))


def build_device_features(df: pd.DataFrame) -> pd.DataFrame:
    """Group metadata by source IP and compute a numerical feature vector
    per device. Returns a DataFrame indexed by src_ip with FEATURE_COLUMNS."""
    if df is None or df.empty:
        return pd.DataFrame(columns=FEATURE_COLUMNS)

    duration = max(float(df["timestamp"].max() - df["timestamp"].min()), 1e-6)

    records = []
    for src_ip, group in df.groupby("src_ip"):
        total_packets = len(group)
        total_bytes = float(group["length"].sum())

        proto_counts = group["protocol"].value_counts()
        tcp = int(proto_counts.get("TCP", 0))
        udp = int(proto_counts.get("UDP", 0))
        icmp = int(proto_counts.get("ICMP", 0))
        dns = int(group["is_dns"].sum())

        unique_dst_ips = group["dst_ip"].nunique()
        unique_dst_ports = group["dst_port"].dropna().nunique()
        unique_src_ports = group["src_port"].dropna().nunique()
        protocol_diversity = proto_counts.shape[0]
        connection_count = group[["dst_ip", "dst_port"]].dropna().drop_duplicates().shape[0]

        record = {
            "src_ip": src_ip,
            "packets_per_second": safe_div(total_packets, duration),
            "bytes_per_second": safe_div(total_bytes, duration),
            "average_packet_size": safe_div(total_bytes, total_packets),
            "unique_destination_ips": unique_dst_ips,
            "unique_destination_ports": unique_dst_ports,
            "unique_source_ports": unique_src_ports,
            "tcp_ratio": safe_div(tcp, total_packets),
            "udp_ratio": safe_div(udp, total_packets),
            "icmp_ratio": safe_div(icmp, total_packets),
            "dns_ratio": safe_div(dns, total_packets),
            "connection_count": connection_count,
            "protocol_diversity": _diversity(protocol_diversity, 3),  # max 3 tracked protocols
            "destination_diversity": _diversity(unique_dst_ips, total_packets),
            "port_diversity": _diversity(unique_dst_ports, total_packets),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
        }
        records.append(record)

    features = pd.DataFrame(records).set_index("src_ip")
    features = features.replace([np.inf, -np.inf], 0).fillna(0)
    return features


def feature_matrix(features: pd.DataFrame) -> pd.DataFrame:
    """Return only the ML-ready numerical columns (drops helper totals)."""
    cols = [c for c in FEATURE_COLUMNS if c in features.columns]
    return features[cols].copy()
