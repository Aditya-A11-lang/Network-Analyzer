"""Establish, store, and compare traffic baselines ('What Changed?').

A baseline is a per-device (or aggregate, when no device is specified)
snapshot of key numerical traffic features considered "normal." It is
persisted via src/database.py.
"""
from __future__ import annotations

from typing import Dict, Optional

import pandas as pd

from .utils import get_logger, pct_change
from .feature_engineering import FEATURE_COLUMNS

logger = get_logger(__name__)

MIN_ROWS_FOR_BASELINE = 5

WHAT_CHANGED_METRICS = [
    "packets_per_second",
    "bytes_per_second",
    "unique_destination_ips",
    "unique_destination_ports",
    "connection_count",
    "tcp_ratio",
    "udp_ratio",
    "dns_ratio",
]

METRIC_LABELS = {
    "packets_per_second": "Packets/sec",
    "bytes_per_second": "Bytes/sec",
    "unique_destination_ips": "Unique destinations",
    "unique_destination_ports": "Unique ports",
    "connection_count": "Connections",
    "tcp_ratio": "TCP ratio",
    "udp_ratio": "UDP ratio",
    "dns_ratio": "DNS activity",
}


class InsufficientBaselineError(Exception):
    pass


def aggregate_features(features: pd.DataFrame) -> Dict[str, float]:
    """Collapse per-device features into a single aggregate snapshot
    (mean of ratios, sum of counts/rates) representing overall traffic."""
    if features is None or features.empty:
        raise InsufficientBaselineError("No feature data available to summarize.")

    agg: Dict[str, float] = {}
    rate_like = {"packets_per_second", "bytes_per_second"}
    count_like = {"unique_destination_ips", "unique_destination_ports", "connection_count"}

    for col in FEATURE_COLUMNS:
        if col not in features.columns:
            continue
        if col in rate_like or col in count_like:
            agg[col] = float(features[col].sum())
        else:
            agg[col] = float(features[col].mean())
    return agg


def establish_baseline(features: pd.DataFrame) -> Dict[str, float]:
    """Compute a baseline snapshot from a features DataFrame. Requires a
    minimum number of underlying packets/devices to be considered
    reliable."""
    total_packets = int(features.get("total_packets", pd.Series(dtype=float)).sum()) if "total_packets" in features.columns else len(features)
    if features.empty or total_packets < MIN_ROWS_FOR_BASELINE:
        raise InsufficientBaselineError(
            "Unable to establish a baseline from the supplied traffic."
        )
    return aggregate_features(features)


def compare_to_baseline(baseline: Dict[str, float], current: Dict[str, float]) -> pd.DataFrame:
    """Return a DataFrame with baseline/current/absolute/percentage change
    for each tracked 'What Changed?' metric, and a 'significant' flag."""
    rows = []
    for metric in WHAT_CHANGED_METRICS:
        b = float(baseline.get(metric, 0.0))
        c = float(current.get(metric, 0.0))
        abs_change = c - b
        pct = pct_change(b, c)
        significant = abs(pct) >= 50.0
        rows.append(
            {
                "metric": METRIC_LABELS.get(metric, metric),
                "baseline": round(b, 3),
                "current": round(c, 3),
                "absolute_change": round(abs_change, 3),
                "percentage_change": round(pct, 1),
                "significant": significant,
            }
        )
    return pd.DataFrame(rows)


def has_significant_deviation(comparison: pd.DataFrame) -> bool:
    return bool(comparison["significant"].any()) if not comparison.empty else False
