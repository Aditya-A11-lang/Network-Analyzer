"""Project-defined 0-100 risk score and severity banding.

These thresholds are analytical conventions for this project, not
universal cybersecurity standards.
"""
from __future__ import annotations

from typing import Dict, Optional

import pandas as pd

from .utils import clamp

SEVERITY_BANDS = [
    (0, 24, "INFO"),
    (25, 49, "LOW"),
    (50, 74, "MEDIUM"),
    (75, 100, "HIGH"),
]

WEIGHTS = {
    "anomaly": 0.40,
    "rate_deviation": 0.25,
    "diversity_deviation": 0.20,
    "protocol_deviation": 0.15,
}


def severity_for_score(score: float) -> str:
    for low, high, label in SEVERITY_BANDS:
        if low <= score <= high:
            return label
    return "INFO"


def _deviation_component(comparison: Optional[pd.DataFrame], metrics: list[str]) -> float:
    """Average absolute percentage change (capped at 200%) across the
    given metrics from a 'What Changed?' comparison table, scaled to 0-1."""
    if comparison is None or comparison.empty:
        return 0.0
    subset = comparison[comparison["metric"].isin(metrics)]
    if subset.empty:
        return 0.0
    capped = subset["percentage_change"].abs().clip(upper=200.0)
    return float((capped / 200.0).mean())


def calculate_risk_score(
    anomaly_score: float,
    comparison: Optional[pd.DataFrame] = None,
) -> Dict[str, object]:
    """Combine anomaly score (0-1) with baseline deviation (if available)
    into a 0-100 risk score and severity label.

    `comparison` is the DataFrame returned by baseline.compare_to_baseline,
    with columns: metric, baseline, current, absolute_change,
    percentage_change, significant.
    """
    anomaly_component = clamp(anomaly_score * 100, 0, 100)

    rate_dev = _deviation_component(comparison, ["Packets/sec", "Bytes/sec"])
    diversity_dev = _deviation_component(comparison, ["Unique destinations", "Unique ports", "Connections"])
    protocol_dev = _deviation_component(comparison, ["TCP ratio", "UDP ratio", "DNS activity"])

    if comparison is None or comparison.empty:
        # No baseline yet: risk is driven entirely by the anomaly model.
        score = anomaly_component
    else:
        score = (
            WEIGHTS["anomaly"] * anomaly_component
            + WEIGHTS["rate_deviation"] * (rate_dev * 100)
            + WEIGHTS["diversity_deviation"] * (diversity_dev * 100)
            + WEIGHTS["protocol_deviation"] * (protocol_dev * 100)
        )

    score = clamp(score, 0, 100)
    return {
        "risk_score": round(score, 1),
        "severity": severity_for_score(score),
        "components": {
            "anomaly": round(anomaly_component, 1),
            "rate_deviation": round(rate_dev * 100, 1),
            "diversity_deviation": round(diversity_dev * 100, 1),
            "protocol_deviation": round(protocol_dev * 100, 1),
        },
    }


def calculate_network_health(average_risk: float, anomaly_rate: float) -> int:
    """Simple project-level 'network health' metric (0-100), inverse of
    average risk and anomaly rate. Not an industry-standard rating."""
    health = 100 - (average_risk * 0.7) - (anomaly_rate * 100 * 0.3)
    return int(round(clamp(health, 0, 100)))
