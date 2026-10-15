"""Generate a plain-language, explainable AI Traffic Review from the
outputs of the anomaly model, risk engine, and baseline comparison.

The review never claims that a deviation proves malicious activity — it
describes observed behavioral change and recommends investigation.
"""
from __future__ import annotations

from typing import Dict, Optional

import pandas as pd


def _deviation_bullets(comparison: Optional[pd.DataFrame]) -> list[str]:
    bullets = []
    if comparison is None or comparison.empty:
        return bullets
    significant = comparison[comparison["significant"]]
    for _, row in significant.iterrows():
        direction = "increased" if row["absolute_change"] >= 0 else "decreased"
        bullets.append(
            f"{row['metric']} has {direction} significantly "
            f"({row['percentage_change']:+.0f}% vs. baseline)."
        )
    return bullets


def generate_ai_review(
    is_anomalous: bool,
    anomaly_score: float,
    risk_result: Dict[str, object],
    comparison: Optional[pd.DataFrame] = None,
    device_ip: Optional[str] = None,
) -> Dict[str, object]:
    """Build the structured AI Traffic Review shown on the AI Analysis page."""
    classification = "ANOMALOUS" if is_anomalous else "NORMAL"
    risk_score = risk_result["risk_score"]
    severity = risk_result["severity"]

    deviations = _deviation_bullets(comparison)
    if is_anomalous and not deviations:
        deviations.append("Traffic behavior differs from what the anomaly model considers typical.")
    if comparison is not None and not comparison.empty:
        deviations.append("Current traffic differs from the established baseline in one or more metrics.")

    if is_anomalous:
        interpretation = (
            "The observed communication behavior differs from the established "
            "device fingerprint and requires further investigation. This does "
            "not, by itself, indicate malicious activity."
        )
        recommendation = (
            "Review the destination addresses, ports, and traffic timing "
            "involved to determine whether this behavior is expected, "
            "authorized, and consistent with normal device usage."
        )
    else:
        interpretation = (
            "The observed communication behavior is consistent with the "
            "established device fingerprint and baseline traffic patterns."
        )
        recommendation = (
            "No immediate action is required. Continue routine monitoring."
        )

    subject = f" for {device_ip}" if device_ip else ""

    return {
        "classification": classification,
        "risk_score": risk_score,
        "severity": severity,
        "anomaly_score": round(anomaly_score, 3),
        "deviations": deviations,
        "interpretation": interpretation,
        "recommendation": recommendation,
        "title": f"AI Traffic Review{subject}",
        "disclaimer": (
            "This classification reflects a statistical behavioral deviation, "
            "not a confirmed security incident. Anomalous does not mean malicious."
        ),
    }
