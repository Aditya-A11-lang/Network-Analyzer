import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pandas as pd

from src.risk_scoring import calculate_risk_score, calculate_network_health, severity_for_score


def _comparison(pct_changes):
    rows = []
    for metric, pct in pct_changes.items():
        rows.append({
            "metric": metric, "baseline": 10, "current": 10 * (1 + pct / 100),
            "absolute_change": 10 * pct / 100, "percentage_change": pct, "significant": abs(pct) >= 50,
        })
    return pd.DataFrame(rows)


def test_severity_bands():
    assert severity_for_score(0) == "INFO"
    assert severity_for_score(24) == "INFO"
    assert severity_for_score(25) == "LOW"
    assert severity_for_score(49) == "LOW"
    assert severity_for_score(50) == "MEDIUM"
    assert severity_for_score(74) == "MEDIUM"
    assert severity_for_score(75) == "HIGH"
    assert severity_for_score(100) == "HIGH"


def test_risk_score_no_baseline_uses_anomaly_only():
    result = calculate_risk_score(anomaly_score=0.9, comparison=None)
    assert result["risk_score"] == 90.0
    assert result["severity"] == "HIGH"


def test_risk_score_zero_anomaly_no_baseline():
    result = calculate_risk_score(anomaly_score=0.0, comparison=None)
    assert result["risk_score"] == 0.0
    assert result["severity"] == "INFO"


def test_risk_score_with_large_deviation_increases_score():
    low_dev = _comparison({"Packets/sec": 5, "Unique destinations": 5})
    high_dev = _comparison({"Packets/sec": 300, "Unique destinations": 300})
    low_result = calculate_risk_score(anomaly_score=0.3, comparison=low_dev)
    high_result = calculate_risk_score(anomaly_score=0.3, comparison=high_dev)
    assert high_result["risk_score"] > low_result["risk_score"]


def test_risk_score_is_clamped_to_0_100():
    result = calculate_risk_score(anomaly_score=5.0, comparison=None)
    assert 0 <= result["risk_score"] <= 100


def test_network_health_decreases_with_risk_and_anomaly_rate():
    healthy = calculate_network_health(average_risk=5, anomaly_rate=0.0)
    unhealthy = calculate_network_health(average_risk=90, anomaly_rate=0.8)
    assert healthy > unhealthy
    assert 0 <= unhealthy <= 100
