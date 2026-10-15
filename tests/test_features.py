import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pandas as pd

from src.feature_engineering import build_device_features, feature_matrix, FEATURE_COLUMNS


def _sample_df():
    rows = []
    # device A: steady TCP traffic to a couple of destinations
    for i in range(10):
        rows.append({
            "timestamp": i * 0.5, "src_ip": "10.0.0.1", "dst_ip": f"10.0.0.{100 + (i % 2)}",
            "src_port": 40000 + i, "dst_port": 443, "protocol": "TCP", "length": 600, "is_dns": False,
        })
    # device B: bursty traffic to many destinations/ports
    for i in range(20):
        rows.append({
            "timestamp": i * 0.1, "src_ip": "10.0.0.2", "dst_ip": f"10.0.1.{i}",
            "src_port": 50000 + i, "dst_port": 1000 + i, "protocol": "UDP", "length": 80, "is_dns": (i % 5 == 0),
        })
    return pd.DataFrame(rows)


def test_build_device_features_returns_row_per_device():
    features = build_device_features(_sample_df())
    assert set(features.index) == {"10.0.0.1", "10.0.0.2"}
    for col in FEATURE_COLUMNS:
        assert col in features.columns


def test_empty_dataframe_returns_empty_features():
    features = build_device_features(pd.DataFrame())
    assert features.empty


def test_feature_matrix_drops_helper_columns():
    features = build_device_features(_sample_df())
    matrix = feature_matrix(features)
    assert "total_packets" not in matrix.columns
    assert "total_bytes" not in matrix.columns
    assert list(matrix.columns) == [c for c in FEATURE_COLUMNS if c in features.columns]


def test_bursty_device_has_higher_port_diversity():
    features = build_device_features(_sample_df())
    assert features.loc["10.0.0.2", "port_diversity"] > features.loc["10.0.0.1", "port_diversity"]
