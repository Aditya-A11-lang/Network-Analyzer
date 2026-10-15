import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pandas as pd

from src.fingerprint import build_fingerprints, generate_fingerprint_id, bar_string
from src.feature_engineering import FEATURE_COLUMNS


def _features_df():
    data = {col: [0.2, 0.8] for col in FEATURE_COLUMNS}
    return pd.DataFrame(data, index=["10.0.0.1", "10.0.0.2"])


def test_build_fingerprints_returns_entry_per_device():
    fingerprints = build_fingerprints(_features_df())
    assert set(fingerprints.keys()) == {"10.0.0.1", "10.0.0.2"}
    for fp in fingerprints.values():
        assert "fingerprint_id" in fp
        assert "bars" in fp
        assert all(0 <= v <= 100 for v in fp["bars"].values())


def test_fingerprint_id_is_deterministic():
    row = pd.Series({col: 0.5 for col in FEATURE_COLUMNS})
    id1 = generate_fingerprint_id(row)
    id2 = generate_fingerprint_id(row)
    assert id1 == id2
    assert len(id1) == 8  # "XX-XX-XX"


def test_fingerprint_id_format():
    row = pd.Series({col: 0.1 for col in FEATURE_COLUMNS})
    fp_id = generate_fingerprint_id(row)
    parts = fp_id.split("-")
    assert len(parts) == 3
    assert all(len(p) == 2 for p in parts)


def test_bar_string_renders_percentage():
    s = bar_string(50, width=10)
    assert "50%" in s
    assert len(s.split("  ")[0]) == 10


def test_empty_features_returns_empty_fingerprints():
    assert build_fingerprints(pd.DataFrame()) == {}
