"""Communication Fingerprinting Module.

Builds behavioral fingerprints and generates deterministic IDs and visual
representation strings for device traffic metadata features.
"""
from __future__ import annotations

import hashlib
import pandas as pd

from src.feature_engineering import FEATURE_COLUMNS


def generate_fingerprint_id(row: pd.Series) -> str:
    """Generate an 8-character deterministic fingerprint ID from a feature row."""
    values_str = "-".join(f"{row.get(col, 0.0):.3f}" for col in FEATURE_COLUMNS)
    hash_digest = hashlib.sha256(values_str.encode("utf-8")).hexdigest()
    return f"{hash_digest[:2].upper()}-{hash_digest[2:4].upper()}-{hash_digest[4:6].upper()}"


def bar_string(percentage: float, width: int = 10) -> str:
    """Render a visual ASCII/Unicode progress bar string with high-contrast format."""
    pct = max(0.0, min(100.0, float(percentage)))
    filled = int(round(width * (pct / 100.0)))
    bar = "█" * filled + "░" * (width - filled)
    return f"{bar}  {pct:5.1f}%"


def build_fingerprints(features_df: pd.DataFrame) -> dict[str, dict]:
    """Build communication fingerprints for each device in the features DataFrame."""
    if features_df is None or features_df.empty:
        return {}

    fingerprints = {}
    for src_ip, row in features_df.iterrows():
        fp_id = generate_fingerprint_id(row)
        bars = {}
        for col in FEATURE_COLUMNS:
            val = float(row.get(col, 0.0))
            pct = max(0.0, min(100.0, val * 100.0))
            label = col.replace("_", " ").title()
            bars[label] = pct

        fingerprints[str(src_ip)] = {
            "fingerprint_id": fp_id,
            "bars": bars,
        }
    return fingerprints