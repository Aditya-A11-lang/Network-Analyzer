"""Generate a per-device behavioral communication fingerprint: a set of
normalized (0-100%) bars over key traffic features, plus a short,
project-level behavioral identifier (NOT a global device identity)."""
from __future__ import annotations

import hashlib
from typing import Dict

import numpy as np
import pandas as pd

# Features shown on the fingerprint visualization, with friendly labels.
FINGERPRINT_DISPLAY_FEATURES = {
    "tcp_ratio": "TCP / HTTPS-style usage",
    "dns_ratio": "DNS activity",
    "destination_diversity": "Destination diversity",
    "port_diversity": "Port diversity",
    "packets_per_second": "Packet rate",
}


def _normalize_series(series: pd.Series) -> pd.Series:
    """Min-max normalize a feature column across all devices in the
    current session to produce a comparable 0-100% bar."""
    lo, hi = series.min(), series.max()
    if hi - lo < 1e-9:
        # all devices identical on this feature; show a flat mid-level bar
        return pd.Series(50.0, index=series.index)
    return ((series - lo) / (hi - lo)) * 100.0


def generate_fingerprint_id(feature_vector: pd.Series) -> str:
    """Short, deterministic, human-friendly ID derived from the rounded
    feature vector. Explicitly a project-level behavioral identifier."""
    rounded = np.round(feature_vector.fillna(0).to_numpy(dtype=float), 3)
    digest = hashlib.sha256(rounded.tobytes()).hexdigest().upper()
    return f"{digest[0:2]}-{digest[2:4]}-{digest[4:6]}"


def build_fingerprints(features: pd.DataFrame) -> Dict[str, dict]:
    """Build a fingerprint dict per device (indexed by src_ip in `features`).

    Returns: { src_ip: { "fingerprint_id": str, "bars": {label: pct}, "raw": {feat: value} } }
    """
    if features is None or features.empty:
        return {}

    normalized = pd.DataFrame(index=features.index)
    for feat in FINGERPRINT_DISPLAY_FEATURES:
        if feat in features.columns:
            normalized[feat] = _normalize_series(features[feat])

    fingerprints = {}
    for src_ip in features.index:
        bars = {
            FINGERPRINT_DISPLAY_FEATURES[feat]: round(float(normalized.loc[src_ip, feat]), 1)
            for feat in FINGERPRINT_DISPLAY_FEATURES
            if feat in normalized.columns
        }
        fp_id = generate_fingerprint_id(features.loc[src_ip])
        fingerprints[src_ip] = {
            "fingerprint_id": fp_id,
            "bars": bars,
            "raw": features.loc[src_ip].to_dict(),
        }
    return fingerprints


def bar_string(pct: float, width: int = 10) -> str:
    """Render a percentage as a block-character progress bar, e.g. '████████  82%'."""
    pct = max(0.0, min(100.0, pct))
    filled = round((pct / 100.0) * width)
    return "█" * filled + "░" * (width - filled) + f"  {pct:.0f}%"
