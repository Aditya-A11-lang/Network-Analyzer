"""Lightweight unsupervised anomaly detection using Scikit-learn's
Isolation Forest over numerical per-device traffic features.

No deep learning, no external AI API. The model is persisted with
joblib so a baseline, once trained, can be reused across sessions.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from .feature_engineering import FEATURE_COLUMNS
from .utils import get_logger

logger = get_logger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
MODEL_PATH = os.path.join(MODEL_DIR, "isolation_forest.joblib")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.joblib")

MIN_TRAINING_ROWS = 3  # minimum device-observations needed to fit a model


class ModelUnavailableError(Exception):
    """Raised when no trained model exists and one cannot be loaded."""


class InsufficientDataError(Exception):
    """Raised when there isn't enough traffic variation to train/predict."""


@dataclass
class AnomalyResult:
    src_ip: str
    is_anomalous: bool
    anomaly_score: float  # 0-100, higher = more anomalous
    raw_score: float      # underlying isolation forest decision_function output


def _prepare_matrix(features: pd.DataFrame) -> pd.DataFrame:
    cols = [c for c in FEATURE_COLUMNS if c in features.columns]
    matrix = features[cols].replace([np.inf, -np.inf], 0).fillna(0)
    return matrix


def train_anomaly_model(features: pd.DataFrame, contamination: float = 0.15) -> IsolationForest:
    """Fit a new Isolation Forest on the given per-device feature matrix
    and persist it (with its scaler) to disk. Intended to be called on a
    representative sample of *normal* baseline traffic."""
    matrix = _prepare_matrix(features)

    if matrix.shape[0] < MIN_TRAINING_ROWS:
        raise InsufficientDataError(
            f"At least {MIN_TRAINING_ROWS} device-observations are needed to train a "
            f"baseline model; got {matrix.shape[0]}."
        )
    if matrix.shape[1] == 0:
        raise InsufficientDataError("No usable numerical features were found for training.")
    if matrix.std().sum() == 0:
        raise InsufficientDataError("Traffic shows no feature variation; cannot train a model.")

    scaler = StandardScaler()
    scaled = scaler.fit_transform(matrix)

    model = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        random_state=42,
    )
    model.fit(scaled)

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    logger.info("Trained and saved anomaly model on %d rows.", matrix.shape[0])
    return model


def load_anomaly_model() -> tuple[IsolationForest, StandardScaler]:
    """Load a previously trained model + scaler from disk."""
    if not (os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)):
        raise ModelUnavailableError(
            "No trained anomaly model was found. Analyze a baseline traffic sample first."
        )
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
    except Exception as exc:
        raise ModelUnavailableError(f"The saved anomaly model could not be loaded: {exc}") from exc
    return model, scaler


def calculate_anomaly_score(raw_decision_value: float) -> float:
    """Map an Isolation Forest decision_function value (roughly -0.5..0.5,
    lower = more anomalous) onto an intuitive 0-100 anomaly score where
    higher = more anomalous."""
    # decision_function: positive = inlier, negative = outlier.
    # Squash with a logistic-like transform centered at 0.
    squashed = 1.0 / (1.0 + np.exp(raw_decision_value * 8))
    return float(np.clip(squashed * 100.0, 0.0, 100.0))


def predict_anomaly(
    features: pd.DataFrame,
    model: Optional[IsolationForest] = None,
    scaler: Optional[StandardScaler] = None,
) -> list[AnomalyResult]:
    """Run anomaly prediction for each device in `features`. If model/scaler
    are not provided, attempts to load the persisted ones from disk."""
    matrix = _prepare_matrix(features)
    if matrix.empty:
        raise InsufficientDataError("No devices with usable features were found to analyze.")

    if model is None or scaler is None:
        model, scaler = load_anomaly_model()

    scaled = scaler.transform(matrix)
    predictions = model.predict(scaled)          # 1 = inlier, -1 = outlier
    decision_values = model.decision_function(scaled)

    results = []
    for src_ip, pred, raw in zip(matrix.index, predictions, decision_values):
        results.append(
            AnomalyResult(
                src_ip=src_ip,
                is_anomalous=bool(pred == -1),
                anomaly_score=calculate_anomaly_score(float(raw)),
                raw_score=float(raw),
            )
        )
    return results


def model_exists() -> bool:
    return os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH)
