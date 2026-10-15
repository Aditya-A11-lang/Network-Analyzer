"""SQLite persistence for analysis history, device fingerprints, and
baselines. Stores metadata and derived statistics only - never packet
payloads, passwords, or cookies."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator, Optional

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
DB_PATH = os.path.join(DATA_DIR, "network_analyzer.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS analysis_history (
    analysis_id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL,               -- 'live' or 'pcap'
    duration REAL,
    packet_count INTEGER,
    total_bytes INTEGER,
    device_count INTEGER,
    anomaly_count INTEGER,
    anomaly_rate REAL,
    risk_score REAL,
    severity TEXT,
    classification TEXT
);

CREATE TABLE IF NOT EXISTS device_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER,
    src_ip TEXT NOT NULL,
    fingerprint_id TEXT NOT NULL,
    features_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analysis_history (analysis_id)
);

CREATE TABLE IF NOT EXISTS baselines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT NOT NULL DEFAULT 'default',
    features_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with get_connection() as conn:
        conn.executescript(SCHEMA)


def save_analysis(
    source: str,
    duration: float,
    packet_count: int,
    total_bytes: float,
    device_count: int,
    anomaly_count: int,
    risk_score: float,
    severity: str,
    classification: str,
) -> int:
    init_db()
    anomaly_rate = (anomaly_count / device_count) if device_count else 0.0
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO analysis_history
               (timestamp, source, duration, packet_count, total_bytes, device_count,
                anomaly_count, anomaly_rate, risk_score, severity, classification)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                source,
                duration,
                packet_count,
                total_bytes,
                device_count,
                anomaly_count,
                anomaly_rate,
                risk_score,
                severity,
                classification,
            ),
        )
        return cur.lastrowid


def save_fingerprints(analysis_id: int, fingerprints: dict) -> None:
    init_db()
    now = datetime.now(timezone.utc).isoformat()
    with get_connection() as conn:
        for src_ip, fp in fingerprints.items():
            conn.execute(
                """INSERT INTO device_fingerprints
                   (analysis_id, src_ip, fingerprint_id, features_json, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (analysis_id, src_ip, fp["fingerprint_id"], json.dumps(fp.get("raw", {})), now),
            )


def save_baseline(features: dict, label: str = "default") -> int:
    init_db()
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO baselines (label, features_json, created_at) VALUES (?, ?, ?)",
            (label, json.dumps(features), datetime.now(timezone.utc).isoformat()),
        )
        return cur.lastrowid


def get_latest_baseline(label: str = "default") -> Optional[dict]:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            "SELECT features_json FROM baselines WHERE label = ? ORDER BY id DESC LIMIT 1",
            (label,),
        ).fetchone()
        if row is None:
            return None
        return json.loads(row["features_json"])


def get_analysis_history(limit: int = 50):
    init_db()
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT * FROM analysis_history ORDER BY analysis_id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_overview_metrics() -> dict:
    init_db()
    with get_connection() as conn:
        row = conn.execute(
            """SELECT
                   COUNT(*) as total_analyses,
                   COALESCE(SUM(packet_count), 0) as total_packets,
                   COALESCE(SUM(total_bytes), 0) as total_bytes,
                   COALESCE(SUM(anomaly_count), 0) as total_anomalies,
                   COALESCE(AVG(risk_score), 0) as average_risk,
                   COALESCE(MAX(device_count), 0) as active_devices
               FROM analysis_history"""
        ).fetchone()
        return dict(row) if row else {}
