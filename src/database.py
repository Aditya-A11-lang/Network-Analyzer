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
    actor TEXT,
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

CREATE TABLE IF NOT EXISTS local_accounts (
    username TEXT PRIMARY KEY COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    full_name TEXT NOT NULL DEFAULT '',
    role TEXT NOT NULL CHECK (role IN ('user', 'admin')),
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    last_login TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS iam_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    actor_subject TEXT,
    target_subject TEXT,
    action TEXT NOT NULL,
    details TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS user_preferences (
    username TEXT NOT NULL COLLATE NOCASE,
    preference_key TEXT NOT NULL,
    preference_value TEXT NOT NULL,
    PRIMARY KEY (username, preference_key),
    FOREIGN KEY (username) REFERENCES local_accounts (username)
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
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(analysis_history)").fetchall()
        }
        if "actor" not in columns:
            conn.execute("ALTER TABLE analysis_history ADD COLUMN actor TEXT")


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
    actor: Optional[str] = None,
) -> int:
    init_db()
    anomaly_rate = (anomaly_count / device_count) if device_count else 0.0
    with get_connection() as conn:
        cur = conn.execute(
            """INSERT INTO analysis_history
               (timestamp, actor, source, duration, packet_count, total_bytes, device_count,
                anomaly_count, anomaly_rate, risk_score, severity, classification)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                datetime.now(timezone.utc).isoformat(),
                actor,
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


def get_user_theme(username: str) -> str:
    """Return the saved UI theme for a local account, defaulting to Dark."""
    with get_connection() as conn:
        row = conn.execute(
            """SELECT preference_value FROM user_preferences
               WHERE username = ? AND preference_key = 'theme'""",
            (username.strip().casefold(),),
        ).fetchone()
        return row["preference_value"] if row else "Dark"


def set_user_theme(username: str, theme: str) -> None:
    """Persist a validated theme preference for an existing local account."""
    if theme not in {"Light", "Dark", "System Default"}:
        raise ValueError("Theme must be Light, Dark, or System Default.")
    normalized_username = username.strip().casefold()
    with get_connection() as conn:
        account = conn.execute(
            "SELECT 1 FROM local_accounts WHERE username = ?",
            (normalized_username,),
        ).fetchone()
        if account is None:
            raise ValueError("Theme preference requires an existing local account.")
        conn.execute(
            """INSERT INTO user_preferences (username, preference_key, preference_value)
               VALUES (?, 'theme', ?)
               ON CONFLICT(username, preference_key)
               DO UPDATE SET preference_value = excluded.preference_value""",
            (normalized_username, theme),
        )
