import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src import database


def test_analysis_history_persists_after_database_reinitialization(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(database, "DB_PATH", str(tmp_path / "network_analyzer.db"))

    analysis_id = database.save_analysis(
        source="pcap",
        duration=12.5,
        packet_count=40,
        total_bytes=4096,
        device_count=3,
        anomaly_count=1,
        risk_score=42,
        severity="Moderate",
        classification="Review",
        actor="analyst",
    )

    database.init_db()
    history = database.get_analysis_history()

    assert len(history) == 1
    assert history[0]["analysis_id"] == analysis_id
    assert history[0]["packet_count"] == 40
    assert history[0]["actor"] == "analyst"
