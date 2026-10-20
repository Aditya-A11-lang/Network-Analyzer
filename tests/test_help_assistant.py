import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.help_assistant import answer_user_query


def test_assistant_answers_live_capture_guidance():
    answer = answer_user_query("How do I start a live capture?")
    assert "local" in answer
    assert "Npcap" in answer


def test_assistant_reports_current_session_status():
    answer = answer_user_query(
        "What is the current status?",
        {
            "active_page": "Overview",
            "has_data": True,
            "packet_count": 42,
            "risk_score": 18.5,
            "classification": "NORMAL",
        },
    )
    assert "42" in answer
    assert "18.5" in answer
    assert "NORMAL" in answer
