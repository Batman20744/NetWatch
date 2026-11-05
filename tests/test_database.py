
import pandas as pd
import pytest

import src.database as database


@pytest.fixture
def test_db(tmp_path, monkeypatch):
    """Use a temporary database so tests do not modify real history."""
    test_path = tmp_path / "test_netwatch.db"

    monkeypatch.setattr(database, "DATABASE_PATH", test_path)
    database.initialize_database()

    return test_path


def test_database_initializes(test_db):
    assert test_db.exists()


def test_save_analysis_returns_id(test_db):
    alerts = pd.DataFrame(
        columns=[
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "destination_port",
            "packet_count",
            "bytes_sent",
            "alert_reasons",
            "severity",
        ]
    )

    analysis_id = database.save_analysis(
        filename="sample.pcap",
        analysis_type="PCAP",
        total_records=10,
        alerts=alerts,
    )

    assert analysis_id == 1


def test_analysis_history_is_saved(test_db):
    alerts = pd.DataFrame(columns=["alert_reasons", "severity"])

    database.save_analysis(
        filename="sample.csv",
        analysis_type="CSV",
        total_records=25,
        alerts=alerts,
    )

    history = database.get_analysis_history()

    assert len(history) == 1
    assert history[0]["filename"] == "sample.csv"
    assert history[0]["analysis_type"] == "CSV"
    assert history[0]["total_records"] == 25
    assert history[0]["alert_count"] == 0


def test_alerts_are_saved_and_retrieved(test_db):
    alerts = pd.DataFrame(
        [
            {
                "timestamp": "2026-10-21 10:00:00",
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.100",
                "protocol": "TCP",
                "destination_port": 445,
                "packet_count": 20,
                "bytes_sent": 2000,
                "alert_reasons": "Sensitive destination port; ",
                "severity": "Medium",
            }
        ]
    )

    analysis_id = database.save_analysis(
        filename="test.pcap",
        analysis_type="PCAP",
        total_records=20,
        alerts=alerts,
    )

    saved_alerts = database.get_analysis_alerts(analysis_id)

    assert len(saved_alerts) == 1
    assert saved_alerts[0]["source_ip"] == "192.168.1.50"
    assert saved_alerts[0]["destination_port"] == 445
    assert saved_alerts[0]["severity"] == "Medium"


def test_history_returns_newest_analysis_first(test_db):
    alerts = pd.DataFrame(columns=["alert_reasons", "severity"])

    database.save_analysis("first.csv", "CSV", 5, alerts)
    database.save_analysis("second.csv", "CSV", 10, alerts)

    history = database.get_analysis_history()

    assert len(history) == 2
    assert history[0]["filename"] == "second.csv"
    assert history[1]["filename"] == "first.csv"


def test_history_limit_must_be_positive(test_db):
    with pytest.raises(ValueError, match="limit must be at least 1"):
        database.get_analysis_history(limit=0)
