
import pandas as pd
import pytest

from src.detector import detect_anomalies


def make_traffic(ports, timestamps=None):
    """Create sample traffic records for detector tests."""
    if timestamps is None:
        timestamps = [
            f"2026-10-19 09:00:{i:02d}"
            for i in range(len(ports))
        ]

    return pd.DataFrame(
        [
            {
                "timestamp": timestamp,
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.100",
                "protocol": "TCP",
                "destination_port": port,
                "packet_count": 10,
                "bytes_sent": 1000,
            }
            for port, timestamp in zip(ports, timestamps)
        ]
    )


def test_high_packet_count_is_flagged():
    traffic = make_traffic([80])
    traffic.loc[0, "packet_count"] = 500

    alerts = detect_anomalies(traffic)

    assert len(alerts) == 1
    assert "High packet count" in alerts.iloc[0]["alert_reasons"]


def test_high_data_volume_is_flagged():
    traffic = make_traffic([80])
    traffic.loc[0, "bytes_sent"] = 600_000

    alerts = detect_anomalies(traffic)

    assert len(alerts) == 1
    assert "High data volume" in alerts.iloc[0]["alert_reasons"]


def test_sensitive_destination_port_is_flagged():
    traffic = make_traffic([445])

    alerts = detect_anomalies(traffic)

    assert len(alerts) == 1
    assert "Sensitive destination port" in alerts.iloc[0]["alert_reasons"]


def test_normal_traffic_does_not_trigger_alerts():
    traffic = make_traffic(
        [80] * 5,
        [
            "2026-10-19 09:00:00",
            "2026-10-19 09:00:03",
            "2026-10-19 09:00:06",
            "2026-10-19 09:00:09",
            "2026-10-19 09:00:12",
        ],
    )

    alerts = detect_anomalies(traffic)

    assert alerts.empty


def test_multiple_destination_ports_are_flagged():
    timestamps = [
        (
            pd.Timestamp("2026-10-19 09:00:00")
            + pd.Timedelta(seconds=i)
        ).isoformat()
        for i in range(5)
    ]

    traffic = make_traffic([21, 22, 23, 80, 443], timestamps)

    alerts = detect_anomalies(traffic)

    scan_alerts = alerts[
        alerts["alert_reasons"].str.contains(
            "Possible multi-port scan",
            regex=False,
        )
    ]

    assert len(scan_alerts) == 5


def test_port_scan_outside_window_does_not_trigger_scan_rule():
    timestamps = [
        (
            pd.Timestamp("2026-10-19 09:00:00")
            + pd.Timedelta(seconds=61 * i)
        ).isoformat()
        for i in range(5)
    ]

    traffic = make_traffic([21, 22, 23, 80, 443], timestamps)

    alerts = detect_anomalies(traffic)

    assert not alerts["alert_reasons"].str.contains(
        "Possible multi-port scan",
        regex=False,
    ).any()


def test_high_packet_and_data_volume_gets_high_severity():
    traffic = make_traffic([80])
    traffic.loc[0, "packet_count"] = 500
    traffic.loc[0, "bytes_sent"] = 600_000

    alerts = detect_anomalies(traffic)

    assert len(alerts) == 1
    assert alerts.iloc[0]["severity"] == "High"


def test_missing_required_column_raises_error():
    traffic = make_traffic([80])
    traffic = traffic.drop(columns=["source_ip"])

    with pytest.raises(ValueError, match="Missing required columns"):
        detect_anomalies(traffic)


def test_traffic_burst_is_flagged():
    timestamps = [
        (
            pd.Timestamp("2026-10-19 09:00:00")
            + pd.Timedelta(milliseconds=250 * i)
        ).isoformat()
        for i in range(20)
    ]

    traffic = make_traffic([80] * 20, timestamps)

    alerts = detect_anomalies(traffic)

    burst_alerts = alerts[
        alerts["alert_reasons"].str.contains(
            "Possible traffic burst",
            regex=False,
        )
    ]

    assert len(burst_alerts) == 20


def test_normal_traffic_does_not_trigger_burst_rule():
    traffic = make_traffic(
        [80] * 5,
        [
            "2026-10-19 09:00:00",
            "2026-10-19 09:00:03",
            "2026-10-19 09:00:06",
            "2026-10-19 09:00:09",
            "2026-10-19 09:00:12",
        ],
    )

    alerts = detect_anomalies(traffic)

    assert not alerts["alert_reasons"].str.contains(
        "Possible traffic burst",
        regex=False,
    ).any()


def test_traffic_outside_burst_window_does_not_trigger_burst_rule():
    timestamps = [
        (
            pd.Timestamp("2026-10-19 09:00:00")
            + pd.Timedelta(seconds=11 * i)
        ).isoformat()
        for i in range(20)
    ]

    traffic = make_traffic([80] * 20, timestamps)

    alerts = detect_anomalies(traffic)

    assert not alerts["alert_reasons"].str.contains(
        "Possible traffic burst",
        regex=False,
    ).any()
