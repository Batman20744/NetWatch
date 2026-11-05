
import pandas as pd

HIGH_PACKET_THRESHOLD = 400
HIGH_BYTES_THRESHOLD = 500_000
SENSITIVE_PORTS = {23, 445, 3389}

PORT_SCAN_THRESHOLD = 5
PORT_SCAN_WINDOW_SECONDS = 60

BURST_THRESHOLD = 20
BURST_WINDOW_SECONDS = 10


def detect_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """Detect high traffic, high data volume, sensitive ports,
    multi-port scans, and traffic bursts.
    """

    required_columns = {
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "destination_port",
        "packet_count",
        "bytes_sent",
    }

    missing = required_columns - set(df.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    result = df.copy().reset_index(drop=True)

    for column in ("destination_port", "packet_count", "bytes_sent"):
        result[column] = pd.to_numeric(result[column], errors="raise")

    # Convert Unix timestamps or text timestamps to UTC.
    if pd.api.types.is_numeric_dtype(result["timestamp"]):
        timestamps = pd.to_datetime(
            result["timestamp"],
            unit="s",
            errors="raise",
            utc=True,
        )
    else:
        timestamps = pd.to_datetime(
            result["timestamp"],
            format="mixed",
            errors="raise",
            utc=True,
        )

    result["alert_reasons"] = ""

    # Existing detection rules.
    high_packets = result["packet_count"] > HIGH_PACKET_THRESHOLD
    high_bytes = result["bytes_sent"] > HIGH_BYTES_THRESHOLD
    sensitive_port = result["destination_port"].isin(SENSITIVE_PORTS)

    # New detection rules.
    possible_scan = pd.Series(False, index=result.index)
    possible_burst = pd.Series(False, index=result.index)

    timed = result.assign(_timestamp=timestamps)

    for _, group in timed.groupby("source_ip", sort=False):
        group = group.sort_values("_timestamp")

        ports = group["destination_port"].tolist()
        times = group["_timestamp"].tolist()
        indexes = group.index.tolist()

        # Detect five or more distinct destination ports
        # within a rolling 60-second window.
        port_counts = {}
        scan_left = 0

        for right, port in enumerate(ports):
            port_counts[port] = port_counts.get(port, 0) + 1
            current_time = times[right]

            while (
                current_time - times[scan_left]
            ).total_seconds() > PORT_SCAN_WINDOW_SECONDS:
                old_port = ports[scan_left]
                port_counts[old_port] -= 1

                if port_counts[old_port] == 0:
                    del port_counts[old_port]

                scan_left += 1

            if len(port_counts) >= PORT_SCAN_THRESHOLD:
                possible_scan.loc[indexes[scan_left:right + 1]] = True

        # Detect 20 or more traffic records within a rolling
        # 10-second window for the same source IP.
        burst_left = 0

        for right, current_time in enumerate(times):
            while (
                current_time - times[burst_left]
            ).total_seconds() > BURST_WINDOW_SECONDS:
                burst_left += 1

            window_count = right - burst_left + 1

            if window_count >= BURST_THRESHOLD:
                possible_burst.loc[indexes[burst_left:right + 1]] = True

    # Add alert reasons without removing existing detection features.
    result.loc[high_packets, "alert_reasons"] += "High packet count; "
    result.loc[high_bytes, "alert_reasons"] += "High data volume; "
    result.loc[sensitive_port, "alert_reasons"] += (
        "Sensitive destination port; "
    )
    result.loc[possible_scan, "alert_reasons"] += (
        "Possible multi-port scan; "
    )
    result.loc[possible_burst, "alert_reasons"] += (
        "Possible traffic burst; "
    )

    # Return only records that triggered at least one rule.
    alerts = result[result["alert_reasons"] != ""].copy()

    # Preserve existing severity behavior.
    alerts["severity"] = "Medium"

    high_volume = high_packets & high_bytes
    alerts.loc[high_volume.loc[alerts.index], "severity"] = "High"

    return alerts
