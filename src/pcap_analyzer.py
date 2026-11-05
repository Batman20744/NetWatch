
from pathlib import Path

import pandas as pd
from scapy.all import IP, TCP, UDP, rdpcap


def analyze_pcap(pcap_file: Path) -> pd.DataFrame:
    """Convert a saved PCAP file into aggregated traffic records."""

    pcap_file = Path(pcap_file)

    if not pcap_file.is_file():
        raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

    packets = rdpcap(str(pcap_file))
    records = []

    for packet in packets:
        if IP not in packet:
            continue

        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = "OTHER"
        destination_port = 0

        if TCP in packet:
            protocol = "TCP"
            destination_port = int(packet[TCP].dport)
        elif UDP in packet:
            protocol = "UDP"
            destination_port = int(packet[UDP].dport)

        records.append({
            "timestamp": float(packet.time),
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "protocol": protocol,
            "destination_port": destination_port,
            "packet_count": 1,
            "bytes_sent": len(packet),
        })

    columns = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "destination_port",
        "packet_count",
        "bytes_sent",
    ]

    if not records:
        return pd.DataFrame(columns=columns)

    traffic = pd.DataFrame(records)

    # Aggregate packets by source, destination, protocol, and port.
    # This makes packet counts and byte totals useful for detection.
    traffic = (
        traffic.groupby(
            [
                "source_ip",
                "destination_ip",
                "protocol",
                "destination_port",
            ],
            as_index=False,
        )
        .agg(
            timestamp=("timestamp", "min"),
            packet_count=("packet_count", "sum"),
            bytes_sent=("bytes_sent", "sum"),
        )
    )

    return traffic[columns]
