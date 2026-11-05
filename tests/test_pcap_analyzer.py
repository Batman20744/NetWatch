
from pathlib import Path

from scapy.all import IP, TCP, wrpcap

from src.pcap_analyzer import analyze_pcap


def test_pcap_packets_are_aggregated(tmp_path: Path):
    pcap_file = tmp_path / "test.pcap"

    packets = [
        IP(src="192.168.1.10", dst="192.168.1.1")
        / TCP(sport=5000 + i, dport=80)
        for i in range(10)
    ]

    wrpcap(str(pcap_file), packets)

    traffic = analyze_pcap(pcap_file)

    assert len(traffic) == 1
    assert traffic.iloc[0]["source_ip"] == "192.168.1.10"
    assert traffic.iloc[0]["destination_port"] == 80
    assert traffic.iloc[0]["packet_count"] == 10
    assert traffic.iloc[0]["bytes_sent"] == sum(
        len(packet) for packet in packets
    )


def test_missing_pcap_file_raises_error(tmp_path: Path):
    missing_file = tmp_path / "missing.pcap"

    try:
        analyze_pcap(missing_file)
        assert False, "Expected FileNotFoundError"
    except FileNotFoundError:
        pass
