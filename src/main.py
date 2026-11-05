
from pathlib import Path
import argparse

import pandas as pd

from detector import detect_anomalies
from visualizer import create_traffic_chart
from pcap_analyzer import analyze_pcap


def main():
    project_root = Path(__file__).resolve().parent.parent

    parser = argparse.ArgumentParser(
        description="NetWatch: Network Traffic Anomaly Detector"
    )
    parser.add_argument(
        "--pcap",
        type=str,
        help="Path to a PCAP file to analyze instead of the sample CSV",
    )
    args = parser.parse_args()

    if args.pcap:
        data_file = Path(args.pcap).expanduser()
        if not data_file.is_absolute():
            data_file = project_root / data_file

        report_name = "pcap_anomaly_report.csv"
        chart_name = "pcap_traffic_chart.png"
        input_type = "PCAP"
    else:
        data_file = project_root / "data" / "sample_traffic.csv"
        report_name = "anomaly_report.csv"
        chart_name = "traffic_chart.png"
        input_type = "CSV"

    report_file = project_root / "reports" / report_name
    chart_file = project_root / "reports" / chart_name

    print("=" * 50)
    print("       NetWatch: Traffic Anomaly Detector")
    print("=" * 50)
    print(f"Input type: {input_type}")

    try:
        if args.pcap:
            traffic = analyze_pcap(data_file)
        else:
            traffic = pd.read_csv(data_file)

        alerts = detect_anomalies(traffic)

        report_file.parent.mkdir(parents=True, exist_ok=True)
        alerts.to_csv(report_file, index=False)
        create_traffic_chart(traffic, chart_file)

        print(f"Traffic records analysed: {len(traffic)}")
        print(f"Alerts generated: {len(alerts)}")
        print(f"CSV report saved to: {report_file}")
        print(f"Traffic chart saved to: {chart_file}")

        if alerts.empty:
            print("\nNo records matched the configured rules.")
        else:
            print("\nDetected alerts:")
            print(
                alerts[
                    [
                        "source_ip",
                        "destination_port",
                        "packet_count",
                        "bytes_sent",
                        "severity",
                        "alert_reasons",
                    ]
                ].to_string(index=False)
            )

    except (OSError, ValueError, pd.errors.ParserError) as error:
        print(f"Error: {error}")


if __name__ == "__main__":
    main()
