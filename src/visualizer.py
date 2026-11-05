
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import pandas as pd


def create_traffic_chart(
    traffic: pd.DataFrame,
    output_file: Path,
) -> None:
    """Create a chart showing total bytes sent by each source IP."""

    required_columns = {"source_ip", "bytes_sent"}
    missing = required_columns - set(traffic.columns)

    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    summary = traffic.groupby("source_ip")["bytes_sent"].sum()
    summary = summary.sort_values(ascending=False)

    output_file.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=(9, 5))
    summary.plot(kind="bar", ax=ax)

    ax.set_title("NetWatch: Network Traffic by Source IP")
    ax.set_xlabel("Source IP")
    ax.set_ylabel("Total Bytes Sent")
    ax.tick_params(axis="x", labelrotation=35)

    fig.tight_layout()
    fig.savefig(output_file, dpi=150)
    plt.close(fig)
