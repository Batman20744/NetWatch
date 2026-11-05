
import sqlite3
from pathlib import Path

DATABASE_PATH = Path(__file__).resolve().parent.parent / "data" / "netwatch.db"


def get_connection():
    """Open a connection to the NetWatch SQLite database."""
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")

    return connection


def initialize_database():
    """Create the analysis history and alert tables if needed."""
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                analysis_type TEXT NOT NULL,
                total_records INTEGER NOT NULL DEFAULT 0,
                alert_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id INTEGER NOT NULL,
                timestamp TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                destination_port INTEGER,
                packet_count INTEGER,
                bytes_sent INTEGER,
                alert_reasons TEXT,
                severity TEXT,
                FOREIGN KEY (analysis_id)
                    REFERENCES analyses(id)
                    ON DELETE CASCADE
            )
            """
        )


def save_analysis(filename, analysis_type, total_records, alerts):
    """Save one analysis and its detected alerts; return its ID."""
    initialize_database()

    alert_records = alerts.to_dict(orient="records")

    with get_connection() as connection:
        cursor = connection.execute(
            """
            INSERT INTO analyses (
                filename,
                analysis_type,
                total_records,
                alert_count
            )
            VALUES (?, ?, ?, ?)
            """,
            (
                str(filename),
                str(analysis_type),
                int(total_records),
                len(alert_records),
            ),
        )

        analysis_id = cursor.lastrowid

        connection.executemany(
            """
            INSERT INTO alerts (
                analysis_id,
                timestamp,
                source_ip,
                destination_ip,
                protocol,
                destination_port,
                packet_count,
                bytes_sent,
                alert_reasons,
                severity
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    analysis_id,
                    str(alert.get("timestamp", "")),
                    str(alert.get("source_ip", "")),
                    str(alert.get("destination_ip", "")),
                    str(alert.get("protocol", "")),
                    int(alert["destination_port"])
                    if alert.get("destination_port") is not None
                    else None,
                    int(alert["packet_count"])
                    if alert.get("packet_count") is not None
                    else None,
                    int(alert["bytes_sent"])
                    if alert.get("bytes_sent") is not None
                    else None,
                    str(alert.get("alert_reasons", "")),
                    str(alert.get("severity", "Medium")),
                )
                for alert in alert_records
            ],
        )

    return analysis_id


def get_analysis_history(limit=50):
    """Return the most recent analyses first."""
    if limit < 1:
        raise ValueError("limit must be at least 1")

    initialize_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM analyses
            ORDER BY id DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()

    return [dict(row) for row in rows]


def get_analysis_alerts(analysis_id):
    """Return the saved alerts for one analysis."""
    initialize_database()

    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT *
            FROM alerts
            WHERE analysis_id = ?
            ORDER BY id
            """,
            (int(analysis_id),),
        ).fetchall()

    return [dict(row) for row in rows]
