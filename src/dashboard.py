
from pathlib import Path
from uuid import uuid4

import pandas as pd
from flask import (
    Flask,
    jsonify,
    render_template,
    request,
    send_file,
)
from werkzeug.utils import secure_filename

# Support package imports and direct script execution.
try:
    from .detector import detect_anomalies
    from .visualizer import create_traffic_chart
    from .pcap_analyzer import analyze_pcap
    from .live_monitor import live_monitor
    from .ip_reputation import check_ip_reputation
    from .database import (
        save_analysis,
        get_analysis_history,
        get_analysis_alerts,
    )
except ImportError:
    from detector import detect_anomalies
    from visualizer import create_traffic_chart
    from pcap_analyzer import analyze_pcap
    from live_monitor import live_monitor
    from ip_reputation import check_ip_reputation
    from database import (
        save_analysis,
        get_analysis_history,
        get_analysis_alerts,
    )


# =====================================================
# PROJECT CONFIGURATION
# =====================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPORTS_DIR = PROJECT_ROOT / "reports"
UPLOADS_DIR = PROJECT_ROOT / "uploads"
DATA_FILE = PROJECT_ROOT / "data" / "sample_traffic.csv"

ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024


# =====================================================
# FLASK APPLICATION
# =====================================================

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static"),
)

app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES


# =====================================================
# FILE VALIDATION
# =====================================================

def allowed_pcap_filename(filename):
    """Check whether a filename has a supported PCAP extension."""
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS


# =====================================================
# LOAD NETWORK TRAFFIC
# =====================================================

def load_traffic(source_type="csv", pcap_path=None):
    """Load traffic from the sample CSV or a saved PCAP file."""

    if source_type == "pcap":

        if not pcap_path:
            raise ValueError("Please provide a PCAP file path.")

        path = Path(pcap_path).expanduser()

        if not path.is_absolute():
            path = PROJECT_ROOT / path

        path = path.resolve()

        if not path.is_relative_to(PROJECT_ROOT.resolve()):
            raise ValueError(
                "PCAP files must be inside the project directory."
            )

        if path.suffix.lower() not in ALLOWED_EXTENSIONS:
            raise ValueError(
                "Only .pcap and .pcapng files are supported."
            )

        if not path.is_file():
            raise FileNotFoundError("PCAP file not found.")

        return analyze_pcap(path)

    if source_type != "csv":
        raise ValueError("Source must be csv or pcap.")

    return pd.read_csv(DATA_FILE)


# =====================================================
# NETWORK ACTIVITY TIMELINE
# FIXED: 10-SECOND UTC BUCKETS
# =====================================================

def build_timeline(traffic, alerts):
    """
    Group traffic records and security alerts
    into 10-second UTC buckets.
    """

    def time_bucket(value):

        if value is None or value == "":
            return None

        try:

            if pd.isna(value):
                return None

            if isinstance(value, (int, float)):

                timestamp = pd.to_datetime(
                    value,
                    unit="s",
                    utc=True,
                    errors="coerce",
                )

            else:

                timestamp = pd.to_datetime(
                    value,
                    utc=True,
                    errors="coerce",
                )

            if pd.isna(timestamp):
                return None

            # FIX: Use 10-second intervals instead of 1 minute.
            return timestamp.floor("10s").isoformat()

        except (TypeError, ValueError, OverflowError):
            return None

    buckets = {}

    # -------------------------------------------------
    # COUNT TRAFFIC RECORDS
    # -------------------------------------------------

    for _, row in traffic.iterrows():

        key = time_bucket(row.get("timestamp"))

        if key is None:
            continue

        bucket = buckets.setdefault(
            key,
            {
                "timestamp": key,
                "traffic_records": 0,
                "alerts": 0,
            },
        )

        bucket["traffic_records"] += 1

    # -------------------------------------------------
    # COUNT SECURITY ALERTS
    # -------------------------------------------------

    for _, row in alerts.iterrows():

        key = time_bucket(row.get("timestamp"))

        if key is None:
            continue

        bucket = buckets.setdefault(
            key,
            {
                "timestamp": key,
                "traffic_records": 0,
                "alerts": 0,
            },
        )

        bucket["alerts"] += 1

    # -------------------------------------------------
    # SORT TIMELINE CHRONOLOGICALLY
    # -------------------------------------------------

    return sorted(
        buckets.values(),
        key=lambda item: item["timestamp"],
    )


# =====================================================
# BUILD DASHBOARD DATA
# =====================================================

def build_dashboard_data(
    source_type="csv",
    pcap_path=None,
    filename=None,
):
    """Analyze traffic, save history, and prepare dashboard data."""

    # Load traffic
    traffic = load_traffic(source_type, pcap_path)

    # Detect anomalies
    alerts = detect_anomalies(traffic)

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    # Select report filename
    report_name = (
        "dashboard_pcap_alerts.csv"
        if source_type == "pcap"
        else "dashboard_alerts.csv"
    )

    # Save alerts
    alerts.to_csv(
        REPORTS_DIR / report_name,
        index=False,
    )

    # Generate traffic chart
    create_traffic_chart(
        traffic,
        REPORTS_DIR / "dashboard_traffic_chart.png",
    )

    # -------------------------------------------------
    # SAVE ANALYSIS TO SQLITE
    # -------------------------------------------------

    if filename:

        analysis_filename = filename

    elif source_type == "pcap" and pcap_path:

        analysis_filename = Path(pcap_path).name

    else:

        analysis_filename = DATA_FILE.name

    analysis_id = save_analysis(
        filename=analysis_filename,
        analysis_type=source_type.upper(),
        total_records=len(traffic),
        alerts=alerts,
    )

    # -------------------------------------------------
    # TRAFFIC DISTRIBUTION
    # -------------------------------------------------

    traffic_by_source = (
        traffic.groupby("source_ip")["bytes_sent"]
        .sum()
        .sort_values(ascending=False)
    )

    # -------------------------------------------------
    # SEVERITY COUNTS
    # -------------------------------------------------

    severity_counts = (
        alerts["severity"].value_counts().to_dict()
        if not alerts.empty
        else {}
    )

    # -------------------------------------------------
    # ALERT TABLE COLUMNS
    # -------------------------------------------------

    alert_columns = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "destination_port",
        "protocol",
        "packet_count",
        "bytes_sent",
        "severity",
        "alert_reasons",
    ]

    # -------------------------------------------------
    # TRAFFIC TABLE COLUMNS
    # -------------------------------------------------

    traffic_columns = [
        "timestamp",
        "source_ip",
        "destination_ip",
        "protocol",
        "destination_port",
        "packet_count",
        "bytes_sent",
    ]

    # Convert alerts to JSON-compatible records
    alert_records = (
        alerts[alert_columns]
        .copy()
        .fillna("")
        .to_dict(orient="records")
    )

    # Convert traffic to JSON-compatible records
    traffic_records = (
        traffic[traffic_columns]
        .copy()
        .fillna("")
        .to_dict(orient="records")
    )

    # Build timeline using 10-second buckets
    timeline = build_timeline(traffic, alerts)

    # -------------------------------------------------
    # RETURN DASHBOARD DATA
    # -------------------------------------------------

    return {
        "analysis_id": analysis_id,

        "source_type": source_type,

        "total_records": int(len(traffic)),

        "total_alerts": int(len(alerts)),

        "high_alerts": int(
            severity_counts.get("High", 0)
        ),

        "medium_alerts": int(
            severity_counts.get("Medium", 0)
        ),

        "traffic_chart": [
            {
                "source_ip": str(ip),
                "bytes_sent": int(total),
            }
            for ip, total in traffic_by_source.items()
        ],

        "alerts": alert_records,

        "traffic": traffic_records,

        "timeline": timeline,
    }


# =====================================================
# MAIN DASHBOARD PAGE
# =====================================================

@app.get("/")
def index():
    return render_template("index.html")


# =====================================================
# DASHBOARD API
# =====================================================

@app.get("/api/dashboard")
def dashboard_api():

    source_type = request.args.get(
        "source",
        "csv",
    ).lower()

    if source_type not in {"csv", "pcap"}:

        return jsonify(
            {"error": "Source must be csv or pcap."}
        ), 400

    try:

        data = build_dashboard_data(
            source_type,
            request.args.get("path"),
        )

        return jsonify(data)

    except (
        OSError,
        ValueError,
        pd.errors.ParserError,
    ) as error:

        return jsonify(
            {"error": str(error)}
        ), 400

    except Exception:

        app.logger.exception(
            "Traffic analysis failed."
        )

        return jsonify(
            {
                "error": (
                    "Could not analyze this capture file."
                )
            }
        ), 400


# =====================================================
# PCAP UPLOAD API
# =====================================================

@app.post("/api/upload-pcap")
def upload_pcap():
    """Save and analyze an uploaded PCAP file."""

    if "file" not in request.files:

        return jsonify(
            {"error": "Choose a PCAP file to upload."}
        ), 400

    uploaded = request.files["file"]

    if not uploaded.filename:

        return jsonify(
            {"error": "No file selected."}
        ), 400

    safe_name = secure_filename(
        uploaded.filename
    )

    if (
        not safe_name
        or not allowed_pcap_filename(safe_name)
    ):

        return jsonify(
            {
                "error": (
                    "Only .pcap and .pcapng files are accepted."
                )
            }
        ), 400

    UPLOADS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    saved_path = UPLOADS_DIR / (
        f"{uuid4().hex}"
        f"{Path(safe_name).suffix.lower()}"
    )

    try:

        uploaded.save(saved_path)

        if saved_path.stat().st_size == 0:

            return jsonify(
                {"error": "The uploaded file is empty."}
            ), 400

        data = build_dashboard_data(
            "pcap",
            str(saved_path),
            filename=safe_name,
        )

        data["upload_name"] = safe_name

        return jsonify(data)

    except (
        OSError,
        ValueError,
        pd.errors.ParserError,
    ) as error:

        return jsonify(
            {"error": str(error)}
        ), 400

    except Exception:

        app.logger.exception(
            "Uploaded capture could not be analyzed."
        )

        return jsonify(
            {
                "error": (
                    "The file is not a readable PCAP/PCAPNG capture."
                )
            }
        ), 400

    finally:

        saved_path.unlink(missing_ok=True)


# =====================================================
# ANALYSIS HISTORY API
# =====================================================

@app.get("/api/history")
def analysis_history_api():
    """Return recent saved analyses."""

    try:

        limit = int(
            request.args.get("limit", 50)
        )

        if limit < 1 or limit > 200:

            return jsonify(
                {
                    "error": (
                        "Limit must be between 1 and 200."
                    )
                }
            ), 400

        history = get_analysis_history(
            limit=limit
        )

        return jsonify(
            {
                "count": len(history),
                "history": history,
            }
        )

    except (ValueError, TypeError) as error:

        return jsonify(
            {"error": str(error)}
        ), 400

    except Exception:

        app.logger.exception(
            "Could not retrieve analysis history."
        )

        return jsonify(
            {
                "error": (
                    "Could not retrieve analysis history."
                )
            }
        ), 500


# =====================================================
# ANALYSIS DETAIL API
# =====================================================

@app.get("/api/history/<int:analysis_id>")
def analysis_detail_api(analysis_id):
    """Return saved alerts for one analysis."""

    try:

        history = get_analysis_history(
            limit=200
        )

        analysis = next(
            (
                item
                for item in history
                if item["id"] == analysis_id
            ),
            None,
        )

        if analysis is None:

            return jsonify(
                {
                    "error": (
                        "Analysis not found in recent history."
                    )
                }
            ), 404

        return jsonify(
            {
                "analysis": analysis,
                "alerts": get_analysis_alerts(
                    analysis_id
                ),
            }
        )

    except Exception:

        app.logger.exception(
            "Could not retrieve saved analysis."
        )

        return jsonify(
            {
                "error": (
                    "Could not retrieve saved analysis."
                )
            }
        ), 500


# =====================================================
# REPORT DOWNLOAD API
# =====================================================

@app.get("/api/report")
def download_report():
    """Download the report for the selected data source."""

    source_type = request.args.get(
        "source",
        "csv",
    ).lower()

    if source_type not in {"csv", "pcap"}:

        return jsonify(
            {"error": "Source must be csv or pcap."}
        ), 400

    report_name = (
        "dashboard_pcap_alerts.csv"
        if source_type == "pcap"
        else "dashboard_alerts.csv"
    )

    report_path = REPORTS_DIR / report_name

    if not report_path.is_file():

        return jsonify(
            {
                "error": (
                    "No report found. Analyze traffic first."
                )
            }
        ), 404

    return send_file(
        report_path,
        mimetype="text/csv",
        as_attachment=True,
        download_name=(
            f"netwatch_{source_type}_alerts.csv"
        ),
    )


# =====================================================
# FILE SIZE ERROR HANDLER
# =====================================================

@app.errorhandler(413)
def upload_too_large(_error):

    return jsonify(
        {
            "error": (
                "File exceeds the 10 MB upload limit."
            )
        }
    ), 413


# =====================================================
# START NETWATCH SERVER
# =====================================================

if __name__ == "__main__":

    UPLOADS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False,
    )


# =====================================================
# LIVE PACKET MONITORING API
# =====================================================

@app.get("/api/live/status")
def live_status_api():
    return jsonify(live_monitor.status())


@app.post("/api/live/start")
def live_start_api():
    payload = request.get_json(silent=True) or {}
    interface = (payload.get("interface") or "").strip() or None
    if interface and len(interface) > 64:
        return jsonify({"error": "Interface name is too long."}), 400
    try:
        return jsonify(live_monitor.start(interface))
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 400


@app.post("/api/live/stop")
def live_stop_api():
    return jsonify(live_monitor.stop())


# =====================================================
# PUBLIC IP REPUTATION API (ABUSEIPDB)
# =====================================================

@app.post("/api/reputation")
def ip_reputation_api():
    payload = request.get_json(silent=True) or {}
    ip_value = payload.get("ip", "")
    try:
        return jsonify(check_ip_reputation(ip_value))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400
    except RuntimeError as error:
        return jsonify({"error": str(error)}), 503
