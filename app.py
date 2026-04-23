from pathlib import Path

from flask import Flask, jsonify, render_template, request

from modules.crypto import encrypt_file
from modules.ids import build_overview, detect_threats
from modules.logger import (
    get_recent_events,
    get_stored_alerts,
    log_event,
    store_alert,
)
from modules.packet_sniffer import start_sniffing
from modules.vuln_scanner import scan_url

app = Flask(__name__)
UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)


@app.route("/")
def dashboard():
    return render_template("index.html")


@app.get("/api/overview")
def overview():
    events = get_recent_events(limit=100)
    alerts = get_stored_alerts(limit=25)
    return jsonify(build_overview(events, alerts))


@app.post("/api/monitor/run")
def run_monitor():
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode", "auto")

    packets = start_sniffing(mode=mode, packet_count=12)
    alerts = detect_threats(packets)

    for alert in alerts:
        store_alert(alert)
        log_event("alert", alert)

    monitor_event = {
        "message": f"Monitoring run completed in {packets[0]['collection_mode'] if packets else mode} mode.",
        "mode": mode,
        "packet_count": len(packets),
        "generated_alerts": len(alerts),
    }
    log_event("monitor_run", monitor_event)

    return jsonify(
        {
            "packets": packets,
            "alerts": alerts,
            "overview": build_overview(get_recent_events(limit=100), get_stored_alerts(limit=25)),
        }
    )


@app.get("/api/alerts")
def alerts():
    return jsonify(get_stored_alerts(limit=100))


@app.get("/api/events")
def events():
    return jsonify(get_recent_events(limit=100))


@app.post("/api/scan")
def scan():
    payload = request.get_json(silent=True) or {}
    url = (payload.get("url") or "").strip()

    if not url:
        return jsonify({"ok": False, "error": "A target URL is required."}), 400

    result = scan_url(url)
    log_event("scan", {"target": url, "summary": result.get("summary"), "risk_score": result.get("risk_score")})
    return jsonify(result)


@app.post("/api/encrypt")
def encrypt():
    uploaded_file = request.files.get("file")
    if uploaded_file is None or not uploaded_file.filename:
        return jsonify({"ok": False, "error": "Select a file to encrypt."}), 400

    result = encrypt_file(uploaded_file)
    log_event(
        "file_encryption",
        {
            "filename": result["original_name"],
            "output_name": result["encrypted_name"],
            "size_bytes": result["original_size"],
        },
    )
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
