import json
from datetime import datetime, timezone
from pathlib import Path


LOG_DIR = Path("logs")
EVENT_LOG = LOG_DIR / "events.log"
ALERT_LOG = LOG_DIR / "alerts.log"

LOG_DIR.mkdir(exist_ok=True)
EVENT_LOG.touch(exist_ok=True)
ALERT_LOG.touch(exist_ok=True)


def _timestamp():
    return datetime.now(timezone.utc).isoformat()


def _append_json_line(path, payload):
    with path.open("a", encoding="utf-8") as file_handle:
        file_handle.write(json.dumps(payload) + "\n")


def _read_json_lines(path):
    records = []
    with path.open("r", encoding="utf-8") as file_handle:
        for line in file_handle:
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def log_event(event_type, details):
    payload = {
        "timestamp": _timestamp(),
        "event_type": event_type,
        "details": details,
    }
    _append_json_line(EVENT_LOG, payload)
    return payload


def store_alert(alert):
    payload = {
        "timestamp": _timestamp(),
        **alert,
    }
    _append_json_line(ALERT_LOG, payload)
    return payload


def get_recent_events(limit=50):
    records = _read_json_lines(EVENT_LOG)
    return list(reversed(records[-limit:]))


def get_stored_alerts(limit=50):
    records = _read_json_lines(ALERT_LOG)
    return list(reversed(records[-limit:]))
