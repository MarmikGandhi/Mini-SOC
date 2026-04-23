# Mini SOC Command Center

Mini SOC Command Center is a lightweight Flask-based security dashboard for demonstrating core Security Operations Center workflows in one place. It lets you monitor network traffic, generate simple IDS-style alerts, run a basic web exposure scan, and encrypt uploaded artifacts from a single web interface.

## Features

- Network monitoring with `auto`, `live`, and `simulated` capture modes
- Basic threat detection for traffic spikes, exposed sensitive services, and ICMP reconnaissance
- Dashboard metrics for alerts, packet activity, scan history, and recent events
- Lightweight web target scanning for missing security headers, reflected input, and possible CSRF gaps
- File encryption using Fernet for protecting collected artifacts
- Persistent JSON-line logging for alerts and event history

## Tech Stack

- Python
- Flask
- Scapy
- Requests
- Cryptography
- HTML, CSS, JavaScript

## Project Structure

```text
mini_soc/
|-- app.py
|-- requirements.txt
|-- modules/
|   |-- crypto.py
|   |-- ids.py
|   |-- logger.py
|   |-- packet_sniffer.py
|   `-- vuln_scanner.py
|-- static/
|   |-- script.js
|   `-- style.css
|-- templates/
|   `-- index.html
|-- logs/
`-- uploads/
```

## How It Works

### 1. Monitoring

The dashboard can trigger a monitoring run through `/api/monitor/run`.

- `auto` mode tries live packet capture first and falls back to generated demo traffic
- `live` mode attempts a short Scapy capture
- `simulated` mode generates sample packets for demo use

Captured or simulated packets are checked for:

- repeated traffic bursts from the same source
- ingress traffic hitting sensitive services such as `SSH` or `RDP`
- ICMP probing behavior

Generated alerts are stored in `logs/alerts.log`, and monitoring activity is recorded in `logs/events.log`.

### 2. Web Scanning

The scanner sends a lightweight request to a provided target and checks for:

- missing browser security headers
- simple reflected-input behavior
- possible CSRF gaps when forms are present

This is a demo-oriented exposure check, not a full vulnerability scanner.

### 3. Artifact Encryption

Uploaded files are encrypted with Fernet and written to the `logs/` directory as `.bin` files. The encryption key is stored locally at `logs/fernet.key`.

## Installation

### Prerequisites

- Python 3.10+ recommended
- `pip`

### Setup

```bash
pip install -r requirements.txt
```

## Running the App

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000/
```

## API Endpoints

### `GET /`

Serves the dashboard UI.

### `GET /api/overview`

Returns aggregated dashboard metrics, alert summaries, and recent events.

### `POST /api/monitor/run`

Runs packet monitoring.

Example request body:

```json
{
  "mode": "auto"
}
```

Supported modes:

- `auto`
- `live`
- `simulated`

### `GET /api/alerts`

Returns recent stored alerts.

### `GET /api/events`

Returns recent logged system events.

### `POST /api/scan`

Runs a lightweight web scan.

Example request body:

```json
{
  "url": "https://example.com"
}
```

### `POST /api/encrypt`

Accepts a file upload and returns encryption metadata.

## Notes

- Live packet sniffing may require elevated privileges depending on your OS and network setup.
- If live capture is unavailable, the app falls back to simulated traffic so the dashboard remains usable.
- The scanner is intentionally lightweight and should only be used for learning, demos, or internal prototypes.
- Encrypted files and logs are stored locally in the `logs/` directory.

## Future Improvements

- Add authentication and user roles
- Support decrypting stored artifacts
- Add richer IDS rules and protocol analysis
- Persist data in a database instead of flat log files
- Add tests and production configuration

## Author

Developed by **Marmik Gandhi** Feel free to connect:   
- GitHub: [@MarmikGandhi](https://github.com/MarmikGandhi)
- Email: [marmikgandhi@gamil.com](mailto:marmikgandhi@gamil.com)
- LinkedIn: [marmik-gandhi](https://www.linkedin.com/in/marmik-gandhi/)

## License

Add a license file if you plan to distribute this project publicly.
