# NetWatch — Traffic Anomaly Detector

NetWatch is a local network-security monitoring dashboard featuring offline CSV/PCAP analysis, explainable anomaly alerts, analysis history, live IPv4 packet capture, and public-IP reputation checks.

## Features
- CSV traffic analysis and PCAP/PCAPNG upload analysis.
- Detection for high packet counts, high data volume, sensitive destination ports, multi-port scans, and traffic bursts.
- Midnight-black and multi-shade-blue dashboard with traffic charts, alert tables, and SQLite analysis history.
- Live packet capture with packet/byte counters and live security events.
- AbuseIPDB reputation lookup for public IPv4/IPv6 addresses.

## Requirements
- Python 3.10 or newer
- Linux recommended for live packet capture (Scapy and libpcap/Npcap permissions required)
- Internet connection and an AbuseIPDB API key for reputation lookup

## Setup (Pop!_OS / Ubuntu)
```bash
cd ~/CyberProjects/netwatch
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

For packet capture, install the system capture dependency if needed:
```bash
sudo apt update
sudo apt install -y libpcap-dev tcpdump
```

## Configure IP reputation
Create an API key at AbuseIPDB, then export it in the same terminal before launching NetWatch:
```bash
export ABUSEIPDB_API_KEY='paste_your_own_key_here'
```
Do not put a real API key in source code or commit it to GitHub. The `.env.example` file is only a placeholder; this project reads the key from the environment and does not automatically load `.env` files.

## Run
```bash
cd ~/CyberProjects/netwatch
source .venv/bin/activate
python -m src.dashboard
```
Open http://127.0.0.1:5000 in your browser.

Live capture may require elevated permissions. For a quick local test, run the application with the required capture permissions on a network you own or are authorized to monitor. Avoid running the entire web application as root on an untrusted network; a production deployment should isolate capture privileges in a dedicated service.

## Test
```bash
pytest -v
```

## API endpoints
- `GET /api/live/status` — live capture state and recent events
- `POST /api/live/start` — start capture; optional JSON `{"interface":"wlan0"}`
- `POST /api/live/stop` — stop capture
- `POST /api/reputation` — AbuseIPDB lookup; JSON `{"ip":"8.8.8.8"}`

## Privacy and limitations
- Live capture inspects IPv4 packet metadata; it does not decrypt application payloads.
- Reputation lookup sends the entered public IP address to AbuseIPDB. Private, loopback, and reserved addresses are rejected.
- Reputation scores are threat-intelligence signals, not proof that an IP is malicious.
- Live detection is a lightweight real-time rule set. The existing offline detector remains the primary batch-analysis engine.
- Use only on networks for which you have explicit authorization.
