# UniShield — Demo Guide

> The full scripted demonstration is rebuilt in Phase 10. This guide covers what
> works today.

## Quick Demo (Local)

### 1. Install and start the API
```bash
py -3.12 -m venv .venv          # Linux/macOS: python3.12 -m venv .venv
.venv\Scripts\activate          # Linux/macOS: source .venv/bin/activate
pip install -r requirements-dev.txt
pip install --no-deps -e .
python -m unishield.main
```

### 2. Verify Health
```bash
curl http://127.0.0.1:8000/health
```

### 3. Open the Dashboard and API Docs
- Dashboard: http://127.0.0.1:8000/dashboard
- API docs: http://127.0.0.1:8000/docs

### 4. Run the synthetic demo
Click **Run Demo Analysis** on the dashboard, or:
```bash
curl -X POST "http://127.0.0.1:8000/replay/demo?normal=300&ddos=400&scan=150&beacon=30&exfil=40"
```
Currently this produces a small number of scan and exfiltration alerts; DDoS and beaconing
alerts do not appear in the demo yet (audit defects D4, D10).

### 5. Replay sample traffic files
```bash
python scripts/make_samples.py
curl -X POST "http://127.0.0.1:8000/replay/start?file_path=data/samples/sample.pcap"
curl http://127.0.0.1:8000/replay/status
```
The sample PCAP (26 packets) is grouped into 10 flows; `/replay/status` shows the
reader, sessionizer and normaliser counts. It is too short to fill a 10-second
analysis window, so it produces no alerts yet (audit defect D1, fixed in Phase 4).

### 6. Run Tests
```bash
python -m pytest tests/ -q
```

## Offline Demo
After installation the system runs without Internet access. The dashboard requests a web
font from Google Fonts and falls back to system fonts when offline.

## Docker Demo
```bash
docker compose up -d --build
# API and dashboard: http://127.0.0.1:8000/dashboard
```

## What to Show
1. Health endpoint confirming security constraints
2. API documentation with all endpoints
3. Test suite passing
4. Configuration with immutable security constraints
5. Flow and alert schema validation
