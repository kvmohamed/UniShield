# UniShield — Demo Guide

## Quick Demo (Local)

### 1. Start the API
```bash
cd unishield
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -r requirements.txt
pip install -e .
python -m unishield.main
```

### 2. Verify Health
```bash
curl http://127.0.0.1:8000/health
```

### 3. View API Documentation
Open http://127.0.0.1:8000/docs in your browser.

### 4. Run Tests
```bash
pytest tests/unit/ -v
```

## Offline Demo
The system runs entirely offline. No internet access is required after
initial setup. All detection models run locally.

## Docker Demo
```bash
docker-compose up -d
# API: http://localhost:8000
# Dashboard: http://localhost:8501
```

## What to Show
1. Health endpoint confirming security constraints
2. API documentation with all endpoints
3. Test suite passing (56+ tests)
4. Configuration with immutable security constraints
5. Flow and alert schema validation
