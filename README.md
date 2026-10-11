# Threat Detector

A rule-based cybersecurity threat detection platform. It ingests web-server and SSH logs, flags common attacks, stores alerts in SQLite, and shows them on an interactive dashboard.

**Stack:** Python, FastAPI, SQLite, Docker, pytest.

## What it detects

| Rule | Severity | Trigger |
|---|---|---|
| `SQL_INJECTION` | high | UNION SELECT, `' OR 1=1`, `sleep()`, `information_schema`, ... |
| `XSS` | medium | `<script>`, `onerror=`, `javascript:` |
| `PATH_TRAVERSAL` | high | `../`, `/etc/passwd` (URL-decoded twice) |
| `COMMAND_INJECTION` | critical | `;cat`, `\|bash`, `` `id` ``, `$(...)` |
| `SCANNER_USER_AGENT` | medium | sqlmap, nikto, nmap, hydra, ... |
| `SSH_BRUTE_FORCE` | high | 5+ failed SSH logins from one IP in 60s |
| `BRUTE_FORCE_SUCCESS` | critical | successful SSH login right after repeated failures |
| `WEB_LOGIN_BRUTE_FORCE` | high | 10+ failed POSTs to a login URL in 60s |
| `DIRECTORY_SCAN` | medium | 15+ distinct 404 paths from one IP in 60s |
| `REQUEST_FLOOD` | high | 100+ requests from one IP in 10s |

Thresholds live in `THRESHOLDS` and signatures in `SIGNATURES` in `app.py` (rules section).

## Supported log formats
- Apache / Nginx combined access logs
- OpenSSH auth logs (`Failed password` / `Accepted password`)

## Run locally
```bash
pip install -r requirements.txt pytest httpx
uvicorn app:app --reload
```
Open http://localhost:8000 and click **Load demo data**, or upload your own log file.

## Run with Docker
```bash
docker build -t threat-detector . && docker run -p 8000:8000 -v detector-data:/data threat-detector
```
Alerts persist in the `detector-data` volume.

## Tests
```bash
pytest -q
```

## API
| Method | Path | Purpose |
|---|---|---|
| POST | `/api/logs` | Analyze logs: `{"logs": "<raw text>"}` |
| POST | `/api/demo` | Generate and analyze sample attack traffic |
| GET | `/api/alerts?severity=&q=&limit=` | List alerts |
| GET | `/api/stats` | Counts by severity, rule, IP, and timeline |
| DELETE | `/api/alerts` | Clear all alerts |
| GET | `/health` | Health check |

## Limitations
Signature and threshold rules catch known patterns and will miss novel attacks, and legitimate traffic can occasionally trip them. Use it for learning and as a first-pass filter, not as a replacement for a SIEM or WAF. Add authentication before exposing it to a network.
