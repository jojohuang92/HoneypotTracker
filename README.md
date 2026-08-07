# Honeypot Tracker

[![CI](https://github.com/jojohuang92/HoneypotTracker/actions/workflows/ci.yml/badge.svg)](https://github.com/jojohuang92/HoneypotTracker/actions/workflows/ci.yml)

**Real-time SSH honeypot attack-intelligence platform.** Deploys alongside a [Cowrie](https://github.com/cowrie/cowrie) honeypot, ingests attacker sessions as they happen, classifies their intent against MITRE ATT&CK, enriches them with geolocation and threat intelligence, and automatically reports malicious IPs and captured malware to public feeds — all surfaced through a live React dashboard.

![Honeypot Tracker dashboard](docs/screenshot.png)

---

## What it does

An SSH honeypot records everything an attacker types, but the raw logs are noise. Honeypot Tracker turns that stream into **attack intelligence**:

- **Ingests** Cowrie's JSON event log in real time and normalizes it into sessions, login attempts, commands, and captured files.
- **Classifies** each command into an intent (reconnaissance, malware deployment, cryptomining, credential theft, persistence, sabotage) and maps it to a **MITRE ATT&CK** technique.
- **Enriches** every source IP with GeoIP location and reputation data, and captured payloads with VirusTotal analysis.
- **Reports** confirmed attackers to AbuseIPDB and malware samples to VirusTotal automatically, with deduplication and an audit trail.
- **Streams** new attacks to the browser over Server-Sent Events for a live view.

## Features

- 🗺️ **Live attack map** — attacker origins plotted and clustered via GeoIP (Leaflet).
- 🎯 **MITRE ATT&CK classification** — every command tagged with an intent and technique ID, shown as a coverage matrix.
- ⚡ **Real-time dashboard** — new sessions appear instantly over SSE; no polling.
- 🔎 **Attacker profiling & session replay** — reconstruct an attacker's full session keystroke-by-keystroke and profile behavior per IP.
- 🛡️ **Automated threat reporting** — background workers report to AbuseIPDB and submit malware to VirusTotal, with dedup windows and a `ReportLog` audit trail.
- 🔌 **SIEM integration** — forwards enriched events to Splunk via HTTP Event Collector.
- 📤 **IOC export** — attacker IPs, malware hashes, and URLs as a plaintext blocklist, CSV, or STIX 2.1 bundle (`/api/export/*`, deterministic STIX ids for consumer-side dedup).
- 🔔 **Push alerts** — [ntfy](https://ntfy.sh) / Discord notifications for high-signal events: successful logins, captured malware, VirusTotal detections, and first-seen countries, with per-key cooldowns to stop alert storms.
- 🧹 **Data retention** — optional pruning of raw events after N days, with per-day aggregates preserved forever so long-term trends survive on small hosts (e.g. a Raspberry Pi SD card).
- 🔐 **Secured admin surface** — header-based admin auth (constant-time comparison) and per-route rate limiting.
- 🐳 **One-command deploy** — `docker compose up` builds and runs backend + dashboard behind nginx; CI runs the full test suite on every push.

## Architecture

```mermaid
flowchart LR
    C[Cowrie honeypot] -->|tail JSON log| I[Log ingestion]
    I --> DB[(SQLite / SQLAlchemy)]
    I --> CL[Intent classifier<br/>MITRE ATT&CK]
    I --> GEO[GeoIP lookup]
    I --> EN[Threat-intel enrichment]
    CL --> DB
    GEO --> DB
    EN --> DB
    DB --> API[FastAPI<br/>REST + SSE]
    API --> UI[React dashboard]
    EN --> AB[AbuseIPDB reporter]
    EN --> VT[VirusTotal reporter]
    I --> SP[Splunk HEC forwarder]
```

**Backend** — Python 3.11, FastAPI, SQLAlchemy 2, SQLite. Log ingestion, the reporting workers, and the retention worker run as async background tasks in the app lifespan. Server-Sent Events push live updates.

**Frontend** — React 19 + TypeScript, Vite 7, TailwindCSS 4. Leaflet for the map, Recharts for charts, TanStack Table for data grids.

### Design decisions

A few choices worth calling out, because they were deliberate:

- **Rule-based classifier over a black-box model.** Intent classification is an ordered set of explicit regex rules (`services/classifier.py`) mapping commands → intent → ATT&CK technique. For a security tool, *explainability* — being able to point at the exact rule that fired — matters more than squeezing out marginal accuracy. (An experimental ML classifier lives in `ml/` as a future path.)
- **Non-blocking enrichment.** GeoIP, reputation lookups, and outbound reporting all run as background workers so a slow third-party API or a Splunk outage can never stall log ingestion.
- **Deduplicated, audited auto-reporting.** Each reporter checks a `ReportLog` table before acting (a time-window dedup for IPs, report-once for file hashes) and records every action — so the same attacker isn't reported twice and every outbound report is traceable.
- **Header-based admin auth.** The admin API and the authenticated SSE stream take the key via the `X-Admin-Key` header and compare it with `secrets.compare_digest`, keeping the secret out of URLs, proxy logs, and browser history.

## Quickstart

### Docker (recommended)

```bash
cp backend/.env.example backend/.env   # then edit — see Configuration below
docker compose up -d --build
```

The dashboard serves on `http://localhost:8080` with nginx proxying `/api` to the backend (SSE-aware, real client IPs preserved for rate limiting). The Cowrie log directory is mounted from `/var/log/cowrie` by default — override with `COWRIE_LOG_DIR=/path/to/logs docker compose up -d`. To enable the attack map, copy the GeoLite2 database into the data volume:

```bash
docker compose cp GeoLite2-City.mmdb backend:/app/data/
```

### Manual

**Prerequisites:** Python 3.11+, Node 20+, and (optionally) a running Cowrie honeypot producing a JSON log.

### Backend

```bash
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env        # then edit .env — see Configuration below
uvicorn app.main:app --reload
```

The API serves on `http://localhost:8000`. Interactive OpenAPI docs are auto-generated at **`http://localhost:8000/docs`**, and a health probe lives at `/api/health`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The dashboard serves on `http://localhost:5173`.

## Configuration

Configuration is read from `backend/.env` (see [`backend/.env.example`](backend/.env.example)):

| Variable            | Purpose                                                        | Required |
| ------------------- | ------------------------------------------------------------- | -------- |
| `ADMIN_API_KEY`     | Secures `/api/admin/*` and the authenticated SSE stream       | Strongly recommended in prod |
| `COWRIE_LOG_PATH`   | Path to the Cowrie JSON event log to ingest                   | Yes (for live data) |
| `GEOIP_DB_PATH`     | Path to the MaxMind GeoLite2-City `.mmdb` database            | For the attack map |
| `CORS_ORIGINS`      | Comma-separated allowed dashboard origins                     | For non-local deploys |
| `VIRUSTOTAL_API_KEY`| Enables malware submission/enrichment                         | Optional |
| `ABUSEIPDB_API_KEY` | Enables IP reputation lookups and auto-reporting              | Optional |
| `SPLUNK_HEC_URL` / `SPLUNK_HEC_TOKEN` | Forward enriched events to a Splunk HEC     | Optional |
| `NTFY_URL` / `DISCORD_WEBHOOK_URL` | Push alerts for successful logins, malware, VT hits, new countries | Optional |
| `RETENTION_DAYS`    | Prune raw events older than N days (0 = keep forever)        | Optional |

> **Note:** if `ADMIN_API_KEY` is unset, admin endpoints and the authenticated stream run open (intended for local development). Always set it in production.

## Testing

The backend has a pytest suite covering routers, services, and the classifier:

```bash
cd backend
source venv/bin/activate
pytest
```

## Project structure

```
backend/
  app/
    routers/        # FastAPI route handlers (attempts, stats, geo, malware,
                    #   stream, admin, profile, search, replay, meta, ...)
    services/       # ingestion, classifier, geoip, ip_lookup, alerts,
                    #   abuse_reporter, vt_reporter, splunk_forwarder, retention
    models.py       # SQLAlchemy models
    schemas.py      # Pydantic schemas
    config.py       # settings + startup validation
  ml/               # experimental ML classifier (offline training)
  tests/            # pytest suite
frontend/
  src/
    components/     # Dashboard panels, charts, map
    hooks/          # useSSE, useAttempts
    utils/          # API client, formatters
```

## Roadmap

- [x] Containerized deployment (`docker-compose` for backend + frontend)
- [x] CI pipeline (pytest, ESLint, type-check on every push)
- [x] Push alerting (ntfy / Discord) for high-signal events
- [x] Data retention with daily aggregation
- [ ] Generalized "playbook runner" to unify the reporting workers
- [ ] Wire the experimental ML classifier in as an optional enrichment path
- [ ] Attacker-infrastructure analytics (shared payloads and credential lists across IPs/ASNs)

## License

Released under the [MIT License](LICENSE).
