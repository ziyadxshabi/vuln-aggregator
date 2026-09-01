# Enterprise Vulnerability Aggregation & Prioritization Platform

A production-oriented vulnerability management and threat-intelligence platform
built with **Clean / Hexagonal Architecture** (Ports & Adapters). It ingests
findings from multiple scanners, normalizes them into a single domain model,
enriches them with multi-feed threat intelligence, computes a deterministic
risk score, and exposes a secured REST API.

## Architecture

```
              driving adapter                         driven adapters
            ┌────────────────┐                    ┌─────────────────────┐
HTTP  ───▶  │  FastAPI (api) │ ──┐            ┌──▶ │ connectors (GVM,    │
            │  JWT + RBAC    │   │            │    │  Nessus, Trivy)     │
            └────────────────┘   │            │    ├─────────────────────┤
                                 ▼            │    │ enrichment (KEV,    │
   ┌──────────────────────────────────────┐  │    │  EPSS, NVD/Vulners) │
   │        services (use cases)           │──┤    ├─────────────────────┤
   │  ScanService · PostureService         │  │    │ database (SQLAlchemy│
   └──────────────────────────────────────┘  │    │  2.0 async upsert)  │
                     │                        │    ├─────────────────────┤
                     ▼ depends only on ports  └──▶ │ workers (Celery)    │
   ┌──────────────────────────────────────┐       └─────────────────────┘
   │   models (domain) + engine (risk)     │   pure, framework-agnostic core
   └──────────────────────────────────────┘
```

- **`src/models/`** — domain models, enums, and the `Protocol` **ports**.
- **`src/engine/risk_engine.py`** — pure, deterministic scoring (no I/O).
- **`src/connectors/`** — `BaseScannerConnector` + GVM, Nessus, Trivy adapters.
- **`src/enrichment/`** — CISA KEV, FIRST EPSS, NVD/Vulners, Redis TTL cache.
- **`src/database/`** — async engine, ORM (compound indexes), upsert repository.
- **`src/services/`** — orchestration use cases wired via `factory.py`.
- **`src/workers/`** — Celery app, tasks, and the task dispatcher.
- **`src/api/`** — FastAPI app, DI, JWT/RBAC, error envelopes, v1 routes.

## Requirements

- Python 3.12+
- PostgreSQL 16+, Redis 7+
- (Optional) `python-gvm` for live GVM scans, `trivy` binary, OTLP collector

## Quick start (Docker)

```bash
cp .env.example .env          # then edit secrets
docker compose up --build
```

- API + Swagger UI: `http://localhost:8000/docs`
- Health: `http://localhost:8000/health`
- The `api` service runs `alembic upgrade head` before serving.
- `worker` runs Celery scan tasks; `beat` schedules KEV refresh + estate scans.

## Local development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest                       # run the test suite
mypy src                     # strict type checking
ruff check src               # lint
```

## Authentication

Obtain a bearer token (seed users come from `AUTH_USERS`):

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=analyst&password=analyst123"
```

Use the returned `access_token` as `Authorization: Bearer <token>`.

RBAC tiers: **ADMIN** (all), **ANALYST** (launch scans + read), **READ_ONLY** (read).

## API (v1)

| Method | Path | Role | Purpose |
| ------ | ---- | ---- | ------- |
| POST | `/api/v1/auth/token` | public | Issue a JWT |
| POST | `/api/v1/scans` | Analyst+ | Launch async scan (returns task id) |
| GET | `/api/v1/scans/{task_id}` | Read-only+ | Scan progress/status |
| GET | `/api/v1/vulnerabilities` | Read-only+ | Filter/sort with cursor pagination |
| GET | `/api/v1/vulnerabilities/{id}` | Read-only+ | Full finding detail |
| GET | `/api/v1/metrics/posture` | Read-only+ | Posture metrics (severity, KEV, MTTR) |

## Risk model

`risk = clamp( (0.40·CVSS) + (0.30·EPSS·10) + (0.15·exploit) [+ KEV boost/floor] ) · asset_multiplier`

CISA KEV membership applies a fixed boost and forces at least the Critical band.
The full component breakdown is returned by the engine for auditability.

## Migrations

```bash
alembic upgrade head          # apply
alembic revision -m "msg"     # create a new revision (async env)
```

## Notes

- The deterministic finding `id` is a SHA-256 fingerprint of
  `scanner + scanner_vuln_id + asset_ip + port + protocol`, enabling idempotent
  `INSERT ... ON CONFLICT DO UPDATE` upserts across recurring scans.
- The repository upsert is dialect-aware (PostgreSQL in prod, SQLite in tests).
