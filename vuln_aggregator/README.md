# Defensive Network Vulnerability Assessment Platform

Detection-only scanner for networks you own or have written permission to test.
It discovers live hosts with **nmap**, checks them with **Nuclei** (no exploit
payloads), optionally scans container images with **Trivy**, then ranks findings
with CISA KEV / FIRST EPSS / NVD.

GVM and Nessus connectors remain as optional add-ons; they are **not** started
by Docker Compose and are skipped unless configured.

## What a scan does

1. Require `authorized: true` and an allowlisted target (RFC1918/loopback by default).
2. Classify targets: CIDR/IP/hostname → network; `nginx:1.19` → image.
3. nmap TCP-connect (`-sT -sV`) → host inventory + hygiene findings (Telnet, SMB, …).
4. Nuclei detection templates (excludes `intrusive`, `dos`, `fuzz`).
5. Enrich CVEs, score 0–10, upsert into Postgres.

Profiles: **home** (≤256 hosts), **thorough** (≤1024, includes default-login templates),
**large** (≤4096, `/24` chunks).

## Quick start (Docker)

```bash
cp .env.example .env
docker compose up --build
```

- API + Swagger: `http://localhost:8000/docs`
- Dashboard: `http://localhost:8501` (analyst / analyst123)
- Health: `http://localhost:8000/health`

First **image** scan:

```bash
make scan-nginx
```

First **LAN** scan (private CIDR you own):

```bash
make scan-lan
```

Or POST:

```json
{
  "targets": ["192.168.1.0/24"],
  "profile": "home",
  "authorized": true
}
```

## Authentication

```bash
curl -X POST http://localhost:8000/api/v1/auth/token \
  -d "username=analyst&password=analyst123"
```

RBAC: **ADMIN** (all), **ANALYST** (launch scans, resolve findings), **READ_ONLY** (read).

## API (v1)

| Method | Path | Role | Purpose |
| ------ | ---- | ---- | ------- |
| POST | `/api/v1/auth/token` | public | Issue a JWT |
| POST | `/api/v1/scans` | Analyst+ | Launch async scan (`authorized` required) |
| GET | `/api/v1/scans/{id}` | Read-only+ | Status + progress |
| GET | `/api/v1/assets` | Read-only+ | Discovered hosts and ports |
| GET | `/api/v1/vulnerabilities` | Read-only+ | Ranked findings |
| PATCH | `/api/v1/vulnerabilities/{id}` | Analyst+ | Mark resolved |
| GET | `/api/v1/metrics/posture` | Read-only+ | Exposure / KEV / MTTR |

## Ethics

- Default allowlist: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`.
- Public IPs/CIDRs are rejected unless added to `SCAN_ALLOWLIST`.
- nmap does not use OS detection or UDP floods.
- Nuclei does not run exploit, DoS, or fuzz templates.

## Architecture

```
HTTP  →  FastAPI (JWT + RBAC)
           → ScanService
                → nmap → assets + hygiene
                → nuclei → CVE/misconfig/TLS/HTTP detections
                → trivy  → image CVEs
           → KEV / EPSS / NVD
           → risk engine → Postgres
Dashboard and /docs read the same API.
```

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

## Risk model

`risk = clamp( (0.40·CVSS) + (0.30·EPSS·10) + (0.15·exploit) [+ KEV] ) · asset_multiplier`

Gateway-like addresses (`*.1`, `*.254`) use a HIGH asset multiplier automatically.
