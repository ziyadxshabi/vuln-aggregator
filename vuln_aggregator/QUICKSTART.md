# QUICKSTART — defensive network scanner

Detection-only. Scan systems you own or have written permission to test.

## Setup

```bash
cd vuln_aggregator
cp .env.example .env
docker compose up --build
```

Wait for “Application startup complete”.

- Dashboard: http://localhost:8501 — `analyst` / `analyst123`
- API docs: http://localhost:8000/docs

## First network scan

In the dashboard: enter a private CIDR such as `192.168.1.0/24`, choose profile
**home**, check **I am authorized**, start scan.

Or:

```bash
make scan-lan
```

Wait for the worker to finish, then refresh the dashboard. **Hosts** shows open
ports; **Findings** is ranked by risk. Mark items resolved as you patch them.

## First image scan

```bash
make scan-nginx
```

That runs Trivy against `nginx:1.19`. Image refs are not mixed into LAN scans.

## What the numbers mean

- **risk_score**: 0–10. Fix ≥ 7 first.
- **is_known_exploited**: on CISA KEV — treat as emergency.
- **Risky services**: Telnet, SMB, RDP, and similar listeners nmap found.

## Profiles

- `home` — up to a /24, top 1000 ports, safe Nuclei tags
- `thorough` — up to 1024 hosts, also default-login detections
- `large` — up to 4096 hosts, /24 chunks, fewer ports, slower rate

Public IPs are blocked unless you add them to `SCAN_ALLOWLIST` in `.env`.

## Stop

```bash
docker compose down
```
