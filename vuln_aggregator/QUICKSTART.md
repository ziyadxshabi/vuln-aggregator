# QUICKSTART — vuln_aggregator

This guide gets you from zero to seeing real vulnerability scan results. No prior experience needed.

---

## SECTION 1: BEFORE YOU START

You need:

- **Docker Desktop** installed and running
- A terminal (PowerShell on Windows, Terminal on Mac/Linux)
- Nothing else

---

## SECTION 2: ONE-TIME SETUP (do this once, never again)

**Step 1: Go into the project folder**

```bash
cd vuln_aggregator
```

**Step 2: Confirm .env exists**

The `.env` file should already be there. The default settings will work for your first run. You do NOT need to change anything to get started.

**Step 3: Build and start everything**

On Mac/Linux:
```bash
make up
```

On Windows (no make):
```bash
docker compose up --build
```

Wait until you see "Application startup complete" in the output. This takes 3-5 minutes the first time.

---

## SECTION 3: YOUR FIRST SCAN (takes about 60 seconds)

On Mac/Linux:
```bash
make scan-nginx
```

On Windows:
```powershell
# Get a token
$response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/token" -Method Post -Body "username=analyst&password=analyst123" -ContentType "application/x-www-form-urlencoded"
$token = $response.access_token

# Launch the scan
$headers = @{ "Authorization" = "Bearer $token"; "Content-Type" = "application/json" }
$body = '{"targets": ["nginx:1.19"], "scanners": ["trivy"]}'
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/scans" -Method Post -Headers $headers -Body $body
```

What this does: scans the nginx:1.19 Docker image for known CVEs. You will get back a JSON object with a scan job ID. Wait 30-60 seconds for the scan to complete.

---

## SECTION 4: SEE YOUR RESULTS

**Option A — The Dashboard (easiest)**

Open http://localhost:8501 in your browser. Log in with:
- Username: `analyst`
- Password: `analyst123`

You will see your vulnerability findings ranked by risk score.

**Option B — The API Explorer**

Open http://localhost:8000/docs in your browser. Click **Authorize** (top right), enter `analyst` / `analyst123`. Try `GET /api/v1/vulnerabilities`.

**Option C — The Terminal**

On Mac/Linux:
```bash
make findings
```

On Windows:
```powershell
# Get a token
$response = Invoke-RestMethod -Uri "http://localhost:8000/api/v1/auth/token" -Method Post -Body "username=analyst&password=analyst123" -ContentType "application/x-www-form-urlencoded"
$token = $response.access_token

# Fetch findings
$headers = @{ "Authorization" = "Bearer $token" }
Invoke-RestMethod -Uri "http://localhost:8000/api/v1/vulnerabilities?limit=10" -Headers $headers
```

---

## SECTION 5: WHAT YOU ARE LOOKING AT

Each finding has these fields:

- **risk_score**: 0-10, higher = more urgent. Fix anything above 7 first.
- **severity**: CRITICAL / HIGH / MEDIUM / LOW / INFO — the rough category.
- **is_known_exploited**: `true` means real attackers are using this right now.
- **cve_id**: The official catalog number for this vulnerability (e.g., CVE-2021-44228).
- **epss_score**: Probability (0-1) that this will be exploited this month.

---

## SECTION 6: SCANNING SOMETHING ELSE

Trivy can scan any Docker image. Change `"nginx:1.19"` to any image name, e.g. `"python:3.9"` or `"ubuntu:20.04"`.

To scan a whole network (requires GVM or Nessus — advanced), see `README.md` for setup instructions.

---

## SECTION 7: STOPPING EVERYTHING

On Mac/Linux:
```bash
make down
```

On Windows:
```powershell
docker compose down
```

To also delete all stored data:
```bash
docker compose down -v
```

---

## SECTION 8: IF SOMETHING BREAKS

**API not starting:**
```bash
docker compose logs api
```

**Scan not completing:**
```bash
docker compose logs worker
```

**Dashboard not loading:**
Make sure you ran `docker compose up --build`, not just `docker compose up`.

**Everything broken:**
On Mac/Linux:
```bash
make clean
make up
```

On Windows:
```powershell
docker compose down -v
docker compose up --build
```

---

That's it. You now have a working vulnerability management platform.
