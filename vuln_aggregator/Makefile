# Makefile for vuln_aggregator
# Usage: make <target>
#
# Targets:
#   up          - Build and start all services (postgres, redis, api, worker, beat, dashboard)
#   down        - Stop all services
#   logs        - Follow logs from all services
#   logs-api    - Follow API logs only
#   logs-worker - Follow Celery worker logs only
#   test        - Install test deps and run pytest suite
#   token       - Get a JWT token for analyst/analyst123
#   scan-nginx  - Launch a Trivy scan of nginx:1.19
#   scan-lan    - Launch a detection-only nmap+nuclei scan of 192.168.1.0/24
#   findings    - Fetch top 10 vulnerability findings
#   posture     - Fetch security posture metrics
#   health      - Check API health endpoint
#   clean       - Stop services and delete all data volumes

.PHONY: up down logs logs-api logs-worker test token scan-nginx scan-lan findings posture health clean

up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f

logs-api:
	docker compose logs -f api

logs-worker:
	docker compose logs -f worker

test:
	pip install aiosqlite pytest pytest-asyncio httpx && pytest src/tests/ -v

token:
	@echo "Getting analyst token..."
	@curl -s -X POST http://localhost:8000/api/v1/auth/token \
		-d "username=analyst&password=analyst123" | python3 -m json.tool

scan-nginx:
	@echo "Launching Trivy scan of nginx:1.19..."
	@TOKEN=$$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
		-d "username=analyst&password=analyst123" | python3 -c \
		"import sys,json; print(json.load(sys.stdin)['access_token'])"); \
	curl -s -X POST http://localhost:8000/api/v1/scans \
		-H "Authorization: Bearer $$TOKEN" \
		-H "Content-Type: application/json" \
		-d '{"targets": ["nginx:1.19"], "scanners": ["trivy"], "authorized": true}' \
		| python3 -m json.tool

scan-lan:
	@echo "Launching detection-only scan of 192.168.1.0/24 (nmap + nuclei)..."
	@TOKEN=$$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
		-d "username=analyst&password=analyst123" | python3 -c \
		"import sys,json; print(json.load(sys.stdin)['access_token'])"); \
	curl -s -X POST http://localhost:8000/api/v1/scans \
		-H "Authorization: Bearer $$TOKEN" \
		-H "Content-Type: application/json" \
		-d '{"targets": ["192.168.1.0/24"], "profile": "home", "authorized": true}' \
		| python3 -m json.tool

findings:
	@echo "Fetching top 10 findings..."
	@TOKEN=$$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
		-d "username=analyst&password=analyst123" | python3 -c \
		"import sys,json; print(json.load(sys.stdin)['access_token'])"); \
	curl -s "http://localhost:8000/api/v1/vulnerabilities?limit=10" \
		-H "Authorization: Bearer $$TOKEN" \
		| python3 -m json.tool

posture:
	@echo "Fetching security posture..."
	@TOKEN=$$(curl -s -X POST http://localhost:8000/api/v1/auth/token \
		-d "username=analyst&password=analyst123" | python3 -c \
		"import sys,json; print(json.load(sys.stdin)['access_token'])"); \
	curl -s http://localhost:8000/api/v1/metrics/posture \
		-H "Authorization: Bearer $$TOKEN" \
		| python3 -m json.tool

health:
	curl http://localhost:8000/health

clean:
	docker compose down -v --remove-orphans
