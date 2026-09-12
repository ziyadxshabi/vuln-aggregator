import os

import httpx
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Defensive Network Scanner", layout="wide")

API_URL = os.getenv("API_URL", "http://api:8000")

if "token" not in st.session_state:
    st.session_state["token"] = None
if "last_job_id" not in st.session_state:
    st.session_state["last_job_id"] = None


def get_auth_headers() -> dict[str, str]:
    token = st.session_state.get("token")
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


def handle_auth_error(resp: httpx.Response) -> None:
    if resp.status_code == 401:
        st.session_state["token"] = None
        st.warning("Session expired, please log in again.")
        st.rerun()


def login(username: str, password: str) -> bool:
    resp = httpx.post(
        f"{API_URL}/api/v1/auth/token",
        data={"username": username, "password": password},
        timeout=30.0,
    )
    if resp.status_code == 200:
        st.session_state["token"] = resp.json()["access_token"]
        return True
    return False


def fetch_findings(limit: int = 200) -> list[dict]:
    resp = httpx.get(
        f"{API_URL}/api/v1/vulnerabilities",
        params={"limit": limit},
        headers=get_auth_headers(),
        timeout=30.0,
    )
    if resp.status_code == 401:
        handle_auth_error(resp)
        return []
    if resp.status_code == 200:
        return resp.json().get("items", [])
    return []


def fetch_assets(limit: int = 500) -> dict:
    resp = httpx.get(
        f"{API_URL}/api/v1/assets",
        params={"limit": limit},
        headers=get_auth_headers(),
        timeout=30.0,
    )
    if resp.status_code == 401:
        handle_auth_error(resp)
        return {"items": [], "count": 0, "risky_service_count": 0}
    if resp.status_code == 200:
        return resp.json()
    return {"items": [], "count": 0, "risky_service_count": 0}


def fetch_posture() -> dict | None:
    resp = httpx.get(
        f"{API_URL}/api/v1/metrics/posture",
        headers=get_auth_headers(),
        timeout=30.0,
    )
    if resp.status_code == 401:
        handle_auth_error(resp)
        return None
    if resp.status_code == 200:
        return resp.json()
    return None


def fetch_scan(job_id: str) -> dict | None:
    resp = httpx.get(
        f"{API_URL}/api/v1/scans/{job_id}",
        headers=get_auth_headers(),
        timeout=30.0,
    )
    if resp.status_code == 200:
        return resp.json()
    return None


def trigger_scan(targets: list[str], profile: str, authorized: bool) -> tuple[bool, str, str | None]:
    resp = httpx.post(
        f"{API_URL}/api/v1/scans",
        json={"targets": targets, "profile": profile, "authorized": authorized},
        headers=get_auth_headers(),
        timeout=30.0,
    )
    if resp.status_code == 401:
        handle_auth_error(resp)
        return False, "Session expired", None
    if resp.status_code == 202:
        body = resp.json()
        job_id = body.get("id")
        return True, f"Scan started (job id: {job_id})", job_id
    return False, f"Scan failed ({resp.status_code}): {resp.text}", None


def resolve_finding(vuln_id: str) -> tuple[bool, str]:
    resp = httpx.patch(
        f"{API_URL}/api/v1/vulnerabilities/{vuln_id}",
        json={"status": "RESOLVED"},
        headers=get_auth_headers(),
        timeout=30.0,
    )
    if resp.status_code == 401:
        handle_auth_error(resp)
        return False, "Session expired"
    if resp.status_code == 200:
        return True, "Marked resolved"
    return False, f"Update failed ({resp.status_code}): {resp.text}"


with st.sidebar:
    st.header("Login")
    if st.session_state["token"]:
        st.success("Logged in")
        if st.button("Log out"):
            st.session_state["token"] = None
            st.rerun()
    else:
        username = st.text_input("Username", placeholder="analyst")
        password = st.text_input("Password", type="password", placeholder="analyst123")
        if st.button("Login"):
            if login(username, password):
                st.success("Login successful")
                st.rerun()
            else:
                st.error("Invalid username or password")

    st.divider()
    st.header("New scan")
    st.caption(
        "Detection only. Scan networks you own or have written permission to test. "
        "Public internet ranges are blocked unless added to SCAN_ALLOWLIST."
    )
    target = st.text_input("Target (CIDR, IP, or image)", placeholder="192.168.1.0/24")
    profile = st.selectbox("Profile", ["home", "thorough", "large"], index=0)
    authorized = st.checkbox("I am authorized to scan these targets")
    if st.button("Start scan", disabled=not st.session_state["token"]):
        cleaned = target.strip()
        if not cleaned:
            st.error("Enter a target.")
        elif not authorized:
            st.error("You must confirm authorization before scanning.")
        else:
            with st.spinner("Starting scan..."):
                ok, message, job_id = trigger_scan([cleaned], profile, authorized)
            if ok:
                st.session_state["last_job_id"] = job_id
                st.success(message)
            else:
                st.error(message)

if not st.session_state["token"]:
    st.title("Defensive Network Scanner")
    st.info("Log in using the sidebar. Default lab credentials: analyst / analyst123")
    st.stop()

st.title("Defensive Network Scanner")
st.caption("nmap discovery + Nuclei detection + Trivy images. No exploits.")

if st.session_state.get("last_job_id"):
    job = fetch_scan(st.session_state["last_job_id"])
    if job:
        progress = job.get("progress") or {}
        status = job.get("status")
        col_status, col_refresh = st.columns([4, 1])
        with col_status:
            st.info(
                f"Last job {job['id']}: {status} — "
                f"phase={progress.get('phase', 'n/a')}, "
                f"hosts={progress.get('hosts_found', 0)}, "
                f"findings={progress.get('findings_so_far', job.get('total_findings', 0))}"
            )
        with col_refresh:
            if st.button("Refresh progress"):
                st.rerun()
        if status in ("PENDING", "RUNNING"):
            st.caption("Scan in progress. Click Refresh progress to poll job status.")

posture = fetch_posture()
assets_payload = fetch_assets()
hosts = assets_payload.get("items") or []
risky_count = assets_payload.get("risky_service_count", 0)

p1, p2, p3, p4, p5, p6 = st.columns(6)
if posture:
    p1.metric("Hosts up", assets_payload.get("count", len(hosts)))
    p2.metric("Open findings", posture.get("open_findings", 0))
    p3.metric("Known exploited (KEV)", posture.get("known_exploited_count", 0))
    p4.metric("Risky services", risky_count)
    p5.metric("Exposure score", f"{posture.get('exposure_score', 0):.2f}")
    mttr = posture.get("mttr_days")
    p6.metric("MTTR (days)", f"{mttr:.1f}" if mttr is not None else "N/A")
    sev_counts = posture.get("severity_counts") or {}
    if sev_counts:
        st.bar_chart(pd.Series(sev_counts, name="count"))

tab_hosts, tab_findings = st.tabs(["Hosts", "Findings"])

with tab_hosts:
    if not hosts:
        st.info("No hosts yet. Run a network scan of a private CIDR you own.")
    else:
        rows = []
        for host in hosts:
            ports = host.get("ports") or []
            port_label = ", ".join(
                f"{p.get('port')}/{p.get('protocol', 'tcp')} {p.get('service') or ''}".strip()
                for p in ports
            )
            rows.append(
                {
                    "ip": host.get("ip"),
                    "hostname": host.get("hostname"),
                    "criticality": host.get("criticality"),
                    "services": host.get("services") or port_label,
                }
            )
        st.dataframe(pd.DataFrame(rows), use_container_width=True)

with tab_findings:
    findings = fetch_findings()
    if not findings:
        st.info("No findings yet.")
    else:
        df = pd.DataFrame(findings)
        display_cols = [
            c
            for c in [
                "cve_id",
                "asset_ip",
                "port",
                "severity",
                "risk_score",
                "is_known_exploited",
                "status",
                "title",
            ]
            if c in df.columns
        ]
        st.subheader("Ranked findings")
        st.dataframe(df[display_cols].sort_values("risk_score", ascending=False), use_container_width=True)

        open_ids = [
            (item["id"], f"{item.get('asset_ip')} — {item.get('title') or item.get('cve_id')}")
            for item in findings
            if item.get("status") != "RESOLVED"
        ]
        if open_ids:
            labels = {label: vuln_id for vuln_id, label in open_ids}
            choice = st.selectbox("Mark resolved", list(labels.keys()))
            if st.button("Resolve selected finding"):
                ok, message = resolve_finding(labels[choice])
                if ok:
                    st.success(message)
                    st.rerun()
                else:
                    st.error(message)
