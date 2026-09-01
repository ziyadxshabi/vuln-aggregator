import httpx
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Vuln Aggregator Dashboard", layout="wide")

API_URL = "http://api:8000"  # When running in Docker

if "token" not in st.session_state:
    st.session_state["token"] = None


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


def fetch_findings(severity: str | None = None, limit: int = 200) -> list[dict]:
    params: dict[str, str | int] = {"limit": limit}
    if severity:
        params["severity"] = severity
    resp = httpx.get(
        f"{API_URL}/api/v1/vulnerabilities",
        params=params,
        headers=get_auth_headers(),
        timeout=30.0,
    )
    if resp.status_code == 401:
        handle_auth_error(resp)
        return []
    if resp.status_code == 200:
        return resp.json().get("items", [])
    return []


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


def trigger_scan(targets: list[str], scanners: list[str]) -> tuple[bool, str]:
    resp = httpx.post(
        f"{API_URL}/api/v1/scans",
        json={"targets": targets, "scanners": scanners},
        headers=get_auth_headers(),
        timeout=30.0,
    )
    if resp.status_code == 401:
        handle_auth_error(resp)
        return False, "Session expired"
    if resp.status_code == 202:
        body = resp.json()
        return True, f"Scan started (job id: {body.get('id', 'unknown')})"
    return False, f"Scan failed ({resp.status_code}): {resp.text}"


# --- Login gate ---
with st.sidebar:
    st.header("Login")
    if st.session_state["token"]:
        st.success("Logged in")
        if st.button("Log out"):
            st.session_state["token"] = None
            st.rerun()
    else:
        username = st.text_input("Username", placeholder="analyst")
        password = st.text_input(
            "Password",
            type="password",
            placeholder="analyst123",
        )
        if st.button("Login"):
            if login(username, password):
                st.success("Login successful")
                st.rerun()
            else:
                st.error("Invalid username or password")

if not st.session_state["token"]:
    st.title("Vulnerability Aggregation Dashboard")
    st.info("Please log in using the sidebar. Default dev credentials: analyst / analyst123")
    st.stop()

st.title("Vulnerability Aggregation Dashboard by zvdzad")

posture = fetch_posture()
if posture:
    st.subheader("Security Posture")
    p1, p2, p3, p4, p5, p6 = st.columns(6)
    p1.metric("Total Findings", posture.get("total_findings", 0))
    p2.metric("Open Findings", posture.get("open_findings", 0))
    p3.metric("Known Exploited (KEV)", posture.get("known_exploited_count", 0))
    p4.metric("Exposure Score", f"{posture.get('exposure_score', 0):.2f}")
    mttr = posture.get("mttr_days")
    p5.metric("MTTR (days)", f"{mttr:.1f}" if mttr is not None else "N/A")
    sev_counts = posture.get("severity_counts", {})
    critical_count = sev_counts.get("CRITICAL", 0)
    p6.metric("Critical", critical_count)

    if sev_counts:
        st.bar_chart(pd.Series(sev_counts, name="count"))

findings = fetch_findings()

if findings:
    df = pd.DataFrame(findings)

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Listed Findings", len(df))
    col2.metric("Critical", len(df[df["severity"] == "CRITICAL"]))
    col3.metric("High", len(df[df["severity"] == "HIGH"]))
    avg_risk = df["risk_score"].mean() if "risk_score" in df.columns else 0.0
    col4.metric("Avg Risk Score", f"{avg_risk:.2f}")

    st.subheader("Top 10 Highest-Risk Vulnerabilities")
    display_cols = [
        c
        for c in [
            "cve_id",
            "asset_host",
            "severity",
            "risk_score",
            "is_known_exploited",
            "description",
        ]
        if c in df.columns
    ]
    top10 = df.nlargest(10, "risk_score")[display_cols]
    st.dataframe(top10)

    st.subheader("Findings by Severity")
    sev_counts = df["severity"].value_counts()
    st.bar_chart(sev_counts)

    if st.button("Trigger New Scan"):
        with st.spinner("Starting scan..."):
            ok, message = trigger_scan(
                targets=["192.168.1.0/24"],
                scanners=["gvm", "nessus", "trivy"],
            )
            if ok:
                st.success(message)
            else:
                st.error(message)
else:
    st.info("No findings yet. Run a scan.")
    if st.button("Trigger New Scan"):
        with st.spinner("Starting scan..."):
            ok, message = trigger_scan(
                targets=["192.168.1.0/24"],
                scanners=["gvm", "nessus", "trivy"],
            )
            if ok:
                st.success(message)
            else:
                st.error(message)
