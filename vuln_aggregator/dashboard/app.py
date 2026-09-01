import streamlit as st
import httpx
import pandas as pd
from datetime import datetime, timedelta

st.set_page_config(page_title="Vuln Aggregator Dashboard", layout="wide")

API_URL = "http://api:8000"  # When running in Docker

st.title("🛡️ Vulnerability Aggregation Dashboard")

# Fetch latest findings
@st.cache_data(ttl=300)
def fetch_findings(severity=None, limit=200):
    params = {"limit": limit}
    if severity:
        params["severity"] = severity
    resp = httpx.get(f"{API_URL}/findings", params=params)
    if resp.status_code == 200:
        return resp.json()
    return []

findings = fetch_findings()

if findings:
    df = pd.DataFrame(findings)
    # Convert timestamps
    df['scan_timestamp'] = pd.to_datetime(df['scan_timestamp'])
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Findings", len(df))
    col2.metric("Critical", len(df[df['severity'] == "Critical"]))
    col3.metric("High", len(df[df['severity'] == "High"]))
    avg_risk = df['risk_score'].mean()
    col4.metric("Avg Risk Score", f"{avg_risk:.2f}")

    st.subheader("Top 10 Most Critical Vulnerabilities")
    top10 = df.nlargest(10, 'risk_score')[['cve_id', 'asset_host', 'severity', 'risk_score', 'description']]
    st.dataframe(top10)

    # Chart: count by severity
    st.subheader("Findings by Severity")
    sev_counts = df['severity'].value_counts()
    st.bar_chart(sev_counts)

    # Trend over last 7 days
    df['date'] = df['scan_timestamp'].dt.date
    daily = df.groupby('date').size().reset_index(name='count')
    st.subheader("Daily Finding Count (last 7 days)")
    st.line_chart(daily.set_index('date')['count'])

    # Option to trigger scan
    if st.button("Trigger New Scan"):
        with st.spinner("Starting scan..."):
            resp = httpx.post(f"{API_URL}/scans", json=["192.168.1.0/24"])
            if resp.status_code == 200:
                st.success("Scan started successfully!")
else:
    st.info("No findings yet. Run a scan.")
