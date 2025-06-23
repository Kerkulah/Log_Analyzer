
import os
import re
import pandas as pd
import requests
from datetime import datetime
import streamlit as st
from streamlit_autorefresh import st_autorefresh


virusTotal_API_Key = " "  #replace this with  your virusTotal API key

def check_ip_virustotal(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": virusTotal_API_Key}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return stats.get("malicious", 0), stats.get("suspicious", 0)
    return None, None

def parse_syslog(file_path):                     # <<<<syslog parser
    with open(file_path, "r") as f:
        lines = f.readlines()
    data = []
    for line in lines:
        match = re.match(r'^(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .*? from (?P<ip>\d+\.\d+\.\d+\.\d+)', line) #<<here we matching syslog format
        if match:
            entry = match.groupdict()
            try:
                entry["timestamp"] = datetime.strptime(
                    f"{datetime.now().year} {entry['timestamp']}",
                    "%Y %b %d %H:%M:%S"
                )
            except Exception:
                entry["timestamp"] = None
            entry["activity"] = line.strip()
            data.append(entry)
    return pd.DataFrame(data)

def detect_suspicious(df):              # <<<<detect suspicious activity and ffilter for failed attempts
    failed = df[df["activity"].str.contains("Failed password", case=False)]
    suspicious_counts = failed["ip"].value_counts()
    suspicious_df = suspicious_counts[suspicious_counts >= 3].reset_index()
    suspicious_df.columns = ["Suspicious IP", "Failed Attempts"]
    return suspicious_df

# <<<setting up streamlit app UI
st.set_page_config(page_title="Alert Triage Dashboard", layout="wide")
st.title("Alert Triage Dashboard")

mode = st.selectbox("Select Mode", ["Live", "Static"])
if mode == "Live":
    st_autorefresh(interval=5000, limit=None, key="refresh")

st.caption(f" Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

log_type = st.selectbox("Log Format", ["Syslog"])
log_path = "sample_logs/syslog_sample.log"
if not os.path.exists(log_path):
    st.error("Log file not found.")
    st.stop()

df = parse_syslog(log_path)
if df.empty:
    st.warning("No logs parsed.")
    st.stop()

suspicious = detect_suspicious(df)


col1, col2, col3 = st.columns(3)
col1.metric("Total Logs", len(df))
col2.metric("Unique IPs", df['ip'].nunique())
col3.metric("Suspicious IPs", len(suspicious))

st.markdown("---")
tabs = st.tabs(["Raw Logs", " Filter & Search", " Log Activity", " Suspicious Activity"])

# 
with tabs[0]:
    st.subheader("Raw Logs")
    with st.expander("Show/Hide Raw Log Table", expanded=True):
        st.dataframe(df, use_container_width=True)
        st.download_button(
            "Download CSV",
            df.to_csv(index=False).encode("utf-8"),
            "logs.csv",
            "text/csv"
        )


with tabs[1]:                                 # here we setting up tab 2 for filtering logs 
    st.subheader("Filter Logs")
    with st.expander("Show/Hide Filters", expanded=True):
        ip_filter = st.text_input("Filter by IP")
        filtered_df = df.copy()
        if ip_filter:
            filtered_df = filtered_df[filtered_df["ip"] == ip_filter]
        if "timestamp" in filtered_df.columns and not filtered_df["timestamp"].isnull().all():
            hours = st.slider("Filter by hour", 0, 23, (0, 23))
            filtered_df = filtered_df[filtered_df["timestamp"].dt.hour.between(*hours)]
        keyword = st.text_input("Filter by keyword (e.g., Failed, Accepted)")
        if keyword:
            filtered_df = filtered_df[filtered_df["activity"].str.contains(keyword, case=False)]
        st.dataframe(filtered_df, use_container_width=True)

with tabs[2]:                                        # setting up tab 3 for log activity        
    st.subheader("Log Activity Over Time")
    if "timestamp" in df.columns:
        chart_df = df.dropna(subset=["timestamp"]).copy()
        chart_df['hour'] = chart_df['timestamp'].dt.floor('h')

        st.markdown("Events per Hour by IP (Stacked Bar)")
        activity_by_ip = chart_df.groupby(["hour", "ip"]).size().unstack(fill_value=0)
        st.bar_chart(activity_by_ip)

        st.markdown("Total Events per Hour (Line Chart)")
        total_per_hour = chart_df.groupby('hour').size()
        st.line_chart(total_per_hour)

        ip_list = list(chart_df['ip'].dropna().unique())
        selected_ip = st.selectbox("Highlight Activity for IP", ["All"] + ip_list)
        if selected_ip != "All":
            st.markdown(f"Events for {selected_ip}")
            ip_events = chart_df[chart_df['ip'] == selected_ip].groupby('hour').size()
            st.bar_chart(ip_events)
    else:
        st.info("No timestamp data available for chart.")


with tabs[3]:                                                   # setting up tab 4 for suspicious activity
    st.subheader("Suspicious IPs (3+ failed attempts)")
    if not suspicious.empty:
        if "vt_results" not in st.session_state:
            st.session_state.vt_results = {}

        if st.button(" Run VirusTotal Check"):
            vt_data = []
            for ip in suspicious["Suspicious IP"]:
                if ip not in st.session_state.vt_results:
                    with st.spinner(f"Checking {ip} on VirusTotal..."):
                        malicious, suspicious_count = check_ip_virustotal(ip)
                        st.session_state.vt_results[ip] = f"Malicious: {malicious}, Suspicious: {suspicious_count}"
                vt_data.append(st.session_state.vt_results[ip])
            suspicious["VirusTotal"] = vt_data

        elif "VirusTotal" not in suspicious.columns and st.session_state.vt_results:
            suspicious["VirusTotal"] = suspicious["Suspicious IP"].map(st.session_state.vt_results).fillna("Not Checked")

        st.dataframe(suspicious, use_container_width=True)
        st.download_button(
            "Download Suspicious CSV",
            suspicious.to_csv(index=False).encode("utf-8"),
            "suspicious_ips.csv",
            "text/csv"
        )

        selected_suspicious_ip = st.selectbox(
            "Select a Suspicious IP for Details",
            suspicious["Suspicious IP"]
        )

        st.markdown(f"All Events for {selected_suspicious_ip}:")
        ip_events = df[df["ip"] == selected_suspicious_ip]
        st.dataframe(ip_events, use_container_width=True)

        if "timestamp" in ip_events.columns:
            ip_events = ip_events.dropna(subset=["timestamp"])
            ip_events['hour'] = ip_events['timestamp'].dt.floor('h')
            st.markdown("Event Frequency (per hour):")
            st.bar_chart(ip_events.groupby('hour').size())

        if "activity" in ip_events.columns:
            st.markdown("Event Type Breakdown:")
            st.bar_chart(ip_events["activity"].value_counts())
    else:
        st.info(" No suspicious IPs detected.")
