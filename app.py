#Kc
#1/15/2025 

import os
import re
from datetime import datetime
import pandas as pd
import streamlit as st
from streamlit_autorefresh import st_autorefresh


st.set_page_config(page_title=" Alert Triage Dashboard", layout="wide")  #<<<<< configuring the Streamlit Page.
st.title("Alert Triage Dashboard")


mode = st.selectbox("Select Mode", ["Live", "Static"])  #<<<<< settin up the toggle for live or static mode.
if mode == "Live":
    st_autorefresh(interval=5000, limit=None, key="refresh")
st.caption(f" Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


log_type = st.selectbox("Log Format", ["Syslog"])  #<<< ettingg up the log type selection.
log_path = "sample_logs/syslog_sample.log"
if not os.path.exists(log_path):
    st.error("Log file not found.")
    st.stop()


def parse_syslog(file_path):    # <<<<syslog parser ___________________
    """Parse syslog file and extract timestamp, IP, and activity."""
    with open(file_path, "r") as f:
        lines = f.readlines()
    data = []
    for line in lines:
        match = re.match(
            r'^(?P<timestamp>\w{3} \d{1,2} \d{2}:\d{2}:\d{2}) .*? from (?P<ip>\d+\.\d+\.\d+\.\d+)', #<<match syslog format
            line
        )
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


df = parse_syslog(log_path) #<<<<< load the logs
if df.empty:
    st.warning(" No logs parsed")
    st.stop()


def detect_suspicious(df):
    failed = df[df["activity"].str.contains("Failed password", case=False)] #<<<<<ffilter for failed attempts
    return ( 
        failed["ip"].value_counts()[lambda x: x >= 3]
        .reset_index()
        .rename(columns={"index": "Suspicious IP", "ip": "Failed Attempts"})
    )


total_logs = len(df)  #<<<< summary metrics -------
unique_ips = df['ip'].nunique() if 'ip' in df.columns else 0  #<<<<< count unique ips
suspicious = detect_suspicious(df)
suspicious_count = len(suspicious)

col1, col2, col3 = st.columns(3)
col1.metric("Total Logs", total_logs)
col2.metric("Unique IPs", unique_ips)
col3.metric("Suspicious IPs", suspicious_count)

st.markdown("---")

# <<<<<<, creating the tabs
tabs = st.tabs(["Raw Logs", " Filter & Search", " Log Activity", " Suspicious Activity"])


with tabs[0]:
    st.subheader(" Raw Logs")
    with st.expander("Show/Hide Raw Log Table", expanded=True):
        st.dataframe(df, use_container_width=True)
        st.download_button(
            " Download CSV",
            df.to_csv(index=False).encode("utf-8"),
            "logs.csv",
            "text/csv"
        )

with tabs[1]:
    st.subheader(" Filter Logs")
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

with tabs[2]:
    st.subheader(" Log Activity Over Time")
    if "timestamp" in df.columns:
        chart_df = df.copy()
        chart_df = chart_df.dropna(subset=["timestamp"])
        chart_df['hour'] = chart_df['timestamp'].dt.floor('h')

        #<<<<<ggroup by hour and ip for stacked bar-------------
        activity_by_ip = chart_df.groupby(["hour", "ip"]).size().unstack(fill_value=0)
        st.markdown("Events per Hour by IP (Stacked Bar)")
        st.bar_chart(activity_by_ip)

       
        st.markdown("Total Events per Hour (Line Chart)")  #<<<<< adding line chart for total events per hour
        total_per_hour = chart_df.groupby('hour').size()
        st.line_chart(total_per_hour)

        
        ip_list = list(chart_df['ip'].dropna().unique()) # <<<<< dddin option to select and highlight a specific IP
        selected_ip = st.selectbox("Highlight Activity for IP", ["All"] + ip_list)
        if selected_ip != "All":
            st.markdown(f"Events for {selected_ip}")
            ip_events = chart_df[chart_df['ip'] == selected_ip].groupby('hour').size()
            st.bar_chart(ip_events)
    else:
        st.info("No timestamp data available for chart.")

with tabs[3]:      #<<<<the suspicious activity tab 
    st.subheader("Suspicious IPs (3+ failed attempts)")
    if not suspicious.empty:
        st.dataframe(suspicious, use_container_width=True)
        st.download_button(
            " Download Suspicious CSV",
            suspicious.to_csv(index=False).encode("utf-8"),
            "suspicious_ips.csv",
            "text/csv"
        )

        selected_suspicious_ip = st.selectbox(                         
            "Select a Suspicious IP for Details",
            suspicious["Suspicious IP"] if "Suspicious IP" in suspicious.columns else suspicious.iloc[:,0]
        )
        # s<<<< showing all log entries for this IP
        st.markdown(f"All Events for {selected_suspicious_ip}:")
        ip_events = df[df["ip"] == selected_suspicious_ip]
        st.dataframe(ip_events, use_container_width=True)

        #<<<< showing all the activity over time for this IP
        if "timestamp" in ip_events.columns:
            ip_events = ip_events.dropna(subset=["timestamp"])
            ip_events['hour'] = ip_events['timestamp'].dt.floor('h')  # Fixed: use 'h' instead of 'H'
            st.markdown(f"Event Frequency for {selected_suspicious_ip} (per hour):")
            st.bar_chart(ip_events.groupby('hour').size())
        
        if "activity" in ip_events.columns:
            st.markdown("Event Type Breakdown:")
            st.bar_chart(ip_events["activity"].value_counts())
        elif "message" in ip_events.columns:
            st.markdown("Event Type Breakdown:")
            st.bar_chart(ip_events["message"].value_counts())
    else:
        st.info(" No suspicious IPs detected.")
