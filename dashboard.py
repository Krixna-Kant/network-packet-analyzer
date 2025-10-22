# dashboard.py
import streamlit as st
import pandas as pd
import os

PACKET_LOG = "data/packet_log.csv"
SUSPICIOUS_LOG = "data/suspicious_log.csv"


st.set_page_config(page_title="Network Packet Analyzer Dashboard", layout="wide")
st.title("Network Packet Analyzer Dashboard")


@st.cache_data
def load_data(file_path):
    """Load CSV and handle empty/missing files gracefully."""
    if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
        df = pd.read_csv(file_path)
        # Normalize column names for consistency
        df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_")
        return df
    return pd.DataFrame()


packets_df = load_data(PACKET_LOG)
sus_df = load_data(SUSPICIOUS_LOG)


if packets_df.empty:
    st.warning("No packet data available. Please run the packet analyzer (`python main.py`) first.")
    st.stop()


st.sidebar.header("Filter Options")

protocol_filter = st.sidebar.multiselect(
    "Select Protocol(s):",
    options=packets_df["protocol"].unique(),
    default=list(packets_df["protocol"].unique())
)

src_filter = st.sidebar.text_input("Filter by Source IP:")
dst_filter = st.sidebar.text_input("Filter by Destination IP:")

#Apply filters
filtered_df = packets_df[packets_df["protocol"].isin(protocol_filter)]

if src_filter:
    filtered_df = filtered_df[filtered_df["source_ip"].str.contains(src_filter, na=False)]
if dst_filter:
    filtered_df = filtered_df[filtered_df["destination_ip"].str.contains(dst_filter, na=False)]


col1, col2 = st.columns(2)

with col1:
    st.subheader("Protocol Distribution")
    proto_counts = filtered_df["protocol"].value_counts()
    st.bar_chart(proto_counts)

with col2:
    st.subheader("Top Source IPs")
    if "source_ip" in filtered_df.columns:
        src_counts = filtered_df["source_ip"].value_counts().head(10)
        st.bar_chart(src_counts)
    else:
        st.info("No 'source_ip' column found — check your CSV headers.")


st.divider()
st.subheader("Captured Packets")
st.dataframe(filtered_df.tail(100), use_container_width=True)


st.divider()
st.subheader("Suspicious Traffic Alerts")

if not sus_df.empty:
    st.dataframe(sus_df.tail(50), use_container_width=True)
else:
    st.info("No suspicious traffic detected yet.")


st.divider()
st.download_button(
    label="Download Packet Log as CSV",
    data=packets_df.to_csv(index=False),
    file_name="packet_log.csv",
    mime="text/csv"
)
