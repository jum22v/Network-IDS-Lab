"""Local dashboard. Run: python -m streamlit run dashboard/app.py"""
import json
from pathlib import Path
import sys
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from idslab.core import read_packets, read_alerts, detect_ports, sha256

st.set_page_config(page_title="Network IDS Lab", layout="wide")
st.title("Network IDS Lab")
st.caption("Offline analysis · IPv4 summaries · UTC timestamps")
captures = sorted((ROOT / "captures").glob("*.pcap"))
if not captures:
    st.info("Place your lab .pcap files in captures/ to begin.")
    st.stop()
capture = st.sidebar.selectbox("Packet capture", captures, format_func=lambda p: p.name)

@st.cache_data
def load_capture(path, size, modified):
    return read_packets(path), sha256(path)

try:
    stat = capture.stat()
    (packets, stats), digest = load_capture(str(capture), stat.st_size, stat.st_mtime_ns)
except Exception as error:
    st.error(f"Could not read capture: {error}")
    st.stop()

# Only completed runs with a matching capture hash appear by default.
matched = []
for manifest_path in sorted((ROOT / "logs").rglob("run.json")):
    try:
        manifest = json.loads(manifest_path.read_text())
        if (manifest.get("status") == "completed"
                and manifest.get("capture_sha256") == digest
                and (manifest_path.parent / "eve.json").is_file()):
            matched.append(manifest_path.parent / "eve.json")
    except (OSError, ValueError, AttributeError):
        continue
legacy = st.sidebar.checkbox("Select legacy log manually (unverified pairing)")
if legacy:
    choices = sorted((ROOT / "logs").rglob("eve.json"))
    st.sidebar.warning("Choose the log from this capture. Legacy pairing is not verified.")
else:
    choices = matched
log = st.sidebar.selectbox("Suricata run", [None] + choices,
    format_func=lambda p: "No log selected" if p is None else str(p.relative_to(ROOT)))
alerts = pd.DataFrame()
if log is not None:
    try:
        alerts = read_alerts(log)
    except (OSError, ValueError) as error:
        st.error(f"Could not read EVE log: {error}")
        st.stop()
    if not legacy:
        manifest = json.loads((log.parent / "run.json").read_text())
        st.caption(f"Verified capture pairing · Rules: {manifest['rules_name']} · "
                   f"Checksum checks disabled: {manifest['checksum_checks_disabled']}")
if packets.empty:
    st.info(f"No IPv4 packets. Total captured frames: {stats['total_packets']}.")
    st.stop()
source = st.sidebar.selectbox("Source IP", ["All"] + sorted(packets.src_ip.unique()))
visible = packets if source == "All" else packets[packets.src_ip == source]
shown_alerts = alerts
if source != "All" and not alerts.empty:
    shown_alerts = alerts[alerts.src_ip == source]
a, b, c = st.columns(3)
a.metric("IPv4 packets shown", len(visible))
b.metric("Captured bytes shown", int(visible.captured_bytes.sum()))
c.metric("Suricata alerts shown", len(shown_alerts) if log else "Not loaded")
st.caption(f"Capture total: {stats['total_packets']} · Excluded non-IPv4: "
           f"{stats['excluded_non_ipv4']} · Packet counts are not request counts.")
left, right = st.columns(2)
with left:
    st.subheader("Packets by source IP")
    st.bar_chart(visible.groupby("src_ip").size().rename("Packets"))
with right:
    st.subheader("Packets by IP protocol")
    st.bar_chart(visible.groupby("protocol").size().rename("Packets"))
st.subheader("Client-to-server destination ports")
st.caption("Only 10.200.1.1 → 10.200.1.2. Counts packets, not connections.")
client = visible[(visible.src_ip == "10.200.1.1") & (visible.dest_ip == "10.200.1.2")]
ports = client.dropna(subset=["dest_port"]).groupby("dest_port").size().rename("Packets")
if len(ports):
    ports.index = ports.index.astype(str)
    st.bar_chart(ports)
else:
    st.info("No matching TCP/UDP ports.")
st.subheader("Traffic over time")
# Bound the number of resampled bins for captures spanning long periods.
span = max(0, (visible.timestamp.max() - visible.timestamp.min()).total_seconds())
bin_seconds = max(1, int(span / 2000) + 1)
st.caption(f"Packets per {bin_seconds}-second bin; empty bins are included.")
st.line_chart(visible.set_index("timestamp").resample(f"{bin_seconds}s").size().rename("Packets"))
st.subheader("Triggered Suricata alerts")
if log is None:
    st.info("Select a matching Suricata run to inspect alerts.")
elif shown_alerts.empty:
    st.info("No alerts match this selection.")
else:
    st.dataframe(shown_alerts, hide_index=True)
    st.download_button("Download displayed alerts", shown_alerts.to_csv(index=False),
                       file_name=f"{capture.stem}-alerts.csv", mime="text/csv")
with st.expander("Inspect IPv4 packets"):
    st.dataframe(visible, hide_index=True)
st.download_button("Download displayed packets", visible.to_csv(index=False),
                   file_name=f"{capture.stem}-packets.csv", mime="text/csv")
st.divider()
st.subheader("Python detector: destination-port diversity")
st.caption("Initial TCP SYNs from 10.200.1.1 to 10.200.1.2; independent of Suricata alerts.")
l, r = st.columns(2)
with l:
    window = st.slider("Rolling window (seconds)", 1, 120, 60)
with r:
    threshold = st.slider("Distinct ports required", 2, 30, 10)
if source not in ("All", "10.200.1.1"):
    st.info("Select All or the lab client to inspect this detector.")
else:
    observations, detections = detect_ports(packets, window, threshold)
    peak = int(observations.distinct_ports_in_window.max()) if len(observations) else 0
    a, b, c = st.columns(3)
    a.metric("Initial SYN packets", len(observations))
    b.metric("Peak distinct ports", peak)
    c.metric("Threshold reached", "Yes" if len(detections) else "No")
    if len(detections):
        st.warning(f"Possible scan: first threshold crossing at {detections.iloc[0]['timestamp']}")
    else:
        st.info("The threshold was not reached in this capture.")
    if len(observations):
        with st.expander("Rolling-window observations at SYN arrivals"):
            st.dataframe(observations, hide_index=True)
        st.download_button("Download behavioral observations", observations.to_csv(index=False),
                           file_name=f"{capture.stem}-behavior.csv", mime="text/csv")
st.caption("These are lab indicators, not proof of malicious intent or successful compromise.")
