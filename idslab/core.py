"""Shared offline analysis; no packet transmission or elevated privileges."""
from collections import Counter, deque
from decimal import Decimal
from pathlib import Path
import hashlib
import json
import pandas as pd
from scapy.all import IP, TCP, UDP, PcapReader

PACKET_COLUMNS = ["frame_number", "timestamp", "src_ip", "dest_ip", "src_port",
                  "dest_port", "protocol", "captured_bytes", "tcp_flags", "initial_syn"]
ALERT_COLUMNS = ["timestamp", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
                 "app_proto", "alert.signature_id", "alert.signature", "alert.severity",
                 "alert.action", "http.url", "http.status", "flow_id", "pcap_cnt"]
OBS_COLUMNS = ["timestamp", "frame_number", "src_ip", "dest_ip", "dest_port",
               "distinct_ports_in_window"]

def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()

def read_packets(path):
    """One row per IPv4 packet. Frame indices include excluded non-IPv4 frames."""
    rows, total = [], 0
    with PcapReader(str(path)) as capture:
        for number, packet in enumerate(capture, start=1):
            total += 1
            if IP not in packet:
                continue
            ip, transport = packet[IP], packet[IP].payload
            has_ports = isinstance(transport, (TCP, UDP))
            flags = int(transport.flags) if isinstance(transport, TCP) else None
            # Preserve PCAP precision; avoid binary-float timestamp artifacts.
            time_ns = int(Decimal(str(packet.time)) * Decimal(1_000_000_000))
            rows.append({
                "frame_number": number,
                "timestamp": pd.Timestamp(time_ns, unit="ns", tz="UTC"),
                "src_ip": ip.src, "dest_ip": ip.dst,
                "src_port": int(transport.sport) if has_ports else None,
                "dest_port": int(transport.dport) if has_ports else None,
                "protocol": {1: "ICMP", 6: "TCP", 17: "UDP"}.get(
                    int(ip.proto), f"IP protocol {ip.proto}"),
                "captured_bytes": len(packet),
                "tcp_flags": flags,
                "initial_syn": flags is not None and bool(flags & 2) and not bool(flags & 16),
            })
    frame = pd.DataFrame(rows, columns=PACKET_COLUMNS)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True)
    for column in ["src_port", "dest_port", "tcp_flags"]:
        frame[column] = frame[column].astype("Int64")
    frame["initial_syn"] = frame["initial_syn"].astype(bool)
    return frame, {"total_packets": total, "ipv4_packets": len(frame),
                   "excluded_non_ipv4": total - len(frame)}

def read_alerts(path):
    events = []
    with Path(path).open() as file:
        for line_number, line in enumerate(file, start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise ValueError(f"Invalid JSON in {path}, line {line_number}") from error
            if event.get("event_type") == "alert":
                events.append(event)
    # Keep integer IDs exact by parsing individual JSON records before normalization.
    frame = pd.json_normalize(events).reindex(columns=ALERT_COLUMNS)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], utc=True, format="mixed")
    return frame

def detect_ports(packets, window_seconds=60, threshold=10,
                 source="10.200.1.1", destination="10.200.1.2"):
    """Trailing inclusive window, independent state per source/destination pair.

    Returns observations at SYN arrivals and the first detection per pair per capture.
    It does not count attack episodes or emit a Suricata EVE event.
    """
    if window_seconds <= 0 or threshold < 1:
        raise ValueError("Window must be positive and threshold must be at least 1")
    syns = packets[packets["initial_syn"]].copy()
    if source is not None:
        syns = syns[syns["src_ip"] == source]
    if destination is not None:
        syns = syns[syns["dest_ip"] == destination]
    syns = syns.sort_values(["timestamp", "frame_number"])
    windows, counts, detected = {}, {}, set()
    observations, detections = [], []
    duration = pd.Timedelta(seconds=window_seconds)
    for row in syns.itertuples(index=False):
        pair = (row.src_ip, row.dest_ip)
        queue = windows.setdefault(pair, deque())
        counter = counts.setdefault(pair, Counter())
        while queue and queue[0][0] < row.timestamp - duration:
            _, expired = queue.popleft()
            counter[expired] -= 1
            if counter[expired] == 0:
                del counter[expired]
        port = int(row.dest_port)
        queue.append((row.timestamp, port))
        counter[port] += 1
        observation = {"timestamp": row.timestamp, "frame_number": row.frame_number,
                       "src_ip": row.src_ip, "dest_ip": row.dest_ip, "dest_port": port,
                       "distinct_ports_in_window": len(counter)}
        observations.append(observation)
        if len(counter) >= threshold and pair not in detected:
            detected.add(pair)
            detections.append(observation.copy())
    return (pd.DataFrame(observations, columns=OBS_COLUMNS),
            pd.DataFrame(detections, columns=OBS_COLUMNS))

def outcome(actual, detected):
    return ("True positive" if detected else "False negative") if actual else (
        "False positive" if detected else "True negative")
