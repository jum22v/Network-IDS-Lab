"""Run from project root: python -m idslab --help"""
import argparse
import json
from pathlib import Path
import pandas as pd
from .core import read_packets, read_alerts, detect_ports, outcome

def main():
    parser = argparse.ArgumentParser(description="Offline network lab analysis")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("packets", help="Summarize and optionally export IPv4 packets")
    p.add_argument("pcap", type=Path)
    p.add_argument("--csv", type=Path)
    p = sub.add_parser("alerts", help="Read Suricata EVE alerts")
    p.add_argument("eve", type=Path)
    p.add_argument("--csv", type=Path)
    p = sub.add_parser("detect", help="Rolling destination-port detector")
    p.add_argument("pcap", type=Path)
    p.add_argument("--window", type=float, default=60)
    p.add_argument("--threshold", type=int, default=10)
    p.add_argument("--csv", type=Path, help="Export observations at each SYN")
    p = sub.add_parser("compare", help="Evaluate Python detector using scenario labels")
    p.add_argument("scenarios", type=Path, help="JSON list; capture paths relative to this file")
    p.add_argument("--window", type=float, default=60)
    p.add_argument("--threshold", type=int, default=10)
    p.add_argument("--csv", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "alerts":
            frame = read_alerts(args.eve)
            print(frame.to_string(index=False))
            print(f"Total alerts: {len(frame)}")
        elif args.command in ["packets", "detect"]:
            packets, stats = read_packets(args.pcap)
            if args.command == "packets":
                frame = packets
                print(json.dumps(stats, indent=2))
                print(packets.groupby("src_ip").agg(
                    packet_count=("frame_number", "size"),
                    captured_bytes=("captured_bytes", "sum")).to_string())
                print(packets["protocol"].value_counts().to_string())
            else:
                frame, detections = detect_ports(packets, args.window, args.threshold)
                print(frame.to_string(index=False))
                print("First detections per source/destination pair:")
                print(detections.to_string(index=False))
        else:
            rows = []
            for scenario in json.loads(args.scenarios.read_text()):
                actual = scenario["actual_port_scan"]
                if not isinstance(actual, bool):
                    raise ValueError("actual_port_scan must be a JSON boolean")
                path = args.scenarios.parent / scenario["capture"]
                packets, _ = read_packets(path)
                observations, detections = detect_ports(packets, args.window, args.threshold)
                rows.append({"scenario": scenario["scenario"],
                    "actual_port_scan": actual,
                    "initial_syn_packets": len(observations),
                    "max_distinct_ports_in_window": int(observations[
                        "distinct_ports_in_window"].max()) if len(observations) else 0,
                    "scan_detected": not detections.empty,
                    "outcome": outcome(actual, not detections.empty)})
            frame = pd.DataFrame(rows)
            print(frame.to_string(index=False))
        if args.csv:
            args.csv.parent.mkdir(parents=True, exist_ok=True)
            frame.to_csv(args.csv, index=False)
            print(f"Saved {args.csv}")
    except (OSError, ValueError, KeyError, EOFError) as error:
        parser.exit(1, f"Error: {error}\n")

if __name__ == "__main__":
    main()
