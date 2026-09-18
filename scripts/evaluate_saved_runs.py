"""Compare scan-rule runs with Python findings using capture hashes and known labels."""
import argparse
import json
from pathlib import Path
import sys
import pandas as pd
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from idslab.core import sha256, read_packets, read_alerts, detect_ports, outcome


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', type=Path)
    args = parser.parse_args()
    rows = []
    try:
        expected_rules_hash = sha256(ROOT / 'rules/scan.rules')
        manifests = []
        for path in (ROOT / 'logs').rglob('run.json'):
            data = json.loads(path.read_text())
            if data.get('status') == 'completed':
                manifests.append((path, data))
        for scenario in json.loads((ROOT / 'scenarios.json').read_text()):
            capture = ROOT / scenario['capture']
            digest = sha256(capture)
            matches = [(p, d) for p, d in manifests
                       if d.get('capture_sha256') == digest
                       and d.get('rules_sha256') == expected_rules_hash]
            if not matches:
                raise ValueError(f"No matching completed scan.rules run for {capture.name}. "
                                 "Run scripts/run_ids.py with --rules rules/scan.rules first.")
            path, manifest = max(matches, key=lambda item: item[1]['created_utc'])
            alerts = read_alerts(path.parent / 'eve.json')
            count = int((alerts['alert.signature_id'] == 1000003).sum())
            packets, _ = read_packets(capture)
            observations, detections = detect_ports(packets)
            actual = scenario['actual_port_scan']
            if not isinstance(actual, bool):
                raise ValueError('actual_port_scan must be a JSON boolean')
            rows.append({
                'scenario': scenario['scenario'], 'actual_port_scan': actual,
                'scan_rule_alerts': count, 'suricata_outcome': outcome(actual, count > 0),
                'max_distinct_ports_60s': int(observations.distinct_ports_in_window.max())
                    if len(observations) else 0,
                'python_detected': not detections.empty,
                'python_outcome': outcome(actual, not detections.empty),
                'suricata_run': str(path.parent.relative_to(ROOT)),
            })
        frame = pd.DataFrame(rows)
        print(frame.to_string(index=False))
        print('\nUses the most recent completed matching scan-rule run per capture.')
        if args.csv:
            args.csv.parent.mkdir(parents=True, exist_ok=True)
            frame.to_csv(args.csv, index=False)
    except (OSError, ValueError, KeyError) as error:
        parser.exit(1, f'Error: {error}\n')

if __name__ == '__main__':
    main()
