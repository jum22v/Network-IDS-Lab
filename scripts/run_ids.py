"""Validate rules, analyze a closed PCAP, and record reproducible input pairing."""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from idslab.core import sha256


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("pcap", type=Path)
    p.add_argument("--rules", required=True, type=Path)
    p.add_argument("--skip-checksums", action="store_true",
                   help="Use only for known lab offload artifacts; recorded in manifest")
    args = p.parse_args()
    capture, rules = args.pcap.resolve(), args.rules.resolve()
    config = ROOT / "config/suricata.yaml"
    for file in [capture, rules, config]:
        if not file.is_file():
            p.error(f"Missing input: {file}")
    cache = ROOT / "cache/sgh"
    cache.mkdir(parents=True, exist_ok=True)
    (ROOT / "logs").mkdir(exist_ok=True)
    output = Path(tempfile.mkdtemp(prefix=capture.stem + "-", dir=ROOT / "logs"))
    common = ["suricata", "-c", str(config), "-S", str(rules), "-l", str(output),
              "--set", f"detect.sgh-mpm-caching-path={cache}"]
    capture_hash = sha256(capture)
    command = common + ["-r", str(capture), "--runmode", "single"]
    if args.skip_checksums:
        command += ["-k", "none"]
    try:
        version = subprocess.check_output(["suricata", "-V"], text=True).strip()
        subprocess.run(common + ["-T"], check=True)
        subprocess.run(command, check=True)
        if sha256(capture) != capture_hash:
            raise RuntimeError("Capture changed during analysis; stop capture before running.")
        if not (output / "eve.json").exists():
            raise RuntimeError("No eve.json produced; check EVE output in configuration.")
        manifest = {
            "schema_version": 1,
            "created_utc": datetime.now(timezone.utc).isoformat(),
            "capture_name": capture.name, "capture_sha256": capture_hash,
            "rules_name": rules.name, "rules_sha256": sha256(rules),
            "config_sha256": sha256(config),
            "config_sibling_hashes": {f.name: sha256(f) for f in config.parent.iterdir()
                                     if f.is_file() and f.suffix in (".yaml", ".config")},
            "suricata_version": version, "checksum_checks_disabled": args.skip_checksums,
            "command": command, "status": "completed",
        }
        (output / "run.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(f"\nCompleted run: {output}\nEVE: {output / 'eve.json'}")
    except (OSError, subprocess.CalledProcessError, RuntimeError) as error:
        p.exit(1, f"Run failed: {error}\nInspect logs in {output}\n")

if __name__ == "__main__":
    main()
