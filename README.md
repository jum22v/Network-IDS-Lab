# Network Intrusion Detection Lab on Arch Linux

A local, isolated lab combining tcpdump/Wireshark, Suricata custom rules, Python/Pandas analysis, and a Streamlit dashboard.

**Main finding:** a SYN-count rule flagged both repeated normal HTTP requests and a port scan. A rolling distinct-destination-port detector removed that observed benign false positive while still detecting the tested scan. This is evidence from three controlled scenarios, not an estimate of production performance.

## What is included

| Path | Purpose |
|---|---|
| `idslab/core.py` | Shared packet parsing, EVE parsing, rolling-window detection |
| `idslab/__main__.py` | Command-line analysis and comparison |
| `dashboard/app.py` | Interactive local dashboard with CSV exports |
| `rules/local.rules` | Ping pipeline test, SID 1000001 |
| `rules/http.rules` | Exact `/.env` URI detector, SID 1000002 |
| `rules/scan.rules` | Repeated TCP SYN detector, SID 1000003 |
| `scripts/lab_up.sh`, `lab_down.sh` | Create and remove the isolated network |
| `scripts/serve.sh`, `capture.sh`, `traffic.sh` | Server, packet capture, scenario generation |
| `scripts/init_config.py` | Prepare a project-local copy of the installed configuration |
| `scripts/run_ids.py` | Validate/run Suricata; record input hashes and capture pairing |
| `scripts/evaluate_saved_runs.py` | Recreate the combined evaluation from matching completed runs |
| `scenarios.json` | Ground-truth labels for the Python port-scan comparison |
| `reports/observed-results.csv` | User-reported results from the original lab |
| `docs/Obsidian-Network-IDS-Lab.md` | Detailed process, theory, troubleshooting, and review notes |
| `docs/VALIDATION.md` | Checks performed on this packaged implementation |
| `tests/test_core.py` | Synthetic offline boundary and parsing checks |

## Installation from scratch on Arch (Linux distro I used)

### System tools

```bash
sudo pacman -Syu
```

If the kernel was upgraded, reboot before creating the lab. Then:

```bash
sudo pacman -S --needed base-devel git wireshark-qt tcpdump iproute2 iputils curl nmap python python-pip nano less libnet python-yaml
```

Arch is rolling release software. Names and AUR recipes can change. This lab was completed with Suricata **8.0.5**, Vectorscan **5.4.13**, Nmap **7.991**, and curl **8.22.0**. These record the original environment; do not downgrade to reproduce version numbers. Use current supported packages and record what you actually install.

### Suricata via the AUR

Suricata was not available in my enabled official repositories. The AUR recipe required `vectorscan`, which also needed to be built first. AUR recipes are executable community-maintained build instructions: inspect `PKGBUILD` and any associated install/patch files before building. Do not run `makepkg` as root.

```bash
mkdir -p ~/Builds
cd ~/Builds
git clone https://aur.archlinux.org/vectorscan.git
cd vectorscan
less PKGBUILD
CMAKE_BUILD_PARALLEL_LEVEL=1 makepkg -si

cd ~/Builds
git clone https://aur.archlinux.org/suricata.git
cd suricata
less PKGBUILD
```

For the missing OISF signing key encountered in this lab, the official fingerprint was:

```text
B36F DAF2 607E 10E8 FFA8 9E5E 2BA9 C98C CDF1 E93A
```

Compare with the [official verification instructions](https://docs.suricata.io/en/latest/verifying-source-files.html) before import, especially for a future release/key rotation:

```bash
gpg --keyserver hkps://keyserver.ubuntu.com --recv-keys B36FDAF2607E10E8FFA89E5E2BA9C98CCDF1E93A
MAKEFLAGS="-j1" CARGO_BUILD_JOBS=1 makepkg -si
suricata -V
pacman -Ql suricata | grep '/suricata.yaml$'
```

The original archive could also be verified explicitly with `gpg --verify suricata-8.0.5.tar.gz.sig suricata-8.0.5.tar.gz`. Use the actual downloaded filename for other versions. Never work around a failed signature by disabling integrity checks.

If Vectorscan compilation ends in `Killed signal terminated program cc1plus`, inspect memory/OOM logs. The successful recovery in this lab was:

```bash
cd ~/Builds/vectorscan
cmake --build src/build --parallel 1
CMAKE_BUILD_PARALLEL_LEVEL=1 makepkg -esi
```

That build path applies to the recipe used here. A newer recipe might use a different build directory or invoke Ninja directly; inspect it if the setting does not take effect.

### Python environment

From this project root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python scripts/init_config.py
```

Dependency ranges are declared, not a claim of an exact lock of your original machine. After installation you can record your actual environment with `python -m pip freeze > requirements-local.txt` and `suricata --build-info > reports/suricata-build-info.txt`.

## Architecture

| Network namespace | Interface | Address | Purpose |
|---|---|---|---|
| `ids-client` | `veth-client` | `10.200.1.1/24` | Generate lab requests/scans |
| `ids-server` | `veth-server` | `10.200.1.2/24` | Serve HTTP and capture traffic |

Both ends of the veth pair are inside namespaces. No bridge, default route, NAT, or IP forwarding is added. These commands target only the controlled lab server. Network namespaces share the kernel and are not full machine or filesystem isolation.

The web server listens on port 8000. tcpdump captures on the server-side virtual interface. Suricata analyzes a **closed saved PCAP** offline; it is not inline and does not block traffic. Python reads both the PCAP and EVE JSON. The dashboard runs separately on the host's loopback interface.

## Reproduce the experiments

### Start the network and web server

```bash
bash scripts/lab_up.sh
bash scripts/serve.sh
```

The server command stays running. `lab_up.sh` refuses to replace existing namespace names. If your original lab is already running correctly, reuse it rather than running setup again.

### Capture one scenario at a time

In a second terminal, start a capture and wait for tcpdump to say it is listening:

```bash
bash scripts/capture.sh benign-01
```

In a third terminal:

```bash
bash scripts/traffic.sh benign
```

Stop the capture with **Ctrl+C**, then repeat with these pairs:

| Capture command | Traffic command |
|---|---|
| `bash scripts/capture.sh http-test-01` | `bash scripts/traffic.sh http` |
| `bash scripts/capture.sh scan-01` | `bash scripts/traffic.sh scan` |

The capture script refuses to overwrite a file. Use a new scenario name for new evidence, or explicitly archive old captures first. The benign generator sends four pings and eleven requests. The HTTP generator requests `/`, `/missing-page`, and `/.env`. Its scripted timing differs from the original manually entered requests; do not expect identical timestamps, bytes, or all packet counts. The scan tests TCP ports 7990–8010 with a 200 ms probe delay.

Inspect a capture as your normal user:

```bash
wireshark captures/http-test-01.pcap
```

Useful display filters: `icmp`, `http.request`, `tcp.port == 8000`, `ip.src == 10.200.1.1`, and `tcp.flags.syn == 1 && tcp.flags.ack == 0`. If needed, use **Analyze → Decode As → HTTP** for port 8000.

### Run the custom IDS rules

```bash
python scripts/run_ids.py captures/benign-01.pcap --rules rules/local.rules --skip-checksums
python scripts/run_ids.py captures/http-test-01.pcap --rules rules/http.rules --skip-checksums
python scripts/run_ids.py captures/scan-01.pcap --rules rules/scan.rules --skip-checksums
```

The wrapper validates with `-T`, loads only the selected rules with `-S`, reads the PCAP with `-r`, and writes a fresh log directory. `--skip-checksums` adds `-k none` to handle the known virtual-interface offload artifacts. It is **opt-in**, recorded in `run.json`, and should not be assumed appropriate for arbitrary captures.

The wrapper runs as your normal user. Each completed run includes the PCAP hash, rule/config hashes, Suricata version, command, and `eve.json`. The dashboard matches hashes, so renaming or moving a capture does not break content pairing. This is pairing verification, not a signed tamper-proof audit trail. Stop capture first; don't edit inputs during analysis.

Expected original findings: four ping alerts; one exact `/.env` alert despite a 404 response; one scan-rule alert during the 21-port scan. Normal pings are pipeline checks, not malicious findings.

### Analyze and export

```bash
python -m idslab packets captures/http-test-01.pcap --csv reports/generated/http-packets.csv
python -m idslab alerts logs/REPLACE-WITH-RUN/eve.json --csv reports/generated/http-alerts.csv
python -m idslab detect captures/scan-01.pcap --window 60 --threshold 10 --csv reports/generated/scan-behavior.csv
python -m idslab compare scenarios.json --csv reports/generated/python-comparison.csv
```

Replace `REPLACE-WITH-RUN` with the actual printed directory. Tab completion avoids confusing `O` with `0`. Outputs are normal CSV files. `--csv` overwrites the explicitly requested output path if it already exists.

### Evaluate the same Suricata scan rule on every scenario

```bash
for scenario in benign-01 http-test-01 scan-01; do
  python scripts/run_ids.py "captures/$scenario.pcap" --rules rules/scan.rules --skip-checksums || break
done
```

Produce the combined comparison table:

```bash
python scripts/evaluate_saved_runs.py --csv reports/generated/combined-comparison.csv
```

This selects the newest completed run whose capture hash and current scan-rule hash match. It fails explicitly when a matching run is missing; legacy logs can be viewed manually or regenerated with the wrapper.

Use these **scan.rules runs** for comparing false positives, not the earlier ping or HTTP rule runs. Select each corresponding capture and scan-rule run in the dashboard. A suspicious HTTP request is negative ground truth for *port scanning*, even if it is suspicious in another way.

## Dashboard

```bash
python -m streamlit run dashboard/app.py --server.address 127.0.0.1
```

Leave Streamlit's optional email prompt blank and press Enter. Keep the terminal running. Source-IP filtering affects packet and Suricata alert views. The behavioral detector explicitly scopes itself to the original client/server pair and appears for `All` or the client selection. Timestamp normalization is UTC.

The app includes source/protocol charts, client-to-server port counts, traffic over time, alert details, packet tables, CSV downloads, and interactive window/threshold controls. It distinguishes “no log selected” from “zero alerts.” Old logs without `run.json` can be selected with the legacy checkbox; their pairing must be checked manually.

## Recorded results and limits

| Scenario | SYN packets | Distinct ports / 60 s | SYN-rule alerts | SYN-rule outcome | Python outcome |
|---|---:|---:|---:|---|---|
| Normal web requests | 11 | 1 | 1 | False positive | True negative |
| HTTP test | 3 | 1 | 0 | True negative | True negative |
| Port scan | 21 | 21 | 1 | True positive | True positive |

Additional original observations: HTTP capture had 40 total frames, 36 IPv4/TCP packets, and four excluded non-IPv4 frames of unconfirmed type. Client: 19 packets/1,531 captured bytes; server: 17 packets/2,670 bytes. SYN spans: HTTP 17.729 seconds; scan 4.002 seconds. Nmap reported one open port (8000), twenty closed ports, 4.22 seconds total runtime. Both detectors first crossed their scan thresholds at approximately `2026-09-18T18:44:10.422183Z`.

These outcomes are scenario-level, not packet-level labels. Three captures are too small and deliberately constructed to establish real-world precision or recall. The Python detector is an additional heuristic, not a replacement Suricata rule. It misses sufficiently slow or distributed scans, does not analyze IPv6/UDP scanning, and can flag legitimate multi-port activity. Captured byte counts include captured link-layer data but are not total wire utilization. The current implementation retains extracted rows in memory; it targets small lab captures.

## Validation and cleanup

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

Tests cover nine/ten-port boundaries, repeated ports, expiration, independent host pairs, slow scans, PCAP metadata, and malformed EVE input. See `docs/VALIDATION.md` for actual packaging checks and limitations.

Stop tcpdump and the web server with Ctrl+C, then:

```bash
bash scripts/lab_down.sh
```

Cleanup refuses to remove namespaces with running processes. Reboot also removes this temporary network. Captures and logs on disk remain. Stop Streamlit separately with Ctrl+C.

## References

- [Linux network namespaces](https://man.archlinux.org/man/ip-netns.8.en)
- [Virtual Ethernet pairs](https://man.archlinux.org/man/veth.4.en)
- [Suricata Arch installation](https://docs.suricata.io/en/latest/install/other.html)
- [Source signature verification](https://docs.suricata.io/en/latest/verifying-source-files.html)
- [Suricata 8.0.5 command options](https://docs.suricata.io/en/suricata-8.0.5/command-line-options.html)
- [HTTP rules](https://docs.suricata.io/en/suricata-8.0.5/rules/http-keywords.html)
- [Threshold rules](https://docs.suricata.io/en/suricata-8.0.5/rules/thresholding.html)
- [Hyperscan cache configuration](https://docs.suricata.io/en/suricata-8.0.5/performance/hyperscan.html)
- [Nmap TCP connect scans](https://nmap.org/book/man-port-scanning-techniques.html)
- [Scapy usage](https://scapy.readthedocs.io/en/latest/usage.html)
- [Pandas JSON normalization](https://pandas.pydata.org/docs/reference/api/pandas.json_normalize.html)
- [Streamlit documentation](https://docs.streamlit.io/)
