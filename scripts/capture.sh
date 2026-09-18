#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
name=${1:-}
if [[ ! "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "Usage: bash scripts/capture.sh http-test-01 (simple name, no extension)"
  exit 1
fi
mkdir -p "$project_root/captures"
# Protect existing evidence from accidental overwrite.
set -o noclobber
sudo ip netns exec ids-server tcpdump -i veth-server -nn -s 0 -U -w - \
  > "$project_root/captures/$name.pcap"
