#!/usr/bin/env bash
set -euo pipefail
# Never kill processes implicitly; stop server/capture terminals first.
for ns in ids-client ids-server; do
  if sudo ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    pids=$(sudo ip netns pids "$ns")
    if [[ -n "$pids" ]]; then
      echo "Processes still running in $ns: $pids. Stop them before cleanup."
      exit 1
    fi
  fi
done
for ns in ids-client ids-server; do
  if sudo ip netns list | awk '{print $1}' | grep -Fxq "$ns"; then
    sudo ip netns del "$ns"
  fi
done
