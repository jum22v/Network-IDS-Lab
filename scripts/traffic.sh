#!/usr/bin/env bash
set -euo pipefail
request() {
  sudo ip netns exec ids-client curl --noproxy '*' -sS -o /dev/null \
    -w '%{http_code}\n' "http://10.200.1.2:8000$1"
}
case "${1:-}" in
  benign)
    sudo ip netns exec ids-client ping -c 4 10.200.1.2
    request /
    for i in {1..10}; do request /; sleep 1; done
    ;;
  http)
    request /
    request /missing-page
    request /.env
    ;;
  scan)
    sudo ip netns exec ids-client nmap -sT -Pn -n -p 7990-8010 --scan-delay 200ms 10.200.1.2
    ;;
  *) echo "Usage: bash scripts/traffic.sh benign|http|scan"; exit 1 ;;
esac
