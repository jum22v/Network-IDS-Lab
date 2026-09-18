#!/usr/bin/env bash
set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
sudo ip netns exec ids-server runuser -u "$(id -un)" -- \
  /usr/bin/python -m http.server 8000 --bind 10.200.1.2 --directory "$project_root/www"
