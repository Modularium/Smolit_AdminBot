#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 SOCKET_PATH" >&2
  exit 1
fi

socket_path="$1"

cat <<'JSON' | "$(dirname "$0")/send_request.sh" "$socket_path" -
{
  "version": 1,
  "request_id": "2a6f8f0d-6fa0-4f42-b5d8-6dd9f2a62571",
  "requested_by": {
    "type": "human",
    "id": "local-cli"
  },
  "action": "system.status",
  "params": {},
  "dry_run": false,
  "timeout_ms": 3000
}
JSON
