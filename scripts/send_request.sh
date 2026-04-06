#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 SOCKET_PATH [JSON_FILE|-]" >&2
  exit 1
fi

socket_path="$1"
json_source="${2:--}"

python3 - "$socket_path" "$json_source" <<'PY'
import json
import socket
import struct
import sys
from pathlib import Path

socket_path = sys.argv[1]
json_source = sys.argv[2]

if json_source == "-":
    payload = sys.stdin.read()
else:
    payload = Path(json_source).read_text()

data = json.loads(payload)
encoded = json.dumps(data, separators=(",", ":")).encode("utf-8")
frame = struct.pack(">I", len(encoded)) + encoded

with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
    client.connect(socket_path)
    client.sendall(frame)
    header = client.recv(4)
    if len(header) != 4:
        raise SystemExit("short header from daemon")
    expected = struct.unpack(">I", header)[0]
    body = b""
    while len(body) < expected:
        chunk = client.recv(expected - len(body))
        if not chunk:
            break
        body += chunk

print(json.dumps(json.loads(body.decode("utf-8")), indent=2, sort_keys=True))
PY
