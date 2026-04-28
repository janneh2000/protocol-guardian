#!/bin/sh
set -e
CONFIG="${AXL_CONFIG:-/node/node-config.json}"
KEY="${AXL_KEY:-/node/private.pem}"

if [ ! -f "$KEY" ]; then
  echo "[axl] generating ed25519 key at $KEY"
  openssl genpkey -algorithm ed25519 -out "$KEY"
fi

echo "[axl] booting with config $CONFIG"
exec /usr/local/bin/axl-node -config "$CONFIG"
