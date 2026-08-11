#!/usr/bin/env bash
# Publish the whoiam UI to Freenet as a website contract via fdev.
#
# fdev only talks to loopback; the explorer node's websocket API is tunneled:
#   ssh -f -L 7509:localhost:7509 explorer@10.46.101.1 sleep 300
#
# First publish mints the site key (kept in fdev's key store — BACK IT UP;
# it is the only way to ever update the site). Subsequent runs update in
# place, keeping the same contract address.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

KEY_NAME="${WHOIAM_SITE_KEY:-whoiam}"
SITE_DIR="target/dx/whoiam-ui/release/web/public"

make ui

if ! nc -z localhost 7509 2>/dev/null; then
    echo "No node on localhost:7509 — start the tunnel first:" >&2
    echo "  ssh -f -L 7509:localhost:7509 explorer@10.46.101.1 sleep 300" >&2
    exit 1
fi

# No grep -q: its early exit SIGPIPEs fdev, which pipefail turns into a miss.
if fdev website list 2>/dev/null | grep "\b${KEY_NAME}\b" >/dev/null; then
    fdev website update --key "$KEY_NAME" "$SITE_DIR"
else
    # Local Ed25519 keygen only; the key lives in fdev's store — back it up,
    # it is the only way to ever update the site.
    fdev website init "$KEY_NAME"
    fdev website publish --key "$KEY_NAME" "$SITE_DIR"
fi
