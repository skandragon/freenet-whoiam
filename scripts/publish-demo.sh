#!/usr/bin/env bash
# Publish the connect-demo app to Freenet as a website contract via fdev.
# Same tunnel/key-store notes as publish-ui.sh.
set -euo pipefail
cd "$(dirname "$0")/.."

export PATH="/opt/homebrew/opt/rustup/bin:$HOME/.cargo/bin:$PATH"

KEY_NAME="${WHOIAM_DEMO_KEY:-whoiam-demo}"
SITE_DIR="target/dx/whoiam-demo/release/web/public"

# Bake the whoiam site's contract id into the build so the URL field comes
# prefilled (same-origin as wherever the demo is served from). Defaults to
# the site published under this key store's "whoiam" key; override with
# WHOIAM_SITE_CONTRACT, or set it empty to leave the field blank.
if [ -z "${WHOIAM_SITE_CONTRACT+x}" ]; then
    WHOIAM_SITE_CONTRACT="$(fdev website list 2>/dev/null | awk '$1 == "whoiam" { print $2 }')"
fi
export WHOIAM_SITE_CONTRACT
echo "baking whoiam site contract: ${WHOIAM_SITE_CONTRACT:-<none>}"

# dx leaves stale hashed bundles behind; a dirty dir publishes them all.
rm -rf "$SITE_DIR"
make demo

if ! nc -z localhost 7509 2>/dev/null; then
    echo "No node on localhost:7509 — start the tunnel first:" >&2
    echo "  ssh -f -L 7509:localhost:7509 explorer@10.46.101.1 sleep 300" >&2
    exit 1
fi

# Exact first-field match: \b-style grep also matches other keys that merely
# START with this name (whoiam-demo-e2e), routing a first publish to `update`.
if fdev website list 2>/dev/null | awk -v k="$KEY_NAME" '$1 == k { found = 1 } END { exit !found }'; then
    fdev website update --key "$KEY_NAME" "$SITE_DIR"
else
    fdev website init "$KEY_NAME"
    fdev website publish --key "$KEY_NAME" "$SITE_DIR"
fi
