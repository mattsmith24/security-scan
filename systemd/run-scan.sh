#!/bin/bash
# Run the scanner with the environment a systemd --user service needs.
#
# systemd starts a service with a minimal PATH. It holds neither uv (in
# ~/.local/bin) nor the Node.js that provides cdxgen (installed by nvm, in a
# directory that changes with each Node.js version), so both are added here
# before the scanner is started. Set the variables below in the unit's
# Environment= lines to point somewhere else.

set -e

repo=${SECURITY_SCAN_REPO:-$(cd "$(dirname "$0")/.." && pwd)}
scanner=$repo/target/release/security-scan

if [ ! -x "$scanner" ]; then
    echo "$scanner is not built; run: cargo build --release" >&2
    exit 1
fi

PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"

# Ask nvm for its current Node.js rather than hard-coding a version, so an
# upgrade of Node.js does not silently take cdxgen away. A Node.js installed
# system-wide needs nothing here.
NVM_DIR=${NVM_DIR:-$HOME/.nvm}
if [ -s "$NVM_DIR/nvm.sh" ]; then
    # shellcheck source=/dev/null
    . "$NVM_DIR/nvm.sh" --no-use
    node_bin=$(nvm which default 2>/dev/null || true)
    if [ -x "$node_bin" ]; then
        PATH="$(dirname "$node_bin"):$PATH"
    fi
fi
export PATH

exec "$scanner" "$repo/config.toml"
