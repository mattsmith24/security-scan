#!/bin/bash
# Install the daily security scan as systemd --user units.
#
# The units are generated from the .in files in this directory, with @REPO@
# replaced by this checkout's path, so the service runs this copy of the
# scanner wherever it lives.

set -euo pipefail

unit_dir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user
repo=$(cd "$(dirname "$0")/.." && pwd)

# The service runs the release binary, so build it now rather than leaving
# the timer to fail on a checkout that has never been built.
cargo build --release --manifest-path "$repo/Cargo.toml"

install -d "$unit_dir"
for unit in security-scan.service security-scan.timer; do
    sed "s|@REPO@|$repo|g" "$repo/systemd/$unit.in" > "$unit_dir/$unit"
done

systemctl --user daemon-reload
systemctl --user enable --now security-scan.timer

echo
if [ "$(loginctl show-user "$USER" --property=Linger --value 2>/dev/null)" != yes ]; then
    echo "note: the timer runs only while you are logged in. To keep it running"
    echo "      after logout, enable lingering: loginctl enable-linger"
    echo
fi

echo "installed in $unit_dir; next run:"
systemctl --user list-timers security-scan.timer --no-pager
