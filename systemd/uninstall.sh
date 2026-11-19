#!/bin/bash
# Remove the daily security scan's systemd --user units.

set -euo pipefail

unit_dir=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user

systemctl --user disable --now security-scan.timer 2>/dev/null || true
rm -f "$unit_dir/security-scan.service" "$unit_dir/security-scan.timer"
systemctl --user daemon-reload

echo "removed from $unit_dir"
