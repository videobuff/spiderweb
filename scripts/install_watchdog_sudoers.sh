#!/bin/bash
# Installs the NOPASSWD sudoers rule that lets the watchdog script
# (scripts/watchdog.py) auto-restart dxspider.service after a detected
# mariadb-restart-stale-handle stall. Run with: sudo bash install_watchdog_sudoers.sh
set -e

RULE_FILE=/etc/sudoers.d/dxspider-watchdog
RULE='sysop ALL=(root) NOPASSWD: /usr/bin/systemctl restart dxspider.service'

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo: sudo bash $0" >&2
    exit 1
fi

echo "$RULE" > "$RULE_FILE"
chmod 0440 "$RULE_FILE"
visudo -c

echo "Installed and validated: $RULE_FILE"
