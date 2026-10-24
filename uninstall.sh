#!/usr/bin/env bash
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: Please execute as root (sudo ./uninstall.sh)."
   exit 1
fi

echo "[*] Deactivating Aura Guardian service..."
systemctl stop aura-guardian.service 2>/dev/null || true
systemctl disable aura-guardian.service 2>/dev/null || true
rm -f /etc/systemd/system/aura-guardian.service
systemctl daemon-reload

echo "[*] Purging kernel netfilter injection rules..."
# Remove Input matching rule
iptables -D INPUT -m set --match-set aura_blacklist src -j DROP 2>/dev/null || true

# Purge any Aura-managed rules from OUTPUT chain
iptables-save | grep -v "Aura" | iptables-restore 2>/dev/null || true

# Destroy IPSet hash map
ipset destroy aura_blacklist 2>/dev/null || true

echo "[*] Removing binaries and state caches..."
rm -f /usr/local/sbin/aura-guardian-daemon.py
rm -f /usr/local/bin/aura-ctl
rm -rf /var/lib/aura-guard

echo ""
echo "[✓] Complete: Aura Guardian has been safely removed."
echo "[i] Your configuration (/etc/aura-guardian) and logs (/var/log/aura-guard) were preserved."
