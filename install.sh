#!/usr/bin/env bash
set -euo pipefail

cat << 'EOF'
    ___                             ______                       __ _            
   /   |  __  ___________ _        / ____/_  ______ _________/ /(_)___ _____    
  / /| | / / / / ___/ __ `/______ / / __/ / / / __ `/ ___/ __  / / __ `/ __ \   
 / ___ |/ /_/ / /  / /_/ /_____// /_/ / /_/ / /_/ / /  / /_/ / / /_/ / / / /   
/_/  |_|\__,_/_/   \__,_/       \____/\__,_/\__,_/_/   \__,_/_/\__,_/_/ /_/    
                                                                                
EOF

if [[ $EUID -ne 0 ]]; then
   echo "[-] Error: This installation script must be executed as root." 
   exit 1
fi

echo "[*] Step 1/5: Validating environment and package dependencies..."
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y -qq ipset iptables iptables-persistent netfilter-persistent python3
elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q ipset iptables python3
elif command -v yum >/dev/null 2>&1; then
    yum install -y -q ipset iptables python3
elif command -v pacman >/dev/null 2>&1; then
    pacman -Sy --noconfirm ipset iptables python
else
    echo "[!] Non-standard distro detected. Verifying essential tools..."
    for tool in ipset iptables python3; do
        command -v "$tool" >/dev/null 2>&1 \vert{}\vert{} { echo "[-] Missing $tool. Please install it first."; exit 1; }
    done
fi

echo "[*] Step 2/5: Creating isolated runbook & state directories..."
mkdir -p /etc/aura-guardian
mkdir -p /var/lib/aura-guard
mkdir -p /var/log/aura-guard
touch /var/log/aura-guard/guardian.log
chmod 750 /var/log/aura-guard

echo "[*] Step 3/5: Detecting system service accounts & active log locations..."
WEB_USER="nobody"
for candidate in www-data nginx apache httpd caddy; do
    if id "$candidate" >/dev/null 2>&1; then
        WEB_USER="$candidate"
        break
    fi
done
echo "[i] Bound daemon to web service identity: '${WEB_USER}'"

WATCHED_LOGS='["/var/log/nginx/access.log", "/var/log/nginx/error.log"]'
if [[ -f "/var/log/httpd/access_log" ]]; then
    WATCHED_LOGS='["/var/log/httpd/access_log", "/var/log/httpd/error_log"]'
elif [[ -f "/var/log/apache2/access.log" ]]; then
    WATCHED_LOGS='["/var/log/apache2/access.log", "/var/log/apache2/error.log"]'
fi

CONFIG_FILE="/etc/aura-guardian/config.json"
if [[ ! -f "$CONFIG_FILE" ]]; then
    cat <<EOF > "$CONFIG_FILE"
{
  "firewall": {
    "ipset_name": "aura_blacklist",
    "ipset_max_elem": 100000,
    "enforce_egress": false,
    "whitelisted_ips": [
      "127.0.0.1",
      "::1"
    ],
    "whitelisted_subnets": [
      "10.0.0.0/8",
      "172.16.0.0/12",
      "192.168.0.0/16"
    ],
    "egress_rules": {
      "restricted_users": ["${WEB_USER}"],
      "allow_dns": true,
      "allow_ntp": true,
      "allow_http_https": true,
      "extra_allowed_tcp_ports": [],
      "extra_allowed_destinations": []
    }
  },
  "daemon": {
    "ban_duration_seconds": 86400,
    "trigger_threshold": 3,
    "monitor_interval_seconds": 1.0,
    "state_file": "/var/lib/aura-guard/bans.json",
    "watched_logs": ${WATCHED_LOGS}
  }
}
EOF
    chmod 600 "$CONFIG_FILE"
    echo "[✓] Config created with Safe Audit Mode enabled."
else
    echo "[i] Existing configuration found at $CONFIG_FILE. Preserving intact."
fi

echo "[*] Step 4/5: Installing daemon core, helper CLI, and systemd units..."
# If running from cloned git repo:
if [[ -f "usr/local/sbin/aura-guardian-daemon.py" ]]; then
    cp usr/local/sbin/aura-guardian-daemon.py /usr/local/sbin/aura-guardian-daemon.py
    cp bin/aura-ctl /usr/local/bin/aura-ctl
else
    # Fallback to direct raw downloads if piped from curl
    RAW_BASE="https://raw.githubusercontent.com/JoaquinHernandez/aura-guardian/main"
    curl -sSL "${RAW_BASE}/usr/local/sbin/aura-guardian-daemon.py" -o /usr/local/sbin/aura-guardian-daemon.py
    curl -sSL "${RAW_BASE}/bin/aura-ctl" -o /usr/local/bin/aura-ctl
fi

chmod 700 /usr/local/sbin/aura-guardian-daemon.py
chmod 755 /usr/local/bin/aura-ctl

cat << 'EOF' > /etc/systemd/system/aura-guardian.service
[Unit]
Description=Aura Host Guardian & Active Defense Daemon
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 -u /usr/local/sbin/aura-guardian-daemon.py
Restart=always
RestartSec=3
KillMode=process
StandardOutput=append:/var/log/aura-guard/guardian.log
StandardError=append:/var/log/aura-guard/guardian.log

[Install]
WantedBy=multi-user.target
EOF

chmod 644 /etc/systemd/system/aura-guardian.service
systemctl daemon-reload
systemctl enable aura-guardian.service

echo "[*] Step 5/5: Starting defense daemon..."
systemctl restart aura-guardian.service

echo ""
echo "=================================================================="
echo " [✓] Aura Guardian is installed and running in SAFE AUDIT mode!   "
echo "=================================================================="
echo "Quick Checks:"
echo "  • View status and rules:   sudo aura-ctl status"
echo "  • Test reverse-shell trap: sudo aura-ctl test"
echo "  • View real-time logs:     sudo aura-ctl logs"
echo "  • Turn on active blocking: sudo aura-ctl enforce"
echo "=================================================================="
