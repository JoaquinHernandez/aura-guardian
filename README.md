# aura-guardian
# 🛡️ Aura Guardian
<img width="1043" height="718" alt="image" src="https://github.com/user-attachments/assets/7b77eac0-6af4-4d84-b8f4-70221940829e" />


<img width="623" height="459" alt="image" src="https://github.com/user-attachments/assets/926c219a-060c-419b-a7de-68ae0b407e2a" />

---

## ⚡ Highlights

- **Anti-Lockout by Design**: Always protects active SSH management connections, loopback, and local DNS. Starts in **Safe Audit Mode** so it will never disrupt active traffic upon installation.
- **Reverse-Shell Trapping**: Locks the outbound traffic of system web accounts (`www-data`, `nginx`, `apache`). Unsanctioned TCP SYN connections outside allowed destinations trigger immediate kernel alerts and drops.
- **$O(1)$ Ingress Null-Routing**: Bypasses slow linear `iptables` chains using high-speed `ipset (hash:net)` memory tables, keeping latency low even under high connection volume.
- **Zero Third-Party Dependencies**: Pure standard library Python 3 + native Linux utilities (`iptables`, `ipset`).

---

## 🚀 Quick Install (Under 60 Seconds)

### Option A: One-Liner (Automated)
```bash
curl -sSL [https://raw.githubusercontent.com/JoaquinHernandez/aura-guardian/main/install.sh](https://raw.githubusercontent.com/JoaquinHernandez/aura-guardian/main/install.sh) | sudo bash


[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-orange.svg)]()
[![Python: 3.8+](https://img.shields.io/badge/Python-3.8%2B-brightgreen.svg)]()
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-success.svg)]()

**Aura Guardian** is an enterprise-grade, zero-dependency autonomous host defense daemon. Built for small businesses, independent sysadmins, and modern web nodes, it prevents post-exploitation lateral movement and halts automated recon bots in real time.

git clone [https://github.com/JoaquinHernandez/aura-guardian.git](https://github.com/JoaquinHernandez/aura-guardian.git)
cd aura-guardian
sudo ./install.sh

sudo aura-ctl status

sudo aura-ctl test

[*] Running simulated reverse-shell probe as user: www-data
[*] Connecting to 198.51.100.1:4444 (Non-standard egress test)...

=== [Kernel Detection Results] ===
[✓] SUCCESS: Kernel trap caught unauthorized egress attempt:


www-data]: IN= OUT=eth0 SRC=192.168.1.50 DST=198.51.100.1 PROTO=TCP SPT=49152 DPT=4444

sudo aura-ctl enforce

📋 Command Cheat Sheet
Command	Action
sudo aura-ctl status	View active bans, daemon state, and policy mode
sudo aura-ctl test	Trigger simulated reverse shell and verify kernel alerts
sudo aura-ctl logs	Stream guardian live attack detection logs
sudo aura-ctl enforce	Toggle between Audit (passive) and Enforce (active drop) mode
sudo aura-ctl unban <ip>	Manually remove an IP from the kernel null-route table
🧹 Clean Removal
Bash
sudo ./uninstall.sh
⚖️ License
Distributed under the MIT License. See LICENSE for details.


---

### Step-by-Step Test Procedure for Your Own Machine

1. **Create the Project Directory locally:**
   ```bash
   mkdir -p aura-guardian/{bin,etc/aura-guardian,usr/local/sbin}
Save the files above into their designated paths (bin/aura-ctl, install.sh, uninstall.sh, usr/local/sbin/aura-guardian-daemon.py).

Execute local installation:

Bash
cd aura-guardian
chmod +x install.sh uninstall.sh bin/aura-ctl
sudo ./install.sh
Run the self-test:

Bash
sudo aura-ctl test
Inspect the live stream:


Hardened Deployment Checklist
Before pushing this code to your public GitHub repo:

Verify File Permissions:
Ensure the configuration directory and state database are strictly restricted to root:

Bash
sudo chmod 700 /etc/aura-guardian
sudo chmod 600 /etc/aura-guardian/config.json
sudo chmod 700 /var/lib/aura-guard
sudo chmod 700 /usr/local/sbin/aura-guardian-daemon.py
sudo chmod 755 /usr/local/bin/aura-ctl
Run Syntax & Linter Validation:
Ensure no syntax regressions or type errors exist:

Bash
python3 -m py_compile usr/local/sbin/aura-guardian-daemon.py
Verify Reverse-Proxy Configurations:
If running behind a CDN or load balancer (e.g., Cloudflare), ensure Nginx has set_real_ip_from and real_ip_header CF-Connecting-IP; configured. Otherwise, the client IP in access logs will belong to the proxy, risking an inadvertent proxy ban.

Bash
sudo aura-ctl status
sudo aura-ctl logs

