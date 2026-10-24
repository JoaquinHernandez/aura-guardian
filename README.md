# aura-guardian
# 🛡️ Aura Guardian

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

