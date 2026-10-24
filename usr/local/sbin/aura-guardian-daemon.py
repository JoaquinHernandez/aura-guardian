#!/usr/bin/env python3
"""
Aura Guardian Defense Daemon - Hardened Core
Enterprise-grade, zero-dependency host containment, dynamic IPSet null-routing,
and kernel-level reverse-shell containment.
"""

import os
import sys
import time
import json
import signal
import subprocess
import pwd
import re
import ipaddress
from datetime import datetime

CONFIG_PATH = "/etc/aura-guardian/config.json"
LOG_FILE = "/var/log/aura-guard/guardian.log"

EXPLOIT_PATTERN = re.compile(
    r'(\.(env|git|svn|aws)|setup\.cgi|wp-config|xmlrpc|/etc/passwd|'
    r'SELECT.*FROM|UNION.*SELECT|<script>|eval\(|base64_decode|system\(|/bin/sh|/bin/bash)',
    re.IGNORECASE
)
LOG_444_PATTERN = re.compile(r'"\s+444\s+')
RAW_IP_PATTERN = re.compile(r'^([0-9a-fA-F:.]+)')


def write_log(msg: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] [AURA-GUARDIAN] {msg}"
    print(entry, flush=True)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except OSError:
        pass


def safe_exec(cmd_args: list) -> tuple:
    """Executes system binaries safely without shell=True."""
    try:
        res = subprocess.run(
            cmd_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        return res.returncode == 0, res.stdout.strip()
    except Exception as err:
        write_log(f"Execution failed for {cmd_args[0]}: {err}")
        return False, ""


def resolve_uid(user_identifier) -> int:
    """Safely converts username or string UID to numeric UID."""
    if isinstance(user_identifier, int):
        return user_identifier
    if str(user_identifier).isdigit():
        return int(user_identifier)
    try:
        return pwd.getpwnam(str(user_identifier)).pw_uid
    except KeyError:
        return None


class BoundedTracker:
    """Sliding-window rate limiter preventing unbounded memory usage."""
    def __init__(self, max_entries: int = 10000, window_seconds: int = 3600):
        self.entries = {}  # ip -> [count, last_seen]
        self.max_entries = max_entries
        self.window_seconds = window_seconds

    def record_violation(self, ip: str) -> int:
        now = time.time()
        self.cleanup(now)

        if ip in self.entries:
            self.entries[ip][0] += 1
            self.entries[ip][1] = now
            return self.entries[ip][0]

        if len(self.entries) >= self.max_entries:
            # Drop the oldest entry to prevent RAM saturation
            oldest = min(self.entries.keys(), key=lambda k: self.entries[k][1])
            del self.entries[oldest]

        self.entries[ip] = [1, now]
        return 1

    def remove(self, ip: str):
        self.entries.pop(ip, None)

    def cleanup(self, current_time: float):
        expired = [
            ip for ip, data in self.entries.items()
            if current_time - data[1] > self.window_seconds
        ]
        for ip in expired:
            del self.entries[ip]


class FirewallManager:
    def __init__(self, config: dict):
        self.cfg = config.get("firewall", {})
        self.ipset_name = str(self.cfg.get("ipset_name", "aura_blacklist"))
        self.max_elem = int(self.cfg.get("ipset_max_elem", 100000))
        self.enforce = bool(self.cfg.get("enforce_egress", False))

    def verify_environment(self):
        for tool in ["iptables", "ipset"]:
            ok, _ = safe_exec(["which", tool])
            if not ok:
                write_log(f"FATAL: Required binary '{tool}' is missing from system PATH.")
                sys.exit(1)

    def init_firewall(self):
        self.verify_environment()
        write_log("Syncing kernel state tables and netfilter chains...")

        # Initialize IPSet hash table safely
        safe_exec([
            "ipset", "create", self.ipset_name, "hash:net",
            "maxelem", str(self.max_elem), "-exist"
        ])

        # Anchor ingress null-routing rule
        ok, _ = safe_exec(["iptables", "-C", "INPUT", "-m", "set", "--match-set", self.ipset_name, "src", "-j", "DROP"])
        if not ok:
            safe_exec([
                "iptables", "-I", "INPUT", "1", "-m", "set",
                "--match-set", self.ipset_name, "src", "-j", "DROP",
                "-m", "comment", "--comment", "Aura Ingress Drop"
            ])

        # Baseline Egress Safeguards: Always allow loopback, established states, and SSH
        self._ensure_rule(["-o", "lo", "-j", "ACCEPT"], ["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        self._ensure_rule(
            ["-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"]
        )
        self._ensure_rule(
            ["-p", "tcp", "--sport", "22", "-j", "ACCEPT"],
            ["iptables", "-A", "OUTPUT", "-p", "tcp", "--sport", "22", "-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "ACCEPT", "-m", "comment", "--comment", "Aura Protect SSH"]
        )

        egress = self.cfg.get("egress_rules", {})
        restricted_users = egress.get("restricted_users", ["www-data"])

        for user in restricted_users:
            uid = resolve_uid(user)
            if uid is None:
                write_log(f"Notice: User '{user}' not present on host. Skipping egress lockdown.")
                continue

            # Core Protocol Grants
            if egress.get("allow_dns", True):
                self._ensure_rule(
                    [f"Aura Allowed DNS UDP {uid}"],
                    ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-p", "udp", "--dport", "53", "-j", "ACCEPT", "-m", "comment", "--comment", f"Aura Allowed DNS UDP {uid}"]
                )
                self._ensure_rule(
                    [f"Aura Allowed DNS TCP {uid}"],
                    ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-p", "tcp", "--dport", "53", "-j", "ACCEPT", "-m", "comment", "--comment", f"Aura Allowed DNS TCP {uid}"]
                )

            if egress.get("allow_http_https", True):
                self._ensure_rule(
                    [f"Aura Allowed HTTPS {uid}"],
                    ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-p", "tcp", "--dport", "443", "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT", "-m", "comment", "--comment", f"Aura Allowed HTTPS {uid}"]
                )
                self._ensure_rule(
                    [f"Aura Allowed HTTP {uid}"],
                    ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-p", "tcp", "--dport", "80", "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT", "-m", "comment", "--comment", f"Aura Allowed HTTP {uid}"]
                )

            if egress.get("allow_ntp", True):
                self._ensure_rule(
                    [f"Aura Allowed NTP {uid}"],
                    ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-p", "udp", "--dport", "123", "-j", "ACCEPT", "-m", "comment", "--comment", f"Aura Allowed NTP {uid}"]
                )

            # Custom Ports (Integer Validated)
            for raw_port in egress.get("extra_allowed_tcp_ports", []):
                try:
                    port = int(raw_port)
                    if not (1 <= port <= 65535):
                        continue
                except ValueError:
                    continue
                self._ensure_rule(
                    [f"Aura TCP Extra {port} {uid}"],
                    ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-p", "tcp", "--dport", str(port), "-m", "conntrack", "--ctstate", "NEW", "-j", "ACCEPT", "-m", "comment", "--comment", f"Aura TCP Extra {port} {uid}"]
                )

            # Custom Destination Endpoints
            for item in egress.get("extra_allowed_destinations", []):
                proto = "tcp" if item.get("proto", "").lower() == "tcp" else "udp"
                try:
                    port = int(item.get("port", 0))
                    dest_ip = str(ipaddress.ip_address(item.get("destination", "")))
                    if not (1 <= port <= 65535):
                        continue
                except ValueError:
                    continue

                sig = f"Aura Custom {dest_ip}:{port}"
                self._ensure_rule(
                    [sig],
                    ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-p", proto, "-d", dest_ip, "--dport", str(port), "-j", "ACCEPT", "-m", "comment", "--comment", sig]
                )

            # Egress Trap: Kernel Logging
            self._ensure_rule(
                [f"[AURA_REV_SHELL_ALERT_{user}]:"],
                ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-m", "conntrack", "--ctstate", "NEW", "-j", "LOG", "--log-prefix", f"[AURA_REV_SHELL_ALERT_{user}]: ", "--log-level", "4"]
            )

            # Egress Trap: Enforcement Drop
            if self.enforce:
                self._ensure_rule(
                    [f"Aura Block {user} Reverse Shell"],
                    ["iptables", "-A", "OUTPUT", "-m", "owner", "--uid-owner", str(uid), "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP", "-m", "comment", "--comment", f"Aura Block {user} Reverse Shell"]
                )
            else:
                write_log(f"Notice: Safe Audit Mode is active for user '{user}' (alerts logged, drops disabled).")

    def _ensure_rule(self, match_patterns: list, full_cmd: list):
        ok, active_rules = safe_exec(["iptables", "-S", "OUTPUT"])
        if not ok:
            return
        if not all(pattern in active_rules for pattern in match_patterns):
            safe_exec(full_cmd)


class AuraGuardian:
    def __init__(self, config: dict):
        self.config = config
        self.fw = FirewallManager(config)
        self.daemon_cfg = config.get("daemon", {})
        self.ban_duration = int(self.daemon_cfg.get("ban_duration_seconds", 86400))
        self.trigger_threshold = int(self.daemon_cfg.get("trigger_threshold", 3))
        self.state_file = str(self.daemon_cfg.get("state_file", "/var/lib/aura-guard/bans.json"))
        self.watched_logs = self.daemon_cfg.get("watched_logs", [])

        # Parse & Validate Whitelists
        self.whitelisted_ips = set()
        for raw_ip in self.config.get("firewall", {}).get("whitelisted_ips", []):
            try:
                self.whitelisted_ips.add(ipaddress.ip_address(raw_ip))
            except ValueError:
                pass

        self.whitelisted_subnets = []
        for raw_net in self.config.get("firewall", {}).get("whitelisted_subnets", []):
            try:
                self.whitelisted_subnets.append(ipaddress.ip_network(raw_net, strict=False))
            except ValueError:
                pass

        self.tracker = BoundedTracker(max_entries=10000, window_seconds=3600)
        self.active_bans = {}
        self.running = True
        self._load_state()

    def _load_state(self):
        if not os.path.exists(self.state_file):
            return
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    self.active_bans = {str(k): float(v) for k, v in data.items()}
            write_log(f"Restored {len(self.active_bans)} active bans from state cache.")
        except Exception as err:
            write_log(f"Warning: Could not read state cache: {err}")

    def _save_state(self):
        """Atomic state save to prevent zero-byte corruption during crashes."""
        state_dir = os.path.dirname(self.state_file)
        os.makedirs(state_dir, exist_ok=True)
        tmp_path = f"{self.state_file}.tmp.{os.getpid()}"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(self.active_bans, f)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp_path, 0o600)
            os.replace(tmp_path, self.state_file)
        except Exception as err:
            write_log(f"Error persisting state file atomically: {err}")
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    def is_whitelisted(self, ip_obj: ipaddress.IPv4Address) -> bool:
        if ip_obj in self.whitelisted_ips:
            return True
        if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
            return True
        for network in self.whitelisted_subnets:
            if ip_obj in network:
                return True
        return False

    def ban_ip(self, ip_str: str, reason: str):
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            return

        if self.is_whitelisted(ip_obj):
            return

        safe_exec(["ipset", "add", self.fw.ipset_name, ip_str, "-exist"])
        self.active_bans[ip_str] = time.time()
        self.tracker.remove(ip_str)
        self._save_state()
        write_log(f"BAN EXECUTED: {ip_str} | Reason: {reason}")

    def purge_expired(self):
        now = time.time()
        expired = [ip for ip, btime in self.active_bans.items() if now - btime > self.ban_duration]
        for ip in expired:
            safe_exec(["ipset", "del", self.fw.ipset_name, ip, "-exist"])
            del self.active_bans[ip]
            write_log(f"BAN EXPIRED: {ip}")
        if expired:
            self._save_state()

    def inspect_line(self, line: str):
        match = RAW_IP_PATTERN.search(line)
        if not match:
            return
        candidate_ip = match.group(1).strip()

        try:
            ip_obj = ipaddress.ip_address(candidate_ip)
        except ValueError:
            return

        if self.is_whitelisted(ip_obj) or candidate_ip in self.active_bans:
            return

        reason = None
        if LOG_444_PATTERN.search(line):
            reason = "HTTP_444_DROP"
        elif EXPLOIT_PATTERN.search(line):
            reason = "EXPLOIT_SIGNATURE_MATCH"

        if reason:
            count = self.tracker.record_violation(candidate_ip)
            if count >= self.trigger_threshold or reason == "EXPLOIT_SIGNATURE_MATCH":
                self.ban_ip(candidate_ip, f"{reason} (Violations: {count})")

    def run(self):
        self.fw.init_firewall()
        write_log("Guardian initialized. Tail-monitoring web server logs...")

        handles = {}
        for path in self.watched_logs:
            if os.path.exists(path):
                try:
                    f = open(path, "r", encoding="utf-8", errors="replace")
                    f.seek(0, os.SEEK_END)
                    handles[path] = f
                    write_log(f"Attached monitor to: {path}")
                except OSError as err:
                    write_log(f"Unable to read log target {path}: {err}")

        last_expiry_check = time.time()
        poll_interval = float(self.daemon_cfg.get("monitor_interval_seconds", 1.0))

        while self.running:
            for path, f in list(handles.items()):
                while True:
                    line = f.readline()
                    if not line:
                        break
                    self.inspect_line(line)

            # Inode validation for logrotate handling
            for path in self.watched_logs:
                if path not in handles and os.path.exists(path):
                    try:
                        f = open(path, "r", encoding="utf-8", errors="replace")
                        f.seek(0, os.SEEK_END)
                        handles[path] = f
                        write_log(f"Attached to newly created log: {path}")
                    except OSError:
                        pass
                elif path in handles:
                    try:
                        if os.stat(path).st_ino != os.fstat(handles[path].fileno()).st_ino:
                            handles[path].close()
                            handles[path] = open(path, "r", encoding="utf-8", errors="replace")
                            write_log(f"Re-hooked rotated log target: {path}")
                    except Exception:
                        pass

            if time.time() - last_expiry_check > 300:
                self.purge_expired()
                last_expiry_check = time.time()

            time.sleep(poll_interval)

        # Graceful cleanup outside signal handler
        for f in handles.values():
            try:
                f.close()
            except Exception:
                pass


_ACTIVE_DAEMON = None


def sig_handler(signum, frame):
    """Sets a loop flag so shutdown runs cleanly in the main thread."""
    global _ACTIVE_DAEMON
    if _ACTIVE_DAEMON:
        _ACTIVE_DAEMON.running = False


if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Fatal: aura-guardian must run with root permissions.")
        sys.exit(1)

    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGINT, sig_handler)

    if not os.path.exists(CONFIG_PATH):
        print(f"Fatal: Configuration missing at {CONFIG_PATH}")
        sys.exit(1)

    with open(CONFIG_PATH, "r", encoding="utf-8") as cfg_file:
        conf = json.load(cfg_file)

    _ACTIVE_DAEMON = AuraGuardian(conf)
    try:
        _ACTIVE_DAEMON.run()
    finally:
        write_log("Daemon stopped. Saving persistent netfilter tables...")
        ok, _ = safe_exec(["which", "netfilter-persistent"])
        if ok:
            safe_exec(["netfilter-persistent", "save"])
