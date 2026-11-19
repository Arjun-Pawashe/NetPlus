import os
import subprocess
import threading


class WindowsFirewallEnforcer:
    """
    Enforces per-device daily MB quotas at the OS level on Windows 10/11
    using `netsh advfirewall firewall` rules.
    Rules are named `NetPlus_QuotaBlock_<IP>` so they can be cleanly added,
    listed, and removed without touching unrelated Windows Firewall rules.
    """

    RULE_PREFIX = "NetPlus_QuotaBlock_"

    def __init__(self, dry_run: bool = False):
        self.dry_run = dry_run or (os.name != "nt")
        self._lock = threading.Lock()
        self._enforced_ips = set()
        self.last_error = ""

    def _rule_name(self, ip: str) -> str:
        return f"{self.RULE_PREFIX}{ip}"

    def block_ip(self, ip: str) -> bool:
        if not ip or ip in ("127.0.0.1", "localhost"):
            return False
        with self._lock:
            if ip in self._enforced_ips:
                return True
            if self.dry_run:
                self._enforced_ips.add(ip)
                return True

            rule = self._rule_name(ip)
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                # Block routed traffic from this client IP via Windows Firewall
                subprocess.run(
                    [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name={rule}",
                        "dir=in",
                        "action=block",
                        f"remoteip={ip}",
                        "enable=yes",
                    ],
                    capture_output=True, text=True, timeout=5, check=True, creationflags=flags
                )
                self._enforced_ips.add(ip)
                self.last_error = ""
                print(f"🛡️  Windows Firewall quota block applied for {ip} ({rule})")
                return True
            except Exception as exc:
                self.last_error = f"Firewall rule failed for {ip}: {exc}"
                print(f"⚠️  {self.last_error}")
                return False

    def unblock_ip(self, ip: str) -> bool:
        if not ip:
            return False
        with self._lock:
            self._enforced_ips.discard(ip)
            if self.dry_run:
                return True

            rule = self._rule_name(ip)
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"],
                    capture_output=True, text=True, timeout=5, check=False, creationflags=flags
                )
                return True
            except Exception as exc:
                self.last_error = str(exc)
                return False

    def sync_quotas(self, exceeded_ips: set):
        """Ensure firewall rules match the current set of quota-exceeded IPs."""
        with self._lock:
            currently_blocked = set(self._enforced_ips)

        for ip in currently_blocked - exceeded_ips:
            self.unblock_ip(ip)
        for ip in exceeded_ips - currently_blocked:
            self.block_ip(ip)

    def get_enforced_ips(self) -> list:
        with self._lock:
            return sorted(self._enforced_ips)

    def cleanup_all(self):
        for ip in self.get_enforced_ips():
            self.unblock_ip(ip)
