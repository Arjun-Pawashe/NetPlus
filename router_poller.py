import base64
import os
import re
import threading
import time
import urllib.request
from typing import Dict, List, Optional


class TLWR740NPoller:
    """
    Optional poller for TP-Link TL-WR740N stock web UI.
    Polls `/userRpm/WlanStationRpm.htm` and `/userRpm/StatusRpm.htm`
    using HTTP Basic Auth + Referer header (required by TP-Link stock firmware)
    to enrich wireless client MACs, packet counts, SSID, and router uptime.
    """

    def __init__(
        self,
        router_ip: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        enabled: Optional[bool] = None,
        poll_interval: int = 20,
    ):
        self.router_ip = (router_ip or os.environ.get("NETPLUS_ROUTER_IP", "192.168.137.2")).strip()
        self.username = username or os.environ.get("NETPLUS_ROUTER_USER", "admin")
        self.password = password or os.environ.get("NETPLUS_ROUTER_PASS", "admin")
        if enabled is None:
            env_flag = os.environ.get("NETPLUS_ROUTER_POLL", "0").strip().lower()
            self.enabled = env_flag in ("1", "true", "yes", "on")
        else:
            self.enabled = enabled
        self.poll_interval = poll_interval

        self.running = False
        self.status = "disabled" if not self.enabled else "starting"
        self.last_poll = None
        self.last_error = ""
        self.ssid = ""
        self.uptime = ""
        self.wireless_stations: List[Dict] = []
        self._lock = threading.Lock()

    def configure(self, router_ip: str, username: str, password: str, enabled: bool):
        with self._lock:
            self.router_ip = router_ip.strip()
            self.username = username
            self.password = password
            self.enabled = enabled
            self.status = "starting" if enabled else "disabled"
            self.last_error = ""
        if enabled and not self.running:
            self.start()

    def start(self):
        if self.running or not self.enabled:
            return
        self.running = True
        threading.Thread(target=self._poll_loop, daemon=True).start()

    def stop(self):
        self.running = False

    def _fetch_page(self, path: str) -> str:
        url = f"http://{self.router_ip}{path}"
        token = base64.b64encode(f"{self.username}:{self.password}".encode("utf-8")).decode("ascii")
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Basic {token}",
                "Referer": f"http://{self.router_ip}/",
                "User-Agent": "NetPlus-RouterMonitor/1.0",
            },
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.read().decode("utf-8", errors="ignore")

    @staticmethod
    def parse_wlan_stations(html: str) -> List[Dict]:
        """Parse TP-Link `hostList` JS array from WlanStationRpm.htm."""
        stations = []
        m = re.search(r"var\s+hostList\s*=\s*new\s+Array\((.*?)\);", html, re.S)
        if not m:
            return stations
        raw_items = re.findall(r'"([^"]*)"|(\d+)', m.group(1))
        tokens = [a if a else b for a, b in raw_items]
        for i in range(0, len(tokens) - 3, 4):
            mac = tokens[i].replace("-", ":").lower()
            if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
                stations.append({
                    "mac": mac,
                    "status_code": tokens[i + 1],
                    "rx_packets": int(tokens[i + 2]) if tokens[i + 2].isdigit() else 0,
                    "tx_packets": int(tokens[i + 3]) if tokens[i + 3].isdigit() else 0,
                })
        return stations

    @staticmethod
    def parse_status_info(html: str) -> Dict:
        info = {"ssid": "", "uptime": ""}
        m_wlan = re.search(r"var\s+wlanPara\s*=\s*new\s+Array\((.*?)\);", html, re.S)
        if m_wlan:
            raw_items = re.findall(r'"([^"]*)"|(\d+)', m_wlan.group(1))
            tokens = [a if a else b for a, b in raw_items]
            if len(tokens) >= 2 and not tokens[1].isdigit():
                info["ssid"] = tokens[1]
            else:
                strs = [a for a, _ in raw_items if a]
                if strs:
                    info["ssid"] = strs[0]
        return info

    def poll_once(self) -> bool:
        if not self.enabled:
            return False
        try:
            wlan_html = self._fetch_page("/userRpm/WlanStationRpm.htm")
            stations = self.parse_wlan_stations(wlan_html)
            status_info = {"ssid": "", "uptime": ""}
            try:
                status_html = self._fetch_page("/userRpm/StatusRpm.htm")
                status_info = self.parse_status_info(status_html)
            except Exception:
                pass
            with self._lock:
                self.wireless_stations = stations
                self.ssid = status_info.get("ssid", "")
                self.uptime = status_info.get("uptime", "")
                self.status = "connected"
                self.last_poll = time.strftime("%Y-%m-%d %H:%M:%S")
                self.last_error = ""
            return True
        except Exception as exc:
            with self._lock:
                self.status = "unreachable"
                self.last_error = str(exc)
            return False

    def _poll_loop(self):
        while self.running:
            if self.enabled:
                self.poll_once()
            time.sleep(self.poll_interval)

    def get_snapshot(self) -> Dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "router_ip": self.router_ip,
                "status": self.status,
                "ssid": self.ssid,
                "last_poll": self.last_poll,
                "last_error": self.last_error,
                "wireless_stations": list(self.wireless_stations),
                "wireless_count": len(self.wireless_stations),
            }
