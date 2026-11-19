import os
import queue
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import datetime

from db import (
    CLIENT_NETWORK,
    DB_PATH,
    DEPARTMENTS,
    DIVISIONS,
    GATEWAY_IP,
    GENERIC_NAME_RE,
    NAME_PRIORITY,
    ONLINE_WINDOW_SEC,
    YEARS,
    clean_and_normalize_domain,
    clean_hostname,
    fallback_device_name,
    init_db,
    is_client_ip,
    parse_user_agent,
)
from dns_sinkhole import CAPTIVE_PROBE_DOMAINS, DnsSinkholeServer
from firewall_enforcer import WindowsFirewallEnforcer
from packet_sniffer import CaptivePortalHttpRedirector, PacketSnifferEngine
from router_poller import TLWR740NPoller

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class NetworkGatewayEngine:
    """
    NetPlus Router-Gateway Engine for Windows 10/11 + TP-Link TL-WR740N (AP/Bridge Mode).
    Replaces manual HTTP proxy interception with:
      1. UDP Port 53 DNS Forwarder & Sinkhole
      2. Npcap/Scapy TLS SNI + HTTP Host + Byte-Accounting Sniffer
      3. Port 80 Captive Portal Redirector for unregistered students
      4. Windows Firewall (`netsh advfirewall`) Daily Quota Enforcer
      5. Optional TP-Link TL-WR740N Web-UI Poller
    """

    def __init__(self):
        self.running = False
        self.blocked_domains = set()
        self.ws_subscribers = []
        self.lock = threading.Lock()
        self._quota_cache = {}
        self._quota_cache_ts = 0
        self._mac_cache = {}
        self._registration_tokens = {}
        self._prompted_keys = set()
        self._removed_keys = set()
        self._name_state = {}
        self._name_queue = queue.Queue()
        self._name_workers_started = False
        self._own_hostname = socket.gethostname()
        self._daily_byte_offsets = {}  # {ip: extra_bytes_from_sniffer_not_in_domain_rows}
        self._byte_lock = threading.Lock()

        init_db()
        self._load_prompted_keys()
        self._load_removed_keys()
        self.load_blocklist()
        self._refresh_quota_cache()

        self.firewall = WindowsFirewallEnforcer()
        self.router_poller = TLWR740NPoller()
        self.dns_server = DnsSinkholeServer(
            listen_ip=os.environ.get("NETPLUS_DNS_LISTEN_IP", "0.0.0.0"),
            gateway_ip=GATEWAY_IP,
            on_query=self._on_dns_query,
            is_blocked_fn=lambda q: self.is_blocked(q, clean_and_normalize_domain(q)[0]),
            should_captive_redirect_fn=self._should_captive_redirect,
        )
        self.captive_http = CaptivePortalHttpRedirector(
            listen_ip=os.environ.get("NETPLUS_CAPTIVE_LISTEN_IP", GATEWAY_IP),
            dashboard_port=int(os.environ.get("NETPLUS_DASHBOARD_PORT", "5000")),
            issue_token_fn=self.issue_registration_token,
            is_quota_exceeded_fn=self.is_quota_exceeded,
        )
        self.sniffer = PacketSnifferEngine(
            is_client_ip_fn=is_client_ip,
            on_domain_seen=self._on_sniffer_domain,
            on_bytes_seen=self._on_sniffer_bytes,
            gateway_ip=GATEWAY_IP,
        )

    # ─── Prompt & Tombstone Persistence ─────────────────────────
    def _load_prompted_keys(self):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                self._prompted_keys = {r[0] for r in conn.execute("SELECT device_key FROM registration_prompts")}
        except sqlite3.Error:
            self._prompted_keys = set()

    def _load_removed_keys(self):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                self._removed_keys = {r[0] for r in conn.execute("SELECT device_key FROM removed_devices")}
        except sqlite3.Error:
            self._removed_keys = set()

    def _is_removed(self, ip, mac):
        return bool(self._removed_keys) and ((mac or ip or "").lower() in self._removed_keys)

    def _clear_removed(self, ip, mac):
        keys = {k for k in ((ip or "").lower(), (mac or "").lower()) if k and k in self._removed_keys}
        if not keys:
            return
        self._removed_keys -= keys
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                conn.executemany("DELETE FROM removed_devices WHERE device_key=?", [(k,) for k in keys])
        except sqlite3.Error:
            pass

    # ─── Quota & Blocklist ──────────────────────────────────────
    def _refresh_quota_cache(self):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                rows = conn.execute(
                    "SELECT ip, daily_mb_limit FROM device_quotas WHERE enabled = 1 AND daily_mb_limit > 0"
                ).fetchall()
            self._quota_cache = {r[0]: r[1] for r in rows}
            self._quota_cache_ts = time.time()
        except Exception:
            pass

    def get_daily_usage_mb(self, ip: str) -> float:
        try:
            today = datetime.now().strftime("%Y-%m-%d")
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                total_bytes = conn.execute(
                    "SELECT COALESCE(SUM(bytes_transferred),0) FROM access_logs WHERE client_ip = ? AND timestamp LIKE ?",
                    (ip, f"{today}%"),
                ).fetchone()[0] or 0
            return total_bytes / (1024 * 1024)
        except Exception:
            return 0.0

    def is_quota_exceeded(self, ip: str) -> bool:
        if time.time() - self._quota_cache_ts > 60:
            self._refresh_quota_cache()
        limit_mb = self._quota_cache.get(ip, 0)
        if limit_mb <= 0:
            return False
        return self.get_daily_usage_mb(ip) >= limit_mb

    def set_quota(self, ip: str, daily_mb_limit: int):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO device_quotas (ip, daily_mb_limit, enabled, created_at) VALUES (?, ?, 1, ?)",
                    (ip, daily_mb_limit, now),
                )
        except Exception as e:
            print(f"Quota set error: {e}")
        self._refresh_quota_cache()
        self._sync_firewall_quotas()

    def remove_quota(self, ip: str):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                conn.execute("DELETE FROM device_quotas WHERE ip = ?", (ip,))
        except Exception as e:
            print(f"Quota remove error: {e}")
        self._refresh_quota_cache()
        self.firewall.unblock_ip(ip)

    def _sync_firewall_quotas(self):
        self._refresh_quota_cache()
        exceeded = {ip for ip in self._quota_cache if self.is_quota_exceeded(ip)}
        self.firewall.sync_quotas(exceeded)

    def load_blocklist(self):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                rows = conn.execute("SELECT domain FROM blocklist").fetchall()
            self.blocked_domains = {r[0].lower() for r in rows}
        except Exception:
            pass

    def add_block_rule(self, domain: str, reason: str = "Restricted by policy"):
        domain = domain.strip().lower()
        with self.lock:
            self.blocked_domains.add(domain)
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO blocklist (domain, reason, created_at) VALUES (?, ?, ?)",
                    (domain, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
        except Exception as e:
            print(f"Error saving block rule: {e}")

    def remove_block_rule(self, domain: str):
        domain = domain.strip().lower()
        with self.lock:
            self.blocked_domains.discard(domain)
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                conn.execute("DELETE FROM blocklist WHERE domain = ?", (domain,))
        except Exception as e:
            print(f"Error removing block rule: {e}")

    def is_blocked(self, domain: str, clean_site: str) -> bool:
        d1 = (domain or "").lower()
        d2 = (clean_site or "").lower()
        with self.lock:
            rules = list(self.blocked_domains)
        return any(b in d1 or b in d2 for b in rules)

    # ─── Device Naming & Lifecycle ──────────────────────────────
    def rename_device(self, ip: str, new_name: str):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                conn.execute("UPDATE devices SET custom_name = ? WHERE ip = ?", (new_name, ip))
                conn.execute("UPDATE access_logs SET device_name = ? WHERE client_ip = ?", (new_name, ip))
        except Exception as e:
            print(f"Error updating device name: {e}")

    def clear_device_history(self, ip: str) -> int:
        with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
            return conn.execute("DELETE FROM access_logs WHERE client_ip=?", (ip,)).rowcount

    def remove_device(self, ip: str):
        with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
            row = conn.execute("SELECT COALESCE(mac_address,'') FROM devices WHERE ip=?", (ip,)).fetchone()
            logs = conn.execute("DELETE FROM access_logs WHERE client_ip=?", (ip,)).rowcount
            dev = conn.execute("DELETE FROM devices WHERE ip=?", (ip,)).rowcount
            conn.execute("DELETE FROM device_quotas WHERE ip=?", (ip,))
            key = ((row[0] if row else "") or ip).lower()
            if dev:
                conn.execute(
                    "INSERT OR REPLACE INTO removed_devices (device_key, removed_at) VALUES (?, ?)",
                    (key, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
                )
                self._removed_keys.add(key)
        self._mac_cache.pop(ip, None)
        self._name_state.pop(ip, None)
        self._refresh_quota_cache()
        self.firewall.unblock_ip(ip)
        return bool(dev), logs

    def _stored_priority(self, name, source):
        if source:
            return NAME_PRIORITY.get(source, 0)
        return 0 if (not name or GENERIC_NAME_RE.match(name)) else NAME_PRIORITY["ua"]

    def get_or_create_device(self, ip: str, ua_string: str = "") -> dict:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ua_info = parse_user_agent(ua_string) if ua_string else None
        ua_known = bool(ua_info) and not ua_info["name"].startswith(("Unknown Device", "Mobile Device"))
        last_octet = ip.split(".")[-1]
        mac = self.get_mac_for_ip(ip)

        if self._removed_keys:
            self._clear_removed(ip, mac)

        with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
            row = conn.execute(
                "SELECT ip, custom_name, auto_name, device_type, COALESCE(name_source,'') FROM devices WHERE ip = ?",
                (ip,),
            ).fetchone()

            if row:
                custom_name, auto_name, dev_type, src = row[1], row[2], row[3], row[4]
                if ua_known and NAME_PRIORITY["ua"] > self._stored_priority(auto_name, src):
                    auto_name = f"{ua_info['name']} (#{last_octet})"
                    dev_type = ua_info["type"]
                    conn.execute(
                        "UPDATE devices SET auto_name = ?, device_type = ?, name_source = 'ua', last_seen = ?, "
                        "mac_address = COALESCE(NULLIF(?, ''), mac_address) WHERE ip = ?",
                        (auto_name, dev_type, timestamp, mac or "", ip),
                    )
                else:
                    conn.execute(
                        "UPDATE devices SET last_seen = ?, mac_address = COALESCE(NULLIF(?, ''), mac_address) WHERE ip = ?",
                        (timestamp, mac or "", ip),
                    )
                name = custom_name or auto_name
            else:
                if ip == "127.0.0.1":
                    auto_name, dev_type, src = "Host PC (Localhost)", "desktop", "system"
                elif ua_known:
                    suffix = f"#{last_octet}" if is_client_ip(ip) else ip
                    auto_name, dev_type, src = f"{ua_info['name']} ({suffix})", ua_info["type"], "ua"
                else:
                    auto_name, dev_type, src = (
                        fallback_device_name(ip, mac or ""),
                        (ua_info or {}).get("type", "mobile"),
                        "fallback",
                    )
                conn.execute(
                    "INSERT INTO devices (ip, custom_name, auto_name, device_type, first_seen, last_seen, mac_address, name_source) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (ip, "", auto_name, dev_type, timestamp, timestamp, mac or "", src),
                )
                name = auto_name

        self._schedule_name_refresh(ip)
        if mac:
            stu = self.get_student_by_mac(mac)
            if stu:
                self.record_attendance(stu, ip=ip)

        return {"ip": ip, "name": name, "device_type": dev_type}

    def resolve_hostname(self, ip: str):
        if ip in ("127.0.0.1", "::1"):
            return None
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            name = clean_hostname(socket.gethostbyaddr(ip)[0], self._own_hostname)
            if name:
                return name
        except Exception:
            pass
        if os.name != "nt":
            return None
        try:
            r = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3, creationflags=flags)
            m = re.search(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", r.stdout, re.M)
            if m:
                name = clean_hostname(m.group(1), self._own_hostname)
                if name:
                    return name
        except Exception:
            pass
        try:
            r = subprocess.run(
                ["ping", "-a", "-n", "1", "-w", "700", ip],
                capture_output=True, text=True, timeout=4, creationflags=flags,
            )
            m = re.search(r"Pinging\s+(\S+)\s+\[" + re.escape(ip) + r"\]", r.stdout)
            if m:
                return clean_hostname(m.group(1), self._own_hostname)
        except Exception:
            pass
        return None

    def refresh_device_name(self, ip: str) -> bool:
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                row = conn.execute(
                    "SELECT COALESCE(custom_name,''), COALESCE(auto_name,''), COALESCE(device_type,'mobile'), "
                    "COALESCE(name_source,''), COALESCE(mac_address,''), COALESCE(last_seen,'') FROM devices WHERE ip=?",
                    (ip,),
                ).fetchone()
                if not row:
                    return True
                custom, auto, dtype, src, mac, last_seen = row
                cur_pri = self._stored_priority(auto, src)

                ua_row = conn.execute(
                    "SELECT user_agent FROM access_logs WHERE client_ip=? AND user_agent IS NOT NULL AND user_agent!='' ORDER BY id DESC LIMIT 1",
                    (ip,),
                ).fetchone()
                ua_info = parse_user_agent(ua_row[0]) if ua_row else None
                ua_known = bool(ua_info) and not ua_info["name"].startswith(("Unknown Device", "Mobile Device"))
                if ua_info:
                    dtype = ua_info["type"]

                cand = None
                student = self.get_student_by_mac(mac) if mac else None
                if student:
                    cand = (f"{student['name']}'s Device", "student")
                else:
                    online = False
                    try:
                        online = (datetime.now() - datetime.strptime(last_seen, "%Y-%m-%d %H:%M:%S")).total_seconds() <= ONLINE_WINDOW_SEC
                    except Exception:
                        pass
                    host = self.resolve_hostname(ip) if online else None
                    if host:
                        cand = (host, "host")
                    elif ua_known:
                        suffix = f"#{ip.split('.')[-1]}" if is_client_ip(ip) else ip
                        cand = (f"{ua_info['name']} ({suffix})", "ua")
                    elif cur_pri == 0:
                        cand = (fallback_device_name(ip, mac), "fallback")

                if cand:
                    name, source = cand
                    better = NAME_PRIORITY[source] > cur_pri
                    changed_same = NAME_PRIORITY[source] == cur_pri and source in ("host", "student") and name != auto
                    if better or changed_same:
                        conn.execute(
                            "UPDATE devices SET auto_name=?, device_type=?, name_source=? WHERE ip=?",
                            (name, dtype, source, ip),
                        )
                        if not custom:
                            conn.execute("UPDATE access_logs SET device_name=? WHERE client_ip=?", (name, ip))
                        src = source
                if custom:
                    return True
                return src in ("host", "student", "system")
        except Exception as e:
            print(f"Name refresh failed for {ip}: {e}")
            return False

    def _schedule_name_refresh(self, ip: str):
        if not ip:
            return
        now = time.time()
        st = self._name_state.get(ip)
        if st and st[2]:
            return
        interval = 15 if (not st or st[1] < 4) else 300
        if st and now - st[0] < interval:
            return
        self._name_state[ip] = (now, (st[1] + 1) if st else 1, False)
        self._name_queue.put(ip)

    def _name_worker_loop(self):
        while self.running:
            try:
                ip = self._name_queue.get(timeout=2)
            except queue.Empty:
                continue
            final = self.refresh_device_name(ip)
            st = self._name_state.get(ip)
            if st and final:
                self._name_state[ip] = (st[0], st[1], True)

    def _schedule_all_names(self):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                ips = [r[0] for r in conn.execute("SELECT ip FROM devices")]
            for ip in ips:
                self._schedule_name_refresh(ip)
        except sqlite3.Error:
            pass

    # ─── ARP / Neighbor MAC Discovery ───────────────────────────
    def get_mac_for_ip(self, ip: str):
        if not ip:
            return None
        if ip in ("127.0.0.1", "localhost", "::1"):
            return "host:local:mac:01"
        if ip in self._mac_cache and time.time() - self._mac_cache[ip][1] < 15:
            return self._mac_cache[ip][0]
        try:
            if os.name == "nt":
                flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
                result = subprocess.run(
                    ["arp", "-a", ip], capture_output=True, text=True, timeout=2, check=False, creationflags=flags
                )
                match = re.search(r"\b" + re.escape(ip) + r"\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b", result.stdout, re.I)
                if not match:
                    result = subprocess.run(
                        ["arp", "-a"], capture_output=True, text=True, timeout=2, check=False, creationflags=flags
                    )
                    match = re.search(r"\b" + re.escape(ip) + r"\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b", result.stdout, re.I)
                mac = match.group(1).replace("-", ":").lower() if match else None
            else:
                mac = None
                try:
                    result = subprocess.run(["ip", "neigh", "show", "to", ip], capture_output=True, text=True, timeout=2, check=False)
                    match = re.search(r"\blladdr\s+(([0-9a-f]{2}:){5}[0-9a-f]{2})\b", result.stdout, re.I)
                    mac = match.group(1).lower() if match else None
                except FileNotFoundError:
                    pass
                if not mac and os.path.exists("/proc/net/arp"):
                    with open("/proc/net/arp", encoding="ascii") as arp_table:
                        for line in arp_table:
                            fields = line.split()
                            if len(fields) >= 4 and fields[0] == ip and fields[3] != "00:00:00:00:00:00":
                                mac = fields[3].lower()
                                break
            if mac:
                self._mac_cache[ip] = (mac, time.time())
            return mac
        except Exception:
            return None

    def scan_connected_devices(self):
        found = []
        try:
            if os.name == "nt":
                r = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=2,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                entries = []
                for line in r.stdout.splitlines():
                    match = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+dynamic", line)
                    if match:
                        entries.append((match.group(1), match.group(2).replace("-", ":").lower()))
            else:
                r = subprocess.run(["ip", "neigh", "show"], capture_output=True, text=True, timeout=2, check=False)
                entries = []
                for line in r.stdout.splitlines():
                    match = re.match(r"^\s*(\d+\.\d+\.\d+\.\d+)\s+.*?\blladdr\s+(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b", line)
                    if match:
                        entries.append((match.group(1), match.group(2).lower()))

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for ip, mac in entries:
                if not is_client_ip(ip):
                    continue
                self._mac_cache[ip] = (mac, time.time())
                found.append((ip, mac))

            if found:
                to_record, to_name = [], []
                with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                    for ip, mac in found:
                        stu = conn.execute(
                            "SELECT mac_address, prn, name, batch, COALESCE(department,''), COALESCE(year,''), COALESCE(division,'') "
                            "FROM students WHERE mac_address = ?",
                            (mac,),
                        ).fetchone()
                        if stu:
                            to_record.append(
                                ({"mac_address": stu[0], "prn": stu[1], "name": stu[2], "batch": stu[3],
                                  "department": stu[4], "year": stu[5], "division": stu[6]}, ip)
                            )
                        if self._is_removed(ip, mac):
                            continue
                        if conn.execute("SELECT ip FROM devices WHERE ip = ?", (ip,)).fetchone():
                            conn.execute("UPDATE devices SET last_seen = ?, mac_address = ? WHERE ip = ?", (now, mac, ip))
                        else:
                            auto_name, src = (f"{stu[2]}'s Device", "student") if stu else (fallback_device_name(ip, mac), "fallback")
                            conn.execute(
                                "INSERT INTO devices (ip, custom_name, auto_name, device_type, first_seen, last_seen, mac_address, name_source) "
                                "VALUES (?, '', ?, 'mobile', ?, ?, ?, ?)",
                                (ip, auto_name, now, now, mac, src),
                            )
                        to_name.append(ip)
                for student_dict, client_ip in to_record:
                    self.record_attendance(student_dict, ip=client_ip)
                for ip in to_name:
                    self._schedule_name_refresh(ip)
        except Exception:
            pass
        return found

    def _device_monitor_loop(self):
        tick = 0
        while self.running:
            try:
                self.scan_connected_devices()
                if tick % 2 == 0:
                    self._sync_firewall_quotas()
            except Exception:
                pass
            tick += 1
            time.sleep(6)

    # ─── Attendance & Captive Registration ──────────────────────
    def get_student_by_mac(self, mac):
        if not mac:
            return None
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                row = conn.execute(
                    "SELECT mac_address, prn, name, batch, COALESCE(department,''), COALESCE(year,''), COALESCE(division,'') "
                    "FROM students WHERE mac_address=?",
                    (mac,),
                ).fetchone()
            return (
                {"mac_address": row[0], "prn": row[1], "name": row[2], "batch": row[3],
                 "department": row[4], "year": row[5], "division": row[6]}
                if row else None
            )
        except sqlite3.Error:
            return None

    def get_active_session(self):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                row = conn.execute(
                    "SELECT id, session_type, title, session_date, year, division, batch "
                    "FROM sessions WHERE status='active' ORDER BY id DESC LIMIT 1"
                ).fetchone()
            if not row:
                return None
            return {"id": row[0], "session_type": row[1], "title": row[2], "session_date": row[3],
                    "year": row[4], "division": row[5], "batch": row[6]}
        except sqlite3.Error:
            return None

    @staticmethod
    def student_in_session(student, session):
        for key in ("year", "division", "batch"):
            wanted = session.get(key, "") or ""
            if wanted and (student.get(key, "") or "") != wanted:
                return False
        return True

    def record_attendance(self, student, ip=""):
        session = self.get_active_session()
        if not session or not self.student_in_session(student, session):
            return False
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dept = student.get("department", "") or ""
        year = student.get("year", "") or ""
        div = student.get("division", "") or ""
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                already = (
                    conn.execute(
                        "SELECT 1 FROM attendance WHERE mac_address=? AND session_id=?",
                        (student["mac_address"], session["id"]),
                    ).fetchone() is not None
                )
                conn.execute(
                    """
                    INSERT INTO attendance
                        (mac_address, prn, student_name, batch, department, year, division,
                         attendance_date, first_seen, last_seen, connection_count, ip_address, status, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 'Present', ?)
                    ON CONFLICT(mac_address, session_id) DO UPDATE SET
                        last_seen=excluded.last_seen,
                        connection_count=attendance.connection_count + 1,
                        prn=excluded.prn, student_name=excluded.student_name, batch=excluded.batch,
                        department=excluded.department, year=excluded.year, division=excluded.division,
                        ip_address=CASE WHEN excluded.ip_address != '' THEN excluded.ip_address ELSE attendance.ip_address END,
                        status='Present'
                    """,
                    (student["mac_address"], student["prn"], student["name"], student["batch"],
                     dept, year, div, session["session_date"], now, now, ip or "", session["id"]),
                )
            if not already:
                self.broadcast_event({
                    "type": "ATTENDANCE_RECORDED",
                    "session_id": session["id"],
                    "session_type": session["session_type"],
                    "student_name": student["name"],
                    "prn": student["prn"],
                    "batch": student["batch"],
                    "department": dept,
                    "year": year,
                    "division": div,
                    "mac_address": student["mac_address"],
                    "ip_address": ip,
                    "time": now,
                })
            return True
        except Exception as e:
            print(f"Error recording attendance: {e}")
            return False

    def _should_captive_redirect(self, client_ip: str, qname: str) -> bool:
        if qname not in CAPTIVE_PROBE_DOMAINS:
            return False
        if not is_client_ip(client_ip):
            return False
        mac = self.get_mac_for_ip(client_ip)
        if mac and self.get_student_by_mac(mac):
            return False
        return True

    def reset_prompts(self, device_key=None):
        with self.lock:
            if device_key:
                self._prompted_keys.discard(device_key.lower())
            else:
                self._prompted_keys.clear()
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                if device_key:
                    conn.execute("DELETE FROM registration_prompts WHERE device_key=?", (device_key.lower(),))
                else:
                    conn.execute("DELETE FROM registration_prompts")
        except sqlite3.Error:
            pass

    def issue_registration_token(self, ip: str) -> str:
        now = time.time()
        for existing, (_, expires) in list(self._registration_tokens.items()):
            if expires <= now:
                self._registration_tokens.pop(existing, None)
        for existing, (token_ip, expires) in self._registration_tokens.items():
            if token_ip == ip and expires > now:
                return existing
        token = secrets.token_urlsafe(24)
        self._registration_tokens[token] = (ip, now + 3600)
        return token

    def get_registration_ip(self, token: str):
        item = self._registration_tokens.get(token)
        if not item:
            return None
        if item[1] < time.time():
            self._registration_tokens.pop(token, None)
            return None
        return item[0]

    def consume_registration_token(self, token: str):
        self._registration_tokens.pop(token, None)

    # ─── Capture Callbacks (DNS + Sniffer) ──────────────────────
    def _on_dns_query(self, client_ip: str, domain: str, status: str):
        self._record_domain_event(client_ip, domain, "DNS", "", 128, force_status=status)

    def _on_sniffer_domain(self, client_ip: str, domain: str, method: str, ua: str, pkt_bytes: int):
        self._record_domain_event(client_ip, domain, method, ua, pkt_bytes)

    def _on_sniffer_bytes(self, client_ip: str, byte_count: int):
        """Credit real packet byte counts to the client's most recent log row for today,
        or create a background traffic-accounting entry if none exists yet."""
        if byte_count <= 0:
            return
        today = datetime.now().strftime("%Y-%m-%d")
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                row = conn.execute(
                    "SELECT id FROM access_logs WHERE client_ip=? AND timestamp LIKE ? ORDER BY id DESC LIMIT 1",
                    (client_ip, f"{today}%"),
                ).fetchone()
                if row:
                    conn.execute(
                        "UPDATE access_logs SET bytes_transferred = COALESCE(bytes_transferred,0) + ? WHERE id=?",
                        (byte_count, row[0]),
                    )
                else:
                    dev = self.get_or_create_device(client_ip)
                    conn.execute(
                        "INSERT INTO access_logs (timestamp, client_ip, device_name, device_type, domain, clean_site, "
                        "is_background, category, method, bytes_transferred, status, risk_flag, user_agent) "
                        "VALUES (?, ?, ?, ?, 'gateway-flow', 'gateway-flow', 1, 'Background & OS Telemetry', 'FLOW', ?, 'Allowed', 'Normal', '')",
                        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_ip, dev["name"], dev["device_type"], byte_count),
                    )
        except Exception:
            pass

    def _record_domain_event(
        self,
        client_ip: str,
        domain: str,
        method: str,
        user_agent: str = "",
        byte_count: int = 0,
        force_status: str = None,
    ):
        if not domain:
            return
        device_info = self.get_or_create_device(client_ip, user_agent)
        clean_site, category, is_background = clean_and_normalize_domain(domain)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        blocked = force_status == "Blocked" or self.is_blocked(domain, clean_site)
        quota_hit = not is_background and self.is_quota_exceeded(client_ip)

        if blocked:
            status, risk_flag = "Blocked", "Policy Violation"
        elif quota_hit:
            status, risk_flag = "Blocked", "Quota Exceeded"
            self.firewall.block_ip(client_ip)
        else:
            status = "Allowed"
            if category == "Gaming & Arcade":
                risk_flag = "Restricted Gaming"
            elif category == "Proxy & Bypass":
                risk_flag = "Bypass Attempt"
            else:
                risk_flag = "Normal"

        self.log_event({
            "timestamp": timestamp,
            "client_ip": client_ip,
            "device_name": device_info["name"],
            "device_type": device_info["device_type"],
            "domain": domain,
            "clean_site": clean_site,
            "is_background": is_background,
            "category": category,
            "method": method,
            "bytes": byte_count,
            "status": status,
            "risk_flag": risk_flag,
            "user_agent": user_agent,
        })

    # ─── Logging & WebSocket Broadcast ──────────────────────────
    def log_event(self, entry: dict):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                conn.execute(
                    """
                    INSERT INTO access_logs (timestamp, client_ip, device_name, device_type, domain, clean_site,
                        is_background, category, method, bytes_transferred, status, risk_flag, user_agent)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        entry["timestamp"],
                        entry["client_ip"],
                        entry["device_name"],
                        entry["device_type"],
                        entry["domain"],
                        entry["clean_site"],
                        1 if entry.get("is_background") else 0,
                        entry["category"],
                        entry["method"],
                        entry["bytes"],
                        entry["status"],
                        entry["risk_flag"],
                        entry.get("user_agent", ""),
                    ),
                )
        except Exception as e:
            print(f"DB Error: {e}")
        self.broadcast_event(entry)

    def register_ws(self, ws, loop=None):
        with self.lock:
            self.ws_subscribers.append((ws, loop))

    def unregister_ws(self, ws):
        with self.lock:
            self.ws_subscribers = [(w, l) for (w, l) in self.ws_subscribers if w != ws]

    def broadcast_event(self, event: dict):
        dead = []
        with self.lock:
            subscribers = list(self.ws_subscribers)
        msg = json_dumps(event) if (isinstance(event, dict) and "type" in event) else json_dumps({"type": "NEW_LOG", "data": event})
        for item in subscribers:
            ws, loop = item if isinstance(item, tuple) else (item, None)
            try:
                if loop and loop.is_running():
                    import asyncio
                    asyncio.run_coroutine_threadsafe(ws.send_text(msg), loop)
            except Exception:
                dead.append(ws)
        if dead:
            with self.lock:
                self.ws_subscribers = [(w, l) for (w, l) in self.ws_subscribers if w not in dead]

    # ─── Lifecycle & Status ─────────────────────────────────────
    def get_gateway_status(self) -> dict:
        return {
            "gateway_ip": GATEWAY_IP,
            "client_network": str(CLIENT_NETWORK),
            "dns_sinkhole": {
                "active": self.dns_server.active,
                "port": self.dns_server.port,
                "upstream": self.dns_server.upstream_dns,
                "error": self.dns_server.last_error,
            },
            "packet_sniffer": {
                "active": self.sniffer.active,
                "captured_packets": self.sniffer.captured_packets,
                "error": self.sniffer.last_error,
            },
            "captive_http": {
                "active": self.captive_http.active,
                "port": self.captive_http.port,
                "error": self.captive_http.last_error,
            },
            "firewall": {
                "dry_run": self.firewall.dry_run,
                "enforced_ips": self.firewall.get_enforced_ips(),
                "error": self.firewall.last_error,
            },
            "router_poller": self.router_poller.get_snapshot(),
        }

    def start(self):
        if self.running:
            return
        self.running = True
        self.dns_server.start()
        self.captive_http.start()
        self.sniffer.start()
        self.router_poller.start()

        threading.Thread(target=self._device_monitor_loop, daemon=True).start()
        if not self._name_workers_started:
            self._name_workers_started = True
            for _ in range(2):
                threading.Thread(target=self._name_worker_loop, daemon=True).start()
            self._schedule_all_names()

    def stop(self):
        self.running = False
        self.dns_server.stop()
        self.captive_http.stop()
        self.sniffer.stop()
        self.router_poller.stop()


def json_dumps(obj) -> str:
    import json
    return json.dumps(obj)


engine = NetworkGatewayEngine()
