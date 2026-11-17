import socket
import select
import threading
import time
import json
import sqlite3
import os
import sys
import re
import ipaddress
import subprocess
import secrets
import queue
from datetime import datetime, timedelta

try:
    sys.stdout.reconfigure(encoding='utf-8')
except Exception:
    pass

DB_PATH = os.path.join(os.path.dirname(__file__), "network_logs.db")
GATEWAY_IP = os.environ.get("NETPLUS_GATEWAY_IP", "192.168.137.1").strip()
HOTSPOT_NETWORK = ipaddress.ip_network(
    os.environ.get("NETPLUS_CLIENT_NETWORK", "192.168.137.0/24"), strict=False
)


def is_hotspot_client(ip):
    try:
        return ipaddress.ip_address(ip) in HOTSPOT_NETWORK
    except ValueError:
        return False

# ─── Academic structure (used by student registration dropdowns) ───
DEPARTMENTS = [
    "Software Engineering",
    "Computer Engineering",
    "Information Technology",
    "AI & Data Science",
    "Electronics & Telecommunication",
    "Mechanical Engineering",
]
YEARS = [
    {"value": "FE", "label": "First Year (FE)"},
    {"value": "SE", "label": "Second Year (SE)"},
    {"value": "TE", "label": "Third Year (TE)"},
    {"value": "BE", "label": "Final Year (BE)"},
]
DIVISIONS = ["A", "B", "C", "D", "E", "F"]
# Year-wise batches seeded on first run. Admins can add/remove more from the dashboard.
DEFAULT_YEAR_BATCHES = {y["value"]: [f"{y['value']}-B{i}" for i in range(1, 5)] for y in YEARS}

def init_db():
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA busy_timeout=5000;")
    except Exception:
        pass
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            client_ip TEXT,
            device_name TEXT,
            device_type TEXT,
            domain TEXT,
            clean_site TEXT,
            is_background INTEGER DEFAULT 0,
            category TEXT,
            method TEXT,
            bytes_transferred INTEGER,
            status TEXT,
            risk_flag TEXT,
            user_agent TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            ip TEXT PRIMARY KEY,
            custom_name TEXT,
            auto_name TEXT,
            device_type TEXT,
            first_seen TEXT,
            last_seen TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS blocklist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT UNIQUE,
            reason TEXT,
            created_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_quotas (
            ip TEXT PRIMARY KEY,
            daily_mb_limit INTEGER DEFAULT 0,
            enabled INTEGER DEFAULT 1,
            created_at TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS latency_targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT,
            host TEXT,
            port INTEGER DEFAULT 80,
            enabled INTEGER DEFAULT 1
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            mac_address TEXT PRIMARY KEY,
            prn TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            batch TEXT NOT NULL,
            registered_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            mac_address TEXT NOT NULL,
            prn TEXT NOT NULL,
            student_name TEXT NOT NULL,
            batch TEXT NOT NULL,
            attendance_date TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            connection_count INTEGER NOT NULL DEFAULT 1,
            UNIQUE(mac_address, attendance_date)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS year_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            year TEXT NOT NULL,
            batch TEXT NOT NULL,
            UNIQUE(year, batch)
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS removed_devices (
            device_key TEXT PRIMARY KEY,
            removed_at TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS registration_prompts (
            device_key TEXT PRIMARY KEY,
            prompted_at TEXT NOT NULL
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM year_batches")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT OR IGNORE INTO year_batches (year, batch) VALUES (?, ?)",
            [(yr, b) for yr, batches in DEFAULT_YEAR_BATCHES.items() for b in batches]
        )
    cursor.execute("SELECT COUNT(*) FROM latency_targets")
    if cursor.fetchone()[0] == 0:
        cursor.executemany(
            "INSERT INTO latency_targets (label, host, port, enabled) VALUES (?, ?, ?, 1)",
            [
                ('Google (Baseline)', 'www.google.com', 80),
                ('Cloudflare', 'one.one.one.one', 80),
            ]
        )
    # Safe column additions if existing DB was created without them
    try:
        cursor.execute("ALTER TABLE devices ADD COLUMN mac_address TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE devices ADD COLUMN name_source TEXT DEFAULT ''")
    except Exception:
        pass
    for tbl in ("students", "attendance"):
        for col in ("department", "year", "division"):
            try:
                cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} TEXT DEFAULT ''")
            except Exception:
                pass
    try:
        cursor.execute("ALTER TABLE attendance ADD COLUMN ip_address TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE attendance ADD COLUMN status TEXT DEFAULT 'Present'")
    except Exception:
        pass

    # ── Attendance sessions (Lab / Theory) ──
    # year / division / batch = who may be marked in the session ('' means "all").
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_type TEXT NOT NULL,
            title TEXT NOT NULL DEFAULT '',
            session_date TEXT NOT NULL,
            start_time TEXT NOT NULL,
            year TEXT NOT NULL DEFAULT '',
            division TEXT NOT NULL DEFAULT '',
            batch TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'active',
            started_at TEXT NOT NULL,
            ended_at TEXT
        )
    """)
    _migrate_attendance_to_sessions(cursor)
    conn.commit()
    conn.close()

def _migrate_attendance_to_sessions(cursor):
    """Old attendance rows were unique per (device, day). Rebuild the table so a device can have
    one row per session instead. Existing rows are kept with session_id NULL ("legacy")."""
    cols = [r[1] for r in cursor.execute("PRAGMA table_info(attendance)").fetchall()]
    if "session_id" not in cols:
        cursor.execute("ALTER TABLE attendance RENAME TO attendance_old")
        cursor.execute("""
            CREATE TABLE attendance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mac_address TEXT NOT NULL,
                prn TEXT NOT NULL,
                student_name TEXT NOT NULL,
                batch TEXT NOT NULL,
                department TEXT DEFAULT '',
                year TEXT DEFAULT '',
                division TEXT DEFAULT '',
                attendance_date TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                connection_count INTEGER NOT NULL DEFAULT 1,
                ip_address TEXT DEFAULT '',
                status TEXT DEFAULT 'Present',
                session_id INTEGER,
                UNIQUE(mac_address, session_id)
            )
        """)
        cursor.execute("""
            INSERT INTO attendance
                (id, mac_address, prn, student_name, batch, department, year, division,
                 attendance_date, first_seen, last_seen, connection_count, ip_address, status, session_id)
            SELECT id, mac_address, prn, student_name, batch, COALESCE(department,''), COALESCE(year,''),
                   COALESCE(division,''), attendance_date, first_seen, last_seen, connection_count,
                   COALESCE(ip_address,''), COALESCE(status,'Present'), NULL
            FROM attendance_old
        """)
        cursor.execute("DROP TABLE attendance_old")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_session ON attendance(session_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_attendance_date ON attendance(attendance_date)")

# Known Root Brand Normalization Mapping
ROOT_DOMAIN_RULES = [
    (r'.*takeuforward\.(org|com).*', 'takeuforward.org', 'Academic & Learning'),
    (r'.*codechef\.(com|org).*', 'codechef.com', 'Academic & Learning'),
    (r'.*leetcode\.(com|org).*', 'leetcode.com', 'Academic & Learning'),
    (r'.*geeksforgeeks\.(org|com).*', 'geeksforgeeks.org', 'Academic & Learning'),
    (r'.*moodle.*', 'moodle.college.edu', 'Academic & Learning'),
    (r'.*erp.*', 'erp.college.edu', 'Academic & Learning'),
    (r'.*github\.(com|io).*', 'github.com', 'Academic & Learning'),
    (r'.*stackoverflow\.(com).*', 'stackoverflow.com', 'Academic & Learning'),
    (r'.*wikipedia\.(org|com).*', 'wikipedia.org', 'Search & Knowledge'),
    (r'.*chatgpt\.com.*', 'chatgpt.com', 'Academic & Learning'),
    (r'.*openai\.com.*', 'openai.com', 'Academic & Learning'),
    
    (r'.*instagram\.(com|net).*', 'instagram.com', 'Entertainment & Social'),
    (r'.*facebook\.(com|net).*', 'facebook.com', 'Entertainment & Social'),
    (r'.*fbcdn\.net.*', 'facebook.com', 'Entertainment & Social'),
    (r'.*netflix\.(com|net).*', 'netflix.com', 'Entertainment & Social'),
    (r'.*nflx.*\.net.*', 'netflix.com', 'Entertainment & Social'),
    (r'.*nflxext\.com.*', 'netflix.com', 'Entertainment & Social'),
    (r'.*youtube\.(com|be).*', 'youtube.com', 'Entertainment & Social'),
    (r'.*googlevideo\.com.*', 'youtube.com', 'Entertainment & Social'),
    (r'.*ytimg\.com.*', 'youtube.com', 'Entertainment & Social'),
    (r'.*spotify\.(com|net).*', 'spotify.com', 'Entertainment & Social'),
    (r'.*twitch\.tv.*', 'twitch.tv', 'Entertainment & Social'),
    (r'.*snapchat\.com.*', 'snapchat.com', 'Entertainment & Social'),
    (r'.*linkedin\.com.*', 'linkedin.com', 'Entertainment & Social'),
    (r'.*reddit\.(com|it).*', 'reddit.com', 'Entertainment & Social'),
    (r'.*twitter\.(com).*|.*x\.com.*', 'x.com (Twitter)', 'Entertainment & Social'),
    
    (r'.*roblox\.com.*', 'roblox.com', 'Gaming & Arcade'),
    (r'.*steam(powered)?\.com.*', 'steam.com', 'Gaming & Arcade'),
    (r'.*chess\.com.*', 'chess.com', 'Gaming & Arcade'),
    (r'.*epicgames\.com.*', 'epicgames.com', 'Gaming & Arcade'),
    
    (r'.*google\.(com|co\..*|edu|org).*', 'google.com', 'Search & Knowledge'),
    (r'.*yahoo\.(com|co\..*).*', 'yahoo.com', 'Search & Knowledge'),
    (r'.*bing\.com.*', 'bing.com', 'Search & Knowledge'),
    (r'.*whatsapp\.(com|net).*', 'whatsapp.com', 'Messaging & Collab'),
    (r'.*telegram\.(org|me).*', 'telegram.org', 'Messaging & Collab'),
    (r'.*discord\.(com|gg).*', 'discord.com', 'Messaging & Collab'),
    
    (r'.*amazon\.(com|in|co\..*).*', 'amazon.com', 'Shopping & Services'),
    (r'.*awsstatic\.com.*', 'aws.amazon.com', 'Cloud & Infrastructure'),
    (r'.*aws\.dev.*', 'aws.amazon.com', 'Cloud & Infrastructure'),
]

# Patterns representing background telemetry / ads / OS captive portal / noise
BACKGROUND_PATTERNS = [
    r'.*connectivitycheck\..*',
    r'.*generate_204.*',
    r'.*gvt\d+\.com.*',
    r'.*gcp\.gvt\d+\.com.*',
    r'.*googleapis\.com.*',
    r'.*gstatic\.com.*',
    r'.*googleusercontent\.com.*',
    r'.*googleadservices\.com.*',
    r'.*googletagmanager\.com.*',
    r'.*google-analytics\.com.*',
    r'.*doubleclick\.net.*',
    r'.*miui\.com.*',
    r'.*mioffice\.cn.*',
    r'.*xiaomi\.com.*',
    r'.*mi-img\.com.*',
    r'.*pangle\.io.*',
    r'.*demdex\.net.*',
    r'.*omtrdc\.net.*',
    r'.*everesttech\.net.*',
    r'.*onetrust\.(com|io).*',
    r'.*adsrvr\.org.*',
    r'.*adobedc\.net.*',
    r'.*sc-static\.net.*',
    r'.*clrt\.ai.*',
    r'.*brave\.com.*',
    r'.*cloudflareinsights\.com.*',
    r'.*app-measurement\.com.*',
    r'^\d+\.\d+\.\d+\.\d+$' # Raw IP
]

def clean_and_normalize_domain(domain):
    d = domain.lower()

    # 1. Check if it matches a known human-visited website
    for pattern, root_brand, cat in ROOT_DOMAIN_RULES:
        if re.match(pattern, d, re.I):
            return root_brand, cat, False

    # 2. Check if it's background noise / telemetry
    is_bg = any(re.match(p, d, re.I) for p in BACKGROUND_PATTERNS)
    if is_bg:
        return domain, 'Background & OS Telemetry', True

    # 3. Strip subdomains for general sites (e.g. blog.example.com -> example.com)
    parts = d.split('.')
    if len(parts) >= 2:
        root_site = ".".join(parts[-2:])
        # Check academic keywords
        if any(k in root_site for k in ['edu', 'college', 'univ', 'ac.', 'learn', 'code', 'study']):
            return root_site, 'Academic & Learning', False
        elif any(k in root_site for k in ['game', 'play', 'arcade']):
            return root_site, 'Gaming & Arcade', False
        elif any(k in root_site for k in ['proxy', 'vpn', 'hide', 'tunnel']):
            return root_site, 'Proxy & Bypass', False
        return root_site, 'General Web', False

    return domain, 'General Web', False

def parse_user_agent(ua_string):
    if not ua_string:
        return {"name": "Mobile Device", "type": "mobile", "os": "Unknown"}
    ua = ua_string.lower()

    # Extract Android version
    android_ver = ""
    m = re.search(r'android ([\d.]+)', ua)
    if m: android_ver = f" (Android {m.group(1)})"

    # Extract iOS version
    ios_ver = ""
    m2 = re.search(r'os ([\d_]+) like', ua)
    if m2: ios_ver = f" (iOS {m2.group(1).replace('_','.')})"

    if 'iphone' in ua:
        return {"name": f"Apple iPhone{ios_ver}", "type": "mobile", "os": f"iOS{ios_ver}"}
    if 'ipad' in ua:
        return {"name": f"Apple iPad{ios_ver}", "type": "tablet", "os": f"iPadOS{ios_ver}"}
    if 'macintosh' in ua or 'mac os x' in ua:
        return {"name": "MacBook / macOS", "type": "laptop", "os": "macOS"}
    if 'android' in ua:
        model = _extract_android_model(ua_string)
        if model:
            if re.match(r'^sm-', model, re.I):
                label = f"Samsung {model.upper()}"
            elif re.match(r'^pixel', model, re.I):
                label = f"Google {model}"
            elif re.match(r'^(redmi|poco|mi |xiaomi)', model, re.I):
                label = model
            elif re.match(r'^(m\d{4}|\d{5}[a-z]{3,})', model, re.I):   # Xiaomi codes e.g. M2101K6I
                label = f"Xiaomi {model}"
            else:
                label = model
            return {"name": label, "type": "mobile", "os": f"Android{android_ver}"}
        if 'samsung' in ua or 'sm-' in ua:
            return {"name": f"Samsung Galaxy{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
        if 'pixel' in ua:
            return {"name": f"Google Pixel{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
        if 'oneplus' in ua:
            return {"name": f"OnePlus{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
        if 'redmi' in ua or 'xiaomi' in ua or 'poco' in ua or 'miui' in ua:
            return {"name": f"Xiaomi / Redmi{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
        if 'vivo' in ua:
            return {"name": f"Vivo{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
        if 'oppo' in ua:
            return {"name": f"Oppo{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
        if 'realme' in ua:
            return {"name": f"Realme{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
        return {"name": f"Android Phone{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
    if 'windows nt 10' in ua:
        return {"name": "Windows 10/11 PC", "type": "desktop", "os": "Windows 10/11"}
    if 'windows' in ua:
        return {"name": "Windows PC", "type": "desktop", "os": "Windows"}
    if 'linux' in ua:
        return {"name": "Linux PC", "type": "desktop", "os": "Linux"}
    return {"name": "Unknown Device", "type": "mobile", "os": "Unknown"}


def _extract_android_model(ua_string):
    """Pull the real handset model out of an Android UA, e.g. 'SM-A515F'.
    Chrome's reduced UA reports just 'K' as the model - that is ignored."""
    m = re.search(r'android [\d.]+;\s*([^;)]+?)(?:\s+build/[^;)]*)?\s*[;)]', ua_string or '', re.I)
    if not m:
        return ''
    model = m.group(1).strip()
    if len(model) < 3 or model.lower() in ('k', 'mobile', 'wv', 'linux', 'u', 'generic', 'android'):
        return ''
    return model

# ─── Device naming ───
# Higher number = better name. A name is only ever replaced by a better one.
NAME_PRIORITY = {"": 0, "fallback": 1, "ua": 2, "host": 3, "student": 4, "system": 5}
GENERIC_NAME_RE = re.compile(r"^(Hotspot Device|Mobile Device|Client Device|Unknown Device|Unidentified Device|Android Phone)", re.I)
ONLINE_WINDOW_SEC = 120

def clean_hostname(raw, own_hostname=""):
    """Turn a DNS/NetBIOS answer into a presentable device name, or None if it is
    just an IP, a random token, or the gateway PC's own name."""
    if not raw:
        return None
    label = raw.strip().rstrip('.').split('.')[0].strip()
    if len(label) < 2 or len(label) > 63:
        return None
    low = label.lower()
    if low in ('localhost', 'unknown', 'gateway', 'router') or low == (own_hostname or '').lower():
        return None
    if re.fullmatch(r'[\d\-_]+', label):                      # 192-168-137-5
        return None
    if re.fullmatch(r'(android[-_]?)?[0-9a-f]{10,}', low):      # android-1a2b3c4d5e6f
        return None
    return label

def fallback_device_name(ip, mac=""):
    """Stable, non-random placeholder used only until a real name is found."""
    if mac and re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', mac.lower()):
        return f"Unidentified Device ({mac[-5:].upper()})"
    return f"Unidentified Device (#{ip.split('.')[-1]})"

class NetworkMonitoringEngine:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        configured_port = os.environ.get("NETPLUS_PROXY_PORT")
        if configured_port is not None:
            try:
                port = int(configured_port)
            except ValueError as exc:
                raise ValueError("NETPLUS_PROXY_PORT must be an integer from 1 to 65535") from exc
        if not 1 <= port <= 65535:
            raise ValueError("Proxy port must be between 1 and 65535")
        self.port = port
        self.running = False
        self.server_socket = None
        self.blocked_domains = set()
        self.ws_subscribers = []
        self.lock = threading.Lock()
        self._quota_cache = {}   # {ip: daily_mb_limit}
        self._quota_cache_ts = 0
        self._mac_cache = {}
        self._registration_tokens = {}
        self._prompted_keys = set()
        self._removed_keys = set()
        self._name_state = {}            # ip -> (last_try_ts, tries, done)
        self._name_queue = queue.Queue()
        self._name_workers_started = False
        self._own_hostname = socket.gethostname()
        init_db()
        self._load_prompted_keys()
        self._load_removed_keys()
        self.load_blocklist()
        self._refresh_quota_cache()

    def _load_prompted_keys(self):
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                self._prompted_keys = {r[0] for r in conn.execute("SELECT device_key FROM registration_prompts")}
        except sqlite3.Error:
            self._prompted_keys = set()

    def _refresh_quota_cache(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT ip, daily_mb_limit FROM device_quotas WHERE enabled = 1 AND daily_mb_limit > 0")
            self._quota_cache = {r[0]: r[1] for r in c.fetchall()}
            self._quota_cache_ts = time.time()
            conn.close()
        except Exception:
            pass

    def get_daily_usage_mb(self, ip):
        """Returns today's MB consumed by this IP from access_logs."""
        try:
            today = datetime.now().strftime("%Y-%m-%d")
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "SELECT COALESCE(SUM(bytes_transferred),0) FROM access_logs "
                "WHERE client_ip = ? AND timestamp LIKE ?",
                (ip, f"{today}%")
            )
            total_bytes = c.fetchone()[0] or 0
            conn.close()
            return total_bytes / (1024 * 1024)
        except Exception:
            return 0.0

    def is_quota_exceeded(self, ip):
        if time.time() - self._quota_cache_ts > 60:
            self._refresh_quota_cache()
        limit_mb = self._quota_cache.get(ip, 0)
        if limit_mb <= 0:
            return False
        used_mb = self.get_daily_usage_mb(ip)
        return used_mb >= limit_mb

    def set_quota(self, ip, daily_mb_limit):
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute(
                "INSERT OR REPLACE INTO device_quotas (ip, daily_mb_limit, enabled, created_at) VALUES (?, ?, 1, ?)",
                (ip, daily_mb_limit, now)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Quota set error: {e}")
        self._refresh_quota_cache()

    def remove_quota(self, ip):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM device_quotas WHERE ip = ?", (ip,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Quota remove error: {e}")
        self._refresh_quota_cache()

    def load_blocklist(self):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("SELECT domain FROM blocklist")
            self.blocked_domains = {r[0].lower() for r in c.fetchall()}
            conn.close()
        except Exception:
            pass

    def add_block_rule(self, domain, reason="Restricted by policy"):
        domain = domain.strip().lower()
        with self.lock:
            self.blocked_domains.add(domain)
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("INSERT OR REPLACE INTO blocklist (domain, reason, created_at) VALUES (?, ?, ?)",
                      (domain, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error saving block rule: {e}")

    def remove_block_rule(self, domain):
        domain = domain.strip().lower()
        with self.lock:
            self.blocked_domains.discard(domain)
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("DELETE FROM blocklist WHERE domain = ?", (domain,))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error removing block rule: {e}")

    def rename_device(self, ip, new_name):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE devices SET custom_name = ? WHERE ip = ?", (new_name, ip))
            c.execute("UPDATE access_logs SET device_name = ? WHERE client_ip = ?", (new_name, ip))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Error updating device name: {e}")

    def is_blocked(self, domain, clean_site):
        d1 = domain.lower()
        d2 = clean_site.lower()
        for b in self.blocked_domains:
            if b in d1 or b in d2:
                return True
        return False

    def get_or_create_device(self, ip, ua_string):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ua_info = parse_user_agent(ua_string) if ua_string else None
        ua_known = bool(ua_info) and not ua_info["name"].startswith(("Unknown Device", "Mobile Device"))
        last_octet = ip.split('.')[-1]
        mac = self.get_mac_for_ip(ip)

        # A device that is genuinely sending traffic again is no longer "removed".
        if self._removed_keys:
            self._clear_removed(ip, mac)

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT ip, custom_name, auto_name, device_type, COALESCE(name_source,'') FROM devices WHERE ip = ?", (ip,))
        row = c.fetchone()

        if row:
            custom_name, auto_name, dev_type, src = row[1], row[2], row[3], row[4]
            if ua_known and NAME_PRIORITY["ua"] > self._stored_priority(auto_name, src):
                auto_name = f"{ua_info['name']} (#{last_octet})"
                dev_type = ua_info['type']
                c.execute("UPDATE devices SET auto_name = ?, device_type = ?, name_source = 'ua', last_seen = ?, mac_address = COALESCE(NULLIF(?, ''), mac_address) WHERE ip = ?",
                          (auto_name, dev_type, timestamp, mac or '', ip))
            else:
                c.execute("UPDATE devices SET last_seen = ?, mac_address = COALESCE(NULLIF(?, ''), mac_address) WHERE ip = ?", (timestamp, mac or '', ip))
            conn.commit()
            conn.close()
            name = custom_name or auto_name
            self._schedule_name_refresh(ip)
        else:
            if ip == '127.0.0.1':
                auto_name, dev_type, src = 'Host PC (Localhost)', 'desktop', 'system'
            elif ua_known:
                suffix = f"#{last_octet}" if is_hotspot_client(ip) else ip
                auto_name, dev_type, src = f"{ua_info['name']} ({suffix})", ua_info['type'], 'ua'
            else:
                auto_name, dev_type, src = fallback_device_name(ip, mac or ''), (ua_info or {}).get('type', 'mobile'), 'fallback'
            c.execute("INSERT INTO devices (ip, custom_name, auto_name, device_type, first_seen, last_seen, mac_address, name_source) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (ip, '', auto_name, dev_type, timestamp, timestamp, mac or '', src))
            conn.commit()
            conn.close()
            name = auto_name
            self._schedule_name_refresh(ip)

        if mac:
            stu = self.get_student_by_mac(mac)
            if stu:
                self.record_attendance(stu, ip=ip)

        return {"ip": ip, "name": name, "device_type": dev_type}

    # ── Device naming: hostname / student / model, upgraded in the background ──
    def _stored_priority(self, name, source):
        if source:
            return NAME_PRIORITY.get(source, 0)
        # Rows created before name_source existed
        return 0 if (not name or GENERIC_NAME_RE.match(name)) else NAME_PRIORITY["ua"]

    def resolve_hostname(self, ip):
        """Ask the hotspot's DNS (ICS), then NetBIOS, then ping -a for the device's real hostname."""
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
        try:   # NetBIOS (Windows laptops)
            r = subprocess.run(["nbtstat", "-A", ip], capture_output=True, text=True, timeout=3, creationflags=flags)
            m = re.search(r"^\s*([^\s<]+)\s+<00>\s+UNIQUE", r.stdout, re.M)
            if m:
                name = clean_hostname(m.group(1), self._own_hostname)
                if name:
                    return name
        except Exception:
            pass
        try:   # Resolves through the same DNS cache the hotspot shows in Settings
            r = subprocess.run(["ping", "-a", "-n", "1", "-w", "700", ip], capture_output=True, text=True, timeout=4, creationflags=flags)
            m = re.search(r"Pinging\s+(\S+)\s+\[" + re.escape(ip) + r"\]", r.stdout)
            if m:
                return clean_hostname(m.group(1), self._own_hostname)
        except Exception:
            pass
        return None

    def refresh_device_name(self, ip):
        """Work out the best available name for this device and store it if it beats the current one.
        Returns True when the name is final (no need to keep retrying)."""
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                row = conn.execute(
                    "SELECT COALESCE(custom_name,''), COALESCE(auto_name,''), COALESCE(device_type,'mobile'), "
                    "COALESCE(name_source,''), COALESCE(mac_address,''), COALESCE(last_seen,'') FROM devices WHERE ip=?", (ip,)
                ).fetchone()
                if not row:
                    return True
                custom, auto, dtype, src, mac, last_seen = row
                cur_pri = self._stored_priority(auto, src)

                ua_row = conn.execute(
                    "SELECT user_agent FROM access_logs WHERE client_ip=? AND user_agent IS NOT NULL AND user_agent!='' ORDER BY id DESC LIMIT 1", (ip,)
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
                        suffix = f"#{ip.split('.')[-1]}" if is_hotspot_client(ip) else ip
                        cand = (f"{ua_info['name']} ({suffix})", "ua")
                    elif cur_pri == 0:
                        cand = (fallback_device_name(ip, mac), "fallback")

                if cand:
                    name, source = cand
                    better = NAME_PRIORITY[source] > cur_pri
                    changed_same = NAME_PRIORITY[source] == cur_pri and source in ("host", "student") and name != auto
                    if better or changed_same:
                        conn.execute("UPDATE devices SET auto_name=?, device_type=?, name_source=? WHERE ip=?", (name, dtype, source, ip))
                        if not custom:
                            conn.execute("UPDATE access_logs SET device_name=? WHERE client_ip=?", (name, ip))
                        auto, src = name, source
                if custom:
                    return True
                return src in ("host", "student", "system")
        except Exception as e:
            print(f"Name refresh failed for {ip}: {e}")
            return False

    def _schedule_name_refresh(self, ip):
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

    # ── "Removed device" tombstones: stop the ARP scanner re-adding a device the admin deleted ──
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

    def clear_device_history(self, ip):
        """Delete every logged request for this device but keep the device itself."""
        with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
            n = conn.execute("DELETE FROM access_logs WHERE client_ip=?", (ip,)).rowcount
        return n

    def remove_device(self, ip):
        """Delete the device, its history and its quota. Student registrations and
        attendance records are NOT touched. Returns (found, deleted_log_rows)."""
        with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
            row = conn.execute("SELECT COALESCE(mac_address,'') FROM devices WHERE ip=?", (ip,)).fetchone()
            logs = conn.execute("DELETE FROM access_logs WHERE client_ip=?", (ip,)).rowcount
            dev = conn.execute("DELETE FROM devices WHERE ip=?", (ip,)).rowcount
            conn.execute("DELETE FROM device_quotas WHERE ip=?", (ip,))
            key = ((row[0] if row else "") or ip).lower()
            if dev:
                conn.execute("INSERT OR REPLACE INTO removed_devices (device_key, removed_at) VALUES (?, ?)",
                             (key, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                self._removed_keys.add(key)
        self._mac_cache.pop(ip, None)
        self._name_state.pop(ip, None)
        self._refresh_quota_cache()
        return bool(dev), logs

    def get_mac_for_ip(self, ip):
        """Resolve a client's current MAC from the local neighbor table."""
        if not ip:
            return None
        if ip in ("127.0.0.1", "localhost", "::1"):
            return "host:local:mac:01"
        if ip in self._mac_cache and time.time() - self._mac_cache[ip][1] < 15:
            return self._mac_cache[ip][0]
        try:
            if os.name == "nt":
                result = subprocess.run(
                    ["arp", "-a", ip], capture_output=True, text=True,
                    timeout=2, check=False, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                match = re.search(
                    r"\b" + re.escape(ip) + r"\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b",
                    result.stdout, re.I
                )
                if not match:
                    result = subprocess.run(
                        ["arp", "-a"], capture_output=True, text=True, timeout=2, check=False,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                    )
                    match = re.search(
                        r"\b" + re.escape(ip) + r"\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\b",
                        result.stdout, re.I
                    )
                mac = match.group(1).replace("-", ":").lower() if match else None
            else:
                mac = None
                try:
                    result = subprocess.run(
                        ["ip", "neigh", "show", "to", ip],
                        capture_output=True, text=True, timeout=2, check=False
                    )
                    match = re.search(r"\blladdr\s+(([0-9a-f]{2}:){5}[0-9a-f]{2})\b", result.stdout, re.I)
                    mac = match.group(1).lower() if match else None
                except FileNotFoundError:
                    pass
                if not mac:
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
        """Scan the local neighbor table for hotspot clients and update their status."""
        found = []
        try:
            if os.name == "nt":
                r = subprocess.run(
                    ["arp", "-a"], capture_output=True, text=True, timeout=2,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                entries = []
                for line in r.stdout.splitlines():
                    match = re.match(
                        r"^\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})\s+dynamic",
                        line
                    )
                    if match:
                        entries.append((match.group(1), match.group(2).replace("-", ":").lower()))
            else:
                r = subprocess.run(
                    ["ip", "neigh", "show"], capture_output=True, text=True,
                    timeout=2, check=False
                )
                entries = []
                for line in r.stdout.splitlines():
                    match = re.match(
                        r"^\s*(\d+\.\d+\.\d+\.\d+)\s+.*?\blladdr\s+(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})\b",
                        line
                    )
                    if match:
                        entries.append((match.group(1), match.group(2).lower()))

            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for ip, mac in entries:
                if not is_hotspot_client(ip):
                    continue
                self._mac_cache[ip] = (mac, time.time())
                found.append((ip, mac))

            if found:
                to_record = []
                to_name = []
                with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                    c = conn.cursor()
                    for ip, mac in found:
                        c.execute("SELECT mac_address, prn, name, batch, COALESCE(department,''), COALESCE(year,''), COALESCE(division,'') FROM students WHERE mac_address = ?", (mac,))
                        stu = c.fetchone()
                        if stu:
                            # Attendance keeps working even if the admin removed the device card
                            to_record.append(({"mac_address": stu[0], "prn": stu[1], "name": stu[2], "batch": stu[3],
                                               "department": stu[4], "year": stu[5], "division": stu[6]}, ip))
                        if self._is_removed(ip, mac):
                            continue
                        c.execute("SELECT ip FROM devices WHERE ip = ?", (ip,))
                        if c.fetchone():
                            c.execute("UPDATE devices SET last_seen = ?, mac_address = ? WHERE ip = ?", (now, mac, ip))
                        else:
                            if stu:
                                auto_name, src = f"{stu[2]}'s Device", "student"
                            else:
                                auto_name, src = fallback_device_name(ip, mac), "fallback"
                            c.execute("INSERT INTO devices (ip, custom_name, auto_name, device_type, first_seen, last_seen, mac_address, name_source) VALUES (?, '', ?, 'mobile', ?, ?, ?, ?)",
                                      (ip, auto_name, now, now, mac, src))
                        to_name.append(ip)

                for student_dict, client_ip in to_record:
                    self.record_attendance(student_dict, ip=client_ip)
                for ip in to_name:
                    self._schedule_name_refresh(ip)
        except Exception:
            pass
        return found

    def _device_monitor_loop(self):
        while self.running:
            try:
                self.scan_connected_devices()
            except Exception:
                pass
            time.sleep(6)

    def get_student_by_mac(self, mac):
        if not mac:
            return None
        try:
            with sqlite3.connect(DB_PATH) as conn:
                row = conn.execute(
                    "SELECT mac_address, prn, name, batch, COALESCE(department,''), COALESCE(year,''), COALESCE(division,'') "
                    "FROM students WHERE mac_address=?", (mac,)
                ).fetchone()
            return {"mac_address": row[0], "prn": row[1], "name": row[2], "batch": row[3],
                    "department": row[4], "year": row[5], "division": row[6]} if row else None
        except sqlite3.Error:
            return None

    def get_active_session(self):
        """Return the currently running attendance session (dict) or None."""
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                row = conn.execute(
                    "SELECT id, session_type, title, session_date, year, division, batch "
                    "FROM sessions WHERE status='active' ORDER BY id DESC LIMIT 1").fetchone()
        except sqlite3.Error:
            return None
        if not row:
            return None
        return {"id": row[0], "session_type": row[1], "title": row[2], "session_date": row[3],
                "year": row[4], "division": row[5], "batch": row[6]}

    @staticmethod
    def student_in_session(student, session):
        """A session only accepts students of its chosen Year / Div / Batch ('' = any)."""
        for key in ("year", "division", "batch"):
            wanted = session.get(key, "") or ""
            if wanted and (student.get(key, "") or "") != wanted:
                return False
        return True

    def record_attendance(self, student, ip=""):
        """Mark the student present in the ACTIVE session only. Returns True if a record was
        written/updated, False if there is no active session or the student is not part of it.
        The dashboard popup is broadcast only the first time a student is seen in a session."""
        session = self.get_active_session()
        if not session or not self.student_in_session(student, session):
            return False
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dept = student.get("department", "") or ""
        year = student.get("year", "") or ""
        div = student.get("division", "") or ""
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                already = conn.execute(
                    "SELECT 1 FROM attendance WHERE mac_address=? AND session_id=?",
                    (student["mac_address"], session["id"])
                ).fetchone() is not None
                conn.execute("""
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
                """, (student["mac_address"], student["prn"], student["name"], student["batch"],
                      dept, year, div, session["session_date"], now, now, ip or "", session["id"]))

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
                    "time": now
                })
            return True
        except Exception as e:
            print(f"Error recording attendance: {e}")
            return False

    # ── "Join" prompt: show the registration page only once per device ──
    def _prompt_key(self, ip, mac):
        return (mac or ip or "").lower()

    def was_prompted(self, ip, mac):
        key = self._prompt_key(ip, mac)
        if not key:
            return True
        if key in self._prompted_keys:
            return True
        # A device that was prompted by IP before its MAC was resolvable
        return bool(ip) and ip.lower() in self._prompted_keys

    def mark_prompted(self, ip, mac):
        key = self._prompt_key(ip, mac)
        if not key:
            return
        self._prompted_keys.add(key)
        try:
            with sqlite3.connect(DB_PATH, timeout=15.0) as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO registration_prompts (device_key, prompted_at) VALUES (?, ?)",
                    (key, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                )
        except sqlite3.Error:
            pass

    def reset_prompts(self, device_key=None):
        """Let a device (or all devices) see the join page one more time."""
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

    def issue_registration_token(self, ip):
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

    def get_registration_ip(self, token):
        item = self._registration_tokens.get(token)
        if not item:
            return None
        if item[1] < time.time():
            self._registration_tokens.pop(token, None)
            return None
        return item[0]

    def consume_registration_token(self, token):
        self._registration_tokens.pop(token, None)

    def log_event(self, entry):
        try:
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("""
                INSERT INTO access_logs (timestamp, client_ip, device_name, device_type, domain, clean_site, is_background, category, method, bytes_transferred, status, risk_flag, user_agent)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                entry['timestamp'],
                entry['client_ip'],
                entry['device_name'],
                entry['device_type'],
                entry['domain'],
                entry['clean_site'],
                1 if entry.get('is_background') else 0,
                entry['category'],
                entry['method'],
                entry['bytes'],
                entry['status'],
                entry['risk_flag'],
                entry.get('user_agent', '')
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"DB Error: {e}")

        # Broadcast via WebSocket
        self.broadcast_event(entry)

    def register_ws(self, ws, loop=None):
        with self.lock:
            self.ws_subscribers.append((ws, loop))

    def unregister_ws(self, ws):
        with self.lock:
            self.ws_subscribers = [(w, l) for (w, l) in self.ws_subscribers if w != ws]

    def broadcast_event(self, event):
        dead = []
        with self.lock:
            subscribers = list(self.ws_subscribers)
        
        if isinstance(event, dict) and 'type' in event:
            msg = json.dumps(event)
        else:
            msg = json.dumps({"type": "NEW_LOG", "data": event})
        for item in subscribers:
            try:
                ws, loop = item if isinstance(item, tuple) else (item, None)
                if loop and loop.is_running():
                    import asyncio
                    asyncio.run_coroutine_threadsafe(ws.send_text(msg), loop)
            except Exception:
                dead.append(ws)
        
        if dead:
            with self.lock:
                self.ws_subscribers = [(w, l) for (w, l) in self.ws_subscribers if w not in dead]

    def handle_client(self, client_socket, client_address):
        client_ip, _ = client_address
        remote_socket = None

        try:
            request_data = client_socket.recv(8192)
            if not request_data:
                client_socket.close()
                return

            request_text = request_data.decode('utf-8', errors='ignore')
            lines = request_text.split('\r\n')
            if not lines or not lines[0]:
                client_socket.close()
                return

            request_line = lines[0]
            parts = request_line.split()
            if len(parts) < 2:
                client_socket.close()
                return

            method, target = parts[0].upper(), parts[1]

            # Extract User-Agent header
            user_agent = ""
            for line in lines[1:]:
                if line.lower().startswith('user-agent:'):
                    user_agent = line.split(':', 1)[1].strip()
                    break

            device_info = self.get_or_create_device(client_ip, user_agent)
            device_name = device_info['name']
            device_type = device_info['device_type']

            # Extract domain and port
            if method == 'CONNECT':
                if ':' in target:
                    host, port = target.split(':', 1)
                    port = int(port)
                else:
                    host, port = target, 443
            else:
                if target.startswith('http://') or target.startswith('https://'):
                    url_part = target.split('://', 1)[1]
                    host = url_part.split('/')[0]
                else:
                    host = target.split('/')[0]
                if ':' in host:
                    host, port = host.split(':', 1)
                    port = int(port)
                else:
                    port = 80

            # Normalize to clean website & category
            clean_site, category, is_background = clean_and_normalize_domain(host)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            mac_address = self.get_mac_for_ip(client_ip)
            student = self.get_student_by_mac(mac_address)
            if student:
                self.record_attendance(student)

            # Keep unregistered devices on the registration page for every plain
            # HTTP request. Otherwise captive-portal checks may see internet access
            # after the first redirect and dismiss the registration screen.
            is_local_portal = host.lower().strip("[]") in {GATEWAY_IP, "localhost", "127.0.0.1"}
            if method != 'CONNECT' and not is_local_portal and not student and not is_background:
                if not self.was_prompted(client_ip, mac_address):
                    self.mark_prompted(client_ip, mac_address)
                token = self.issue_registration_token(client_ip)
                location = f"http://{GATEWAY_IP}:5000/attendance/register?token={token}"
                response = (
                    "HTTP/1.1 302 Found\r\n"
                    f"Location: {location}\r\n"
                    "Cache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
                )
                client_socket.sendall(response.encode("ascii"))
                return

            # Risk check
            blocked = self.is_blocked(host, clean_site)
            risk_flag = "Normal"
            status = "Blocked" if blocked else "Allowed"

            if blocked:
                risk_flag = "Policy Violation"
            elif category == 'Gaming & Arcade':
                risk_flag = "Restricted Gaming"
            elif category == 'Proxy & Bypass':
                risk_flag = "Bypass Attempt"

            # If blocked
            if blocked:
                response = b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;padding:50px;background:#111;color:#fff;'><h1>403 Forbidden</h1><p>Access to <strong>" + host.encode() + b"</strong> has been restricted by College Policy.</p></body></html>"
                client_socket.sendall(response)
                client_socket.close()

                self.log_event({
                    'timestamp': timestamp,
                    'client_ip': client_ip,
                    'device_name': device_name,
                    'device_type': device_type,
                    'domain': host,
                    'clean_site': clean_site,
                    'is_background': is_background,
                    'category': category,
                    'method': method,
                    'bytes': len(request_data),
                    'status': 'Blocked',
                    'risk_flag': risk_flag,
                    'user_agent': user_agent
                })
                print(f"[{timestamp}] 🚫 BLOCKED: [{client_ip}] {device_name} ──> {clean_site} ({host})")
                return

            # Quota enforcement
            if not is_background and self.is_quota_exceeded(client_ip):
                used_mb = self.get_daily_usage_mb(client_ip)
                quota_mb = self._quota_cache.get(client_ip, 0)
                quota_html = (
                    b"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/html\r\n\r\n"
                    b"<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;"
                    b"padding:60px;background:#111;color:#fff;'>"
                    b"<h1>\xf0\x9f\x9a\xab Daily Quota Exceeded</h1>"
                    b"<p>Your device has reached its daily data limit.<br>Limit: "
                    + f"{quota_mb:.0f} MB".encode()
                    + b" &nbsp;|&nbsp; Used: "
                    + f"{used_mb:.1f} MB".encode()
                    + b"</p><p style='color:#888;'>Quota resets at midnight. Contact admin to adjust.</p>"
                    b"</body></html>"
                )
                client_socket.sendall(quota_html)
                client_socket.close()
                self.log_event({
                    'timestamp': timestamp,
                    'client_ip': client_ip,
                    'device_name': device_name,
                    'device_type': device_type,
                    'domain': host,
                    'clean_site': clean_site,
                    'is_background': False,
                    'category': category,
                    'method': method,
                    'bytes': 0,
                    'status': 'Blocked',
                    'risk_flag': 'Quota Exceeded',
                    'user_agent': user_agent
                })
                print(f"[{timestamp}] 🚫 QUOTA: [{client_ip}] {device_name} — daily limit {quota_mb:.0f} MB reached")
                return

            # Print terminal notification
            if not is_background:
                dev_icon = "📱" if device_type == "mobile" else "💻"
                print(f"[{timestamp}] {dev_icon} [{client_ip}] {device_name} ──> 🌟 {clean_site} [{category}]")

            # Connect to destination
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.settimeout(12.0)
            remote_socket.connect((host, port))

            bytes_transferred = len(request_data)

            if method == 'CONNECT':
                client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                remote_socket.sendall(request_data)

            # Tunnel traffic
            sockets = [client_socket, remote_socket]
            active = True
            while active and self.running:
                r_socks, _, _ = select.select(sockets, [], [], 25.0)
                if not r_socks:
                    break
                for s in r_socks:
                    data = s.recv(16384)
                    if not data:
                        active = False
                        break
                    bytes_transferred += len(data)
                    if s is client_socket:
                        remote_socket.sendall(data)
                    else:
                        client_socket.sendall(data)

            self.log_event({
                'timestamp': timestamp,
                'client_ip': client_ip,
                'device_name': device_name,
                'device_type': device_type,
                'domain': host,
                'clean_site': clean_site,
                'is_background': is_background,
                'category': category,
                'method': method,
                'bytes': bytes_transferred,
                'status': 'Allowed',
                'risk_flag': risk_flag,
                'user_agent': user_agent
            })

        except Exception:
            pass
        finally:
            try:
                client_socket.close()
            except:
                pass
            try:
                if remote_socket:
                    remote_socket.close()
            except:
                pass

    def start(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(200)
        print(f"🚀 Gateway Proxy listening on {self.host}:{self.port}")

        # Start background ARP device discovery and auto-attendance monitor
        t_mon = threading.Thread(target=self._device_monitor_loop, daemon=True)
        t_mon.start()

        # Background workers that look up real device names (hostname) without slowing the proxy
        if not self._name_workers_started:
            self._name_workers_started = True
            for _ in range(2):
                threading.Thread(target=self._name_worker_loop, daemon=True).start()
            self._schedule_all_names()

        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                t = threading.Thread(target=self.handle_client, args=(client_sock, client_addr), daemon=True)
                t.start()
            except Exception:
                if not self.running:
                    break

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass

engine = NetworkMonitoringEngine()
