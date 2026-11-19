import ipaddress
import os
import re
import sqlite3

DB_PATH = os.path.join(os.path.dirname(__file__), "network_logs.db")
GATEWAY_IP = os.environ.get("NETPLUS_GATEWAY_IP", "192.168.137.1").strip()
CLIENT_NETWORK = ipaddress.ip_network(
    os.environ.get("NETPLUS_CLIENT_NETWORK", "192.168.137.0/24"), strict=False
)


def is_client_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in CLIENT_NETWORK
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
                ("Google (Baseline)", "www.google.com", 80),
                ("Cloudflare", "one.one.one.one", 80),
            ]
        )

    # Safe column additions if existing DB was created without them
    for stmt in (
        "ALTER TABLE devices ADD COLUMN mac_address TEXT DEFAULT ''",
        "ALTER TABLE devices ADD COLUMN name_source TEXT DEFAULT ''",
        "ALTER TABLE attendance ADD COLUMN ip_address TEXT DEFAULT ''",
        "ALTER TABLE attendance ADD COLUMN status TEXT DEFAULT 'Present'",
    ):
        try:
            cursor.execute(stmt)
        except Exception:
            pass

    for tbl in ("students", "attendance"):
        for col in ("department", "year", "division"):
            try:
                cursor.execute(f"ALTER TABLE {tbl} ADD COLUMN {col} TEXT DEFAULT ''")
            except Exception:
                pass

    _migrate_attendance_to_sessions(cursor)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_ip_ts ON access_logs(client_ip, timestamp)")
    conn.commit()
    conn.close()


def _migrate_attendance_to_sessions(cursor):
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

BACKGROUND_PATTERNS = [
    r'.*connectivitycheck\..*',
    r'.*generate_204.*',
    r'.*msftconnecttest\.com.*',
    r'.*captive\.apple\.com.*',
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
    r'^\d+\.\d+\.\d+\.\d+$',
]


def clean_and_normalize_domain(domain: str):
    d = (domain or "").strip().lower().rstrip(".")
    if not d:
        return "", "General Web", False

    for pattern, root_brand, cat in ROOT_DOMAIN_RULES:
        if re.match(pattern, d, re.I):
            return root_brand, cat, False

    if any(re.match(p, d, re.I) for p in BACKGROUND_PATTERNS):
        return d, "Background & OS Telemetry", True

    parts = d.split(".")
    if len(parts) >= 2:
        root_site = ".".join(parts[-2:])
        if any(k in root_site for k in ("edu", "college", "univ", "ac.", "learn", "code", "study")):
            return root_site, "Academic & Learning", False
        if any(k in root_site for k in ("game", "play", "arcade")):
            return root_site, "Gaming & Arcade", False
        if any(k in root_site for k in ("proxy", "vpn", "hide", "tunnel")):
            return root_site, "Proxy & Bypass", False
        return root_site, "General Web", False

    return d, "General Web", False


def _extract_android_model(ua_string: str) -> str:
    m = re.search(r'android [\d.]+;\s*([^;)]+?)(?:\s+build/[^;)]*)?\s*[;)]', ua_string or "", re.I)
    if not m:
        return ""
    model = m.group(1).strip()
    if len(model) < 3 or model.lower() in ("k", "mobile", "wv", "linux", "u", "generic", "android"):
        return ""
    return model


def parse_user_agent(ua_string: str) -> dict:
    if not ua_string:
        return {"name": "Mobile Device", "type": "mobile", "os": "Unknown"}
    ua = ua_string.lower()

    android_ver = ""
    m = re.search(r'android ([\d.]+)', ua)
    if m:
        android_ver = f" (Android {m.group(1)})"

    ios_ver = ""
    m2 = re.search(r'os ([\d_]+) like', ua)
    if m2:
        ios_ver = f" (iOS {m2.group(1).replace('_', '.')})"

    if "iphone" in ua:
        return {"name": f"Apple iPhone{ios_ver}", "type": "mobile", "os": f"iOS{ios_ver}"}
    if "ipad" in ua:
        return {"name": f"Apple iPad{ios_ver}", "type": "tablet", "os": f"iPadOS{ios_ver}"}
    if "macintosh" in ua or "mac os x" in ua:
        return {"name": "MacBook / macOS", "type": "laptop", "os": "macOS"}
    if "android" in ua:
        model = _extract_android_model(ua_string)
        if model:
            if re.match(r'^sm-', model, re.I):
                label = f"Samsung {model.upper()}"
            elif re.match(r'^pixel', model, re.I):
                label = f"Google {model}"
            elif re.match(r'^(redmi|poco|mi |xiaomi)', model, re.I):
                label = model
            elif re.match(r'^(m\d{4}|\d{5}[a-z]{3,})', model, re.I):
                label = f"Xiaomi {model}"
            else:
                label = model
            return {"name": label, "type": "mobile", "os": f"Android{android_ver}"}
        for key, label in (
            ("samsung", "Samsung Galaxy"),
            ("sm-", "Samsung Galaxy"),
            ("pixel", "Google Pixel"),
            ("oneplus", "OnePlus"),
            ("vivo", "Vivo"),
            ("oppo", "Oppo"),
            ("realme", "Realme"),
        ):
            if key in ua:
                return {"name": f"{label}{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
        if any(k in ua for k in ("redmi", "xiaomi", "poco", "miui")):
            return {"name": f"Xiaomi / Redmi{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
        return {"name": f"Android Phone{android_ver}", "type": "mobile", "os": f"Android{android_ver}"}
    if "windows nt 10" in ua:
        return {"name": "Windows 10/11 PC", "type": "desktop", "os": "Windows 10/11"}
    if "windows" in ua:
        return {"name": "Windows PC", "type": "desktop", "os": "Windows"}
    if "linux" in ua:
        return {"name": "Linux PC", "type": "desktop", "os": "Linux"}
    return {"name": "Unknown Device", "type": "mobile", "os": "Unknown"}


NAME_PRIORITY = {"": 0, "fallback": 1, "ua": 2, "host": 3, "student": 4, "system": 5}
GENERIC_NAME_RE = re.compile(
    r"^(Hotspot Device|Mobile Device|Client Device|Unknown Device|Unidentified Device|Android Phone)", re.I
)
ONLINE_WINDOW_SEC = 120


def clean_hostname(raw: str, own_hostname: str = ""):
    if not raw:
        return None
    label = raw.strip().rstrip(".").split(".")[0].strip()
    if len(label) < 2 or len(label) > 63:
        return None
    low = label.lower()
    if low in ("localhost", "unknown", "gateway", "router") or low == (own_hostname or "").lower():
        return None
    if re.fullmatch(r"[\d\-_]+", label):
        return None
    if re.fullmatch(r"(android[-_]?)?[0-9a-f]{10,}", low):
        return None
    return label


def fallback_device_name(ip: str, mac: str = "") -> str:
    if mac and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac.lower()):
        return f"Unidentified Device ({mac[-5:].upper()})"
    return f"Unidentified Device (#{ip.split('.')[-1]})"
