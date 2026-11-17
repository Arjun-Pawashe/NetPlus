# 🛰️ NetPlus — Campus Network Intelligence & Monitoring System

![NetPlus](https://img.shields.io/badge/NetPlus-Cyber%20NOC%20v4.0-6366f1?style=for-the-badge&logo=satellite&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-3b82f6?style=for-the-badge&logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-10b981?style=for-the-badge&logo=fastapi&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-f59e0b?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-0078D4?style=for-the-badge)

> **Real-time proxy-based network monitoring** — classify and report web requests from devices configured to use the proxy. Internet sharing is handled separately by Windows ICS or Linux NetworkManager.

---

## 📖 Overview

NetPlus runs an HTTP proxy and dashboard on the laptop. For a Wi-Fi internet uplink shared to a wired router, Windows Internet Connection Sharing (ICS) provides routing/NAT to the router's access-point network. Devices must explicitly use NetPlus's proxy to have their web requests logged; ICS alone does not make traffic visible to NetPlus.

### Use Cases
- **College Lab Monitoring** — Track what students browse during lab hours
- **Home Parental Controls** — Monitor and block sites for kids devices
- **Network Research** — Analyze real traffic patterns and bandwidth
- **Cybersecurity Education** — Understand HTTP/HTTPS proxying and traffic analysis

### Recent updates in the current build
- **Student attendance workflows** for lab/theory sessions with year/division/batch filters and MAC-based check-ins
- **Academic registration system** with department/year/division/batch dropdowns and admin-managed batch lists
- **Persistent device naming** with hostname, student, and model-based naming that respects user rename overrides
- **Device lifecycle controls** for clear-history, remove-device, and quota resets without erasing student records
- **ML-ready export endpoints** for traffic feature datasets and local AI analysis schema

---

## ✨ Features

### Core Monitoring
| Feature | Description |
|---------|-------------|
| Real-time Website Tracking | Proxied HTTP/HTTPS requests displayed as they arrive |
| Per-device Attribution | Identifies which device made each request |
| Smart Domain Normalization | Maps CDN subdomains to root brands (ytimg.com → youtube.com) |
| Background Noise Filtering | Filters OS telemetry, analytics, ads — show only human-visited sites |
| Device Auto-detection | Reads User-Agent to identify Samsung, Xiaomi, iPhone, Windows PC with OS version |
| WebSocket Live Streaming | New requests appear on dashboard with flash animation in real-time |

### Access Control
| Feature | Description |
|---------|-------------|
| Domain Blocker | Block any domain — device gets a custom 403 page at proxy level |
| Per-device Daily Quotas | Set MB/day data caps — device blocked when limit hit |
| Policy Management UI | Full modal interface to add/remove block rules |

### Analytics
| Feature | Description |
|---------|-------------|
| Local AI Traffic Analysis | Learns per-device hourly request baselines from the last 30 days of gateway logs and highlights unusual activity after at least 3 historical comparison days; all analysis stays on the gateway |
| Live KPI Dashboard | Total visits, bandwidth, devices, blocks — auto-refreshed every 4s |
| Activity Timeline Chart | Live line chart streamed via WebSocket |
| Category Donut Chart | Academic, Social, Gaming, Messaging breakdown |
| Top Sites Bar Chart | Most-visited domains ranked by frequency |
| Hourly Bandwidth Trend | 24-hour bar chart of data consumption |
| Network Latency Monitor | Pings configurable targets every 30s |
| Session Grouping | Groups browsing into sessions (30-min gap = new session) |
| Date Range Filtering | Filter all data by custom from/to date |

### Dashboard UI
| Feature | Description |
|---------|-------------|
| Dark / Light Mode | Toggle with persistent preference |
| Mobile Responsive | Works on tablet and mobile browser |
| Device Matrix Grid | Cards per device with liveness badge, top sites, quota bar |
| Device Drilldown Modal | Full history, sessions, top sites, quota per device |
| Real Device Names | Shows the device's own hostname (e.g. `Galaxy-A51`, `Rahuls-iPhone`); falls back to the exact phone model from the User-Agent, then a stable `Unidentified Device (AB:CD)` label — never a random name. Linked students show as `<Student>'s Device`. A name you set with ✏️ Rename is never overwritten |
| Remove Device / Clear History | 🧹 clears one device's browsing history (device stays); 🗑 removes the device, its history and quota (`DELETE /api/devices/{ip}[/history]`). Student and attendance data are kept. A removed device is not re-added by the background scan; it returns only if it browses through the proxy again |
| HTML Audit Report | Download printable report with all device stats |
| CSV Log Export | Full log export |
| Browser Notifications | Desktop alert when blocked site attempted |
| Animated Particle Background | 80-node network canvas animation |

### Student Attendance
| Feature | Description |
|---------|-------------|
| First-use Student Registration | Plain HTTP requests from an unregistered hotspot device redirect to a join form (PRN, Name, Department, Year, Div, Batch) until registration is complete, keeping captive-portal screens from dismissing early. Prompt history is remembered across restarts; admins can reset it with `POST /api/attendance/prompts/reset` |
| Year-wise Batches | Each academic year (FE / SE / TE / BE) has its own batch list. Choosing a Year narrows the Batch dropdown; admins can add batches from the Register Student modal (`/api/academic/batches`) |
| Student Dropdowns | Department, Year, Div and Batch are dropdowns (validated server-side); attendance ledger shows and filters by all of them |
| Attendance Sessions (Lab / Theory) | The admin starts a session (type, optional title, date, time, and the **Year / Div / Batch** allowed) and ends it manually. Attendance is recorded for the running session only, and only for students of its Year/Div/Batch; when no session is running, connections are ignored. Each new session starts with an empty list, so the same student is marked again in every session. Only one session runs at a time. Ended sessions can be reviewed from the session dropdown, exported, or deleted with their records |
| MAC-based Check-in | Windows ARP or Linux neighbor table associates a downstream client's IP with its MAC; known devices that belong to the running session are checked in on proxy activity, once per session |
| Attendance Dashboard | View attendance per session (or all sessions of a date), batch, first seen, last seen, and proxy request count. Records made before sessions existed appear under “Legacy daily records” |
| Edit Student Details | ✎ button on every attendance row (and on matched devices in the radar) opens the student form pre-filled; change PRN, name, department, year, division or batch (`PUT /api/students/{mac}`). Optionally corrects the student's past attendance rows too |
| Admin Device Registration | Register or update a student's PRN, name, department, year, division and batch against a MAC directly from the dashboard |

The gateway cannot launch a browser on a device. The registration redirect happens only after that device makes a plain HTTP request through the configured proxy; it repeats for unregistered devices until registration is complete. HTTPS CONNECT traffic cannot be redirected without TLS interception. The OS neighbor table must be able to resolve the downstream client's MAC. Devices using randomized MAC addresses must keep the same private address for this network, or they may need to register again.

---

## 🏗️ Architecture

```
+------------------------------------------------------------------+
|                        HOST PC (Windows)                         |
|                                                                  |
|  +-----------------+    +----------------+    +---------------+  |
|  |   engine.py     |<-->|   server.py    |<-->|   static/     |  |
|  | (Proxy Gateway) |    | (FastAPI + WS) |    |  Dashboard    |  |
|  |  Port: 8080     |    |  Port: 5000    |    |  index.html   |  |
|  +-----------------+    +----------------+    +---------------+  |
|         |                       |                                 |
|         v                       v                                 |
|  +----------------------------------------------+                |
|  |         network_logs.db (SQLite)              |                |
|  | access_logs | devices | blocklist | quotas    |                |
|  +----------------------------------------------+                |
+--------------------------------+---------------------------------+
                                 | Windows ICS / Linux NetworkManager shared mode
                    +------------+------------+
                    v                         v
             Router client             Router client
       Optional manual proxy: gateway address:8080
```

Internet sharing is provided by Windows ICS or Linux NetworkManager. Only
devices/apps explicitly configured for the proxy are monitored.

---

## 📁 Project Structure

```
NetPlus-main (2)/
├── engine.py               # HTTP/HTTPS proxy gateway (TCP, multi-threaded)
├── server.py               # FastAPI web server + REST API + WebSocket
├── network_logs.db         # SQLite database (created on first run)
├── requirements.txt        # Python dependencies
├── start_netpulse.bat      # Windows startup launcher
├── start_netpulse.sh       # Linux startup launcher
├── README.md               # Project documentation
├── PROJECT_DOCUMENTATION.md # System design / academic project write-up
├── static/
│   ├── attendance.html     # Student registration page
│   ├── index.html          # Dashboard UI (charts, modals, tables)
│   ├── style.css           # Dark/light responsive styling
│   └── app.js              # Frontend logic and live dashboard behavior
├── gateway_proxy.py        # Optional proxy helpers / compatibility layer
├── test_sniffer.py         # Local traffic checks / validation helper
└── __pycache__/            # Python cache output
```

---

## ⚡ Quick Setup

### Prerequisites

```bash
py -3 -m pip install -r requirements.txt
```

Python 3.10+ required. No other dependencies.

### Windows: Public Wi-Fi uplink → Ethernet router

This layout uses the laptop as the internet-sharing gateway and the router as a
wired access point. Use a router/AP you administer and follow the public
Wi-Fi network's terms. Complete any captive-portal sign-in on the laptop first.

1. Connect the laptop to the public Wi-Fi and verify that the laptop itself has
   internet access.
2. Connect laptop Ethernet to a **LAN** port on the router. Do not use the
   router's WAN/Internet port for this access-point layout.
3. Configure the router in **AP/bridge mode**. Disable its DHCP server so
   Windows ICS is the only DHCP server. If AP mode is unavailable, configure
   the equivalent bridge settings and ensure its LAN address does not conflict
   with ICS. Do not leave router/NAT mode enabled.
4. On Windows, open **Control Panel → Network and Internet → Network
   Connections** (or run `ncpa.cpl`). Right-click the **Wi-Fi** adapter →
   **Properties → Sharing**. Enable **Allow other network users to connect
   through this computer's Internet connection** and select the **Ethernet**
   adapter as the home networking connection. Windows ICS commonly assigns
   Ethernet `192.168.137.1/24`; check the Ethernet adapter's IPv4 address after
   enabling sharing.
5. Connect a test device to the router's Wi-Fi/LAN and confirm it receives an
   address and can browse the internet. If it does not, confirm AP mode, only
   one DHCP server, ICS's selected adapter, and any captive-portal requirements.
6. Start NetPlus using `start_netpulse.bat`. Open `http://localhost:5000` on
   the laptop. The Windows launcher uses `192.168.137.1:8081` by default to
   avoid a conflict with services that already use port 8080.

If ICS uses a different Ethernet address or client subnet, configure both
values in the same Command Prompt before starting NetPlus:

```bat
set NETPLUS_GATEWAY_IP=192.168.137.1
set NETPLUS_CLIENT_NETWORK=192.168.137.0/24
set NETPLUS_PROXY_PORT=8081
start_netpulse.bat
```

Replace the example values with the actual ICS Ethernet gateway and the
router-client subnet. `NETPLUS_GATEWAY_IP` is the proxy address devices use;
`NETPLUS_CLIENT_NETWORK` limits which addresses the dashboard treats as
downstream clients. The batch launcher uses those environment variables, or
the Windows ICS defaults above.

### Configure monitoring on each device

Internet sharing works independently of monitoring. To send a device's web
traffic through NetPlus, set that device's Wi-Fi proxy to **Manual**:

| Device setting | Value |
|---------|-------|
| Proxy mode | Manual |
| Proxy host | Laptop's ICS Ethernet address (default `192.168.137.1`) |
| Proxy port | `8081` (Windows launcher default) |

**Android:** Wi-Fi settings → network details/modify → Advanced → Proxy: Manual  
**iPhone:** Settings → Wi-Fi → network info → HTTP Proxy → Manual  
**Windows/macOS:** Set the HTTP/HTTPS proxy in the network or system proxy settings.

Only apps that honor the configured proxy are logged. Other apps/devices can
still get internet through ICS but will not appear as browsing activity in
NetPlus. HTTPS proxying reveals the destination hostname, not encrypted page
contents or URL paths. The proxy does not provide transparent monitoring.
Allow inbound TCP `8081` only on the trusted Ethernet/private network in
Windows Firewall; do not allow it on the public Wi-Fi. If you choose a
different port, set `NETPLUS_PROXY_PORT` before launching and allow that port.
The dashboard includes administrative APIs and has no authentication: keep port `5000` blocked from
the public Wi-Fi and do not expose it to untrusted clients. Client-side student
registration redirects require access to port `5000`; only enable that access
on a trusted downstream network when needed.

### Linux (NetworkManager)

The Linux version uses NetworkManager's hotspot (shared/NAT) mode. NetPlus does
not configure Wi-Fi or change firewall rules for you. Use it only with devices
you own or have permission to monitor.

#### 1. Check the RTL8825BE driver and AP support

Install the distro's normal firmware and wireless tools first. On Debian/Ubuntu:

```bash
sudo apt update
sudo apt install python3 python3-venv python3-pip network-manager iw iproute2
lspci -nnk | grep -A3 -i 'network controller'
iw list | sed -n '/Supported interface modes:/,/Band/p'
```

In the `iw list` output, look for `* AP`. The exact RTL8825BE driver/firmware
availability depends on your Linux distribution and kernel; check the driver
shown by `lspci -nnk` and install the firmware package recommended by that
distro. Update to a supported kernel if the device is not detected. Do not
install an unrelated third-party driver unless the distro's driver support
specifically requires it.

#### 2. Create the hotspot

In GNOME, open **Settings → Wi-Fi → ⋮ → Turn On Wi-Fi Hotspot**, then set a
strong password. Other NetworkManager desktops have a similar hotspot action.
You can also use:

```bash
nmcli device status
nmcli device wifi hotspot ifname <wifi-interface> ssid NetPlusHotspot password '<strong-password>'
```

Replace `<wifi-interface>` with the interface shown by `nmcli device status`.
The common NetworkManager shared-mode gateway is `10.42.0.1/24`; confirm yours
with `ip -4 address show dev <wifi-interface>`. A wired Ethernet connection is
the simplest internet uplink. Starting a Wi-Fi hotspot may disconnect an
existing Wi-Fi connection if the driver cannot run client and AP modes at the
same time.

#### 3. Start NetPlus

From the project directory:

```bash
bash start_netpulse.sh
```

The script creates a local `.venv`, installs `requirements.txt` there if
needed, and starts the app. Open `http://127.0.0.1:5000` on the host. For a
non-default hotspot address or subnet, pass the values when starting it:

```bash
NETPLUS_GATEWAY_IP=10.42.0.1 \
NETPLUS_CLIENT_NETWORK=10.42.0.0/24 \
bash start_netpulse.sh
```

Use the gateway address and IPv4 subnet actually shown by your hotspot. The
dashboard and redirect links use `NETPLUS_GATEWAY_IP`; client discovery is
limited to `NETPLUS_CLIENT_NETWORK`. Linux reads client MAC addresses from the
neighbor table (`ip neigh`/`/proc/net/arp`).

The dashboard currently has no authentication and includes administrative APIs.
Only share the hotspot with trusted devices; do not expose port 5000 to an
untrusted network. If UFW blocks hotspot traffic, allow the proxy on the hotspot
interface (substitute the actual interface name):

```bash
sudo ufw allow in on <wifi-interface> to any port 8080 proto tcp
```

Port 5000 is also required on the hotspot interface only if you intentionally
use the student registration redirect. Exposing it gives hotspot clients access
to the unauthenticated dashboard and its admin APIs.

#### 4. Configure your test device

Connect a device you control to the hotspot and set its Wi-Fi proxy to **Manual**:

| Setting | Value |
|---------|-------|
| Proxy host | Hotspot gateway (commonly `10.42.0.1`) |
| Proxy port | `8080` |

HTTPS sites expose only the CONNECT hostname to this proxy, not encrypted page
contents. The app does not configure a transparent proxy; only traffic from
devices on which you manually set this proxy is recorded.

---

## 🔌 API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/config | Runtime config: gateway IP, proxy port and downstream client network |
| GET | /api/stats | KPI metrics. Supports `mode`, `date_from`, `date_to` |
| GET | /api/ai/analysis | Local rolling traffic analysis with per-device hourly anomaly estimates |
| GET | /api/academic/options | Department/year/division/batch options and year-wise batch map |
| POST | /api/academic/batches | Add a `year` + `batch` entry |
| DELETE | /api/academic/batches/{year}/{batch} | Remove a year-specific batch only when unused |
| POST | /api/attendance/prompts/reset | Re-enable registration prompts for one device or all devices |
| GET | /attendance/register | Student registration page |
| POST | /api/attendance/register | Register PRN, name, and batch against the hotspot MAC; recorded only if a matching session is running |
| GET | /api/attendance | Attendance records. Optional `date=YYYY-MM-DD` and `session_id=<id>\|all\|legacy` |
| GET | /api/attendance/stats | Present / eligible / active counts. Optional `date`, `session_id` |
| POST | /api/attendance/checkin | Admin override: mark a student (by PRN) in a session (default: the running one) |
| GET | /api/attendance/sessions | Sessions, newest first. Optional `date=YYYY-MM-DD` |
| GET | /api/attendance/sessions/active | The running session, or `null` |
| POST | /api/attendance/sessions | Start a session `{session_type: Lab\|Theory, title, date, time, year, division, batch}` (empty year/division/batch = all) |
| POST | /api/attendance/sessions/{id}/end | End the running session |
| DELETE | /api/attendance/sessions/{id} | Delete an ended session and its attendance records |
| GET | /api/connected-devices | Connected devices from ARP/neighbor discovery plus student registration state |
| GET | /api/students | Registered student roster |
| POST | /api/students | Admin registration by MAC address, PRN, name, department, year, division, and batch |
| PUT | /api/students/{mac} | Update student details and optionally apply to matching historical attendance rows |
| DELETE | /api/students/{prn} | Remove a registered student |
| GET | /api/export/schema | AI dataset schema / feature definitions |
| GET | /api/export/ai-dataset | Export ML-ready feature rows as CSV/JSON |
| GET | /api/devices | All devices with liveness, stats, quotas |
| GET | /api/devices/{ip}/activity | Full activity for one device |
| GET | /api/sessions/{ip} | Session-grouped browsing history |
| PUT | /api/devices/{ip}/rename | Set custom device nickname |
| DELETE | /api/devices/{ip}/history | Clear browsing history while leaving the device card |
| DELETE | /api/devices/{ip} | Remove a device and its history/quotas while keeping student/attendance data |
| GET | /api/logs | Filterable log (mode, category, client_ip, status, search, dates) |
| POST | /api/logs/clear | Delete all logs and device records |
| GET | /api/policy/rules | List all blocked domains |
| POST | /api/policy/block | Block a domain (proxy enforced) |
| POST | /api/policy/unblock | Remove a block rule |
| GET | /api/quota | List all quotas with usage |
| POST | /api/quota/set | Set daily MB cap for a device |
| DELETE | /api/quota/{ip} | Remove quota for a device |
| GET | /api/bandwidth/trend | Hourly bytes for last 24h |
| GET | /api/latency | Latency history for all targets |
| GET | /api/latency/targets | List configured ping targets |
| POST | /api/latency/targets | Add target `{label, host, port}` |
| DELETE | /api/latency/targets/{id} | Remove a latency target |
| GET | /api/report | Download HTML audit report |
| WS | /ws | WebSocket for live log streaming |

---

## 🗃️ Database Schema

### access_logs
```sql
id, timestamp, client_ip, device_name, device_type,
domain (raw), clean_site (normalized), is_background,
category, method, bytes_transferred, status, risk_flag, user_agent
```

### devices
```sql
ip, custom_name, auto_name, device_type, first_seen, last_seen
```

### blocklist
```sql
id, domain, reason, created_at
```

### device_quotas
```sql
ip, daily_mb_limit, enabled, created_at
```

### latency_targets
```sql
id, label, host, port, enabled
```

---

## 🧠 How It Works

1. Laptop shares its internet connection to a downstream network using Windows ICS or NetworkManager shared mode
2. Devices get internet through that network; only devices configured to use the proxy send monitored web requests through NetPlus
3. Proxied HTTP/HTTPS traffic flows through engine.py's TCP proxy
4. For HTTPS: reads the CONNECT hostname:443 header (domain visible before TLS)
5. Domain is normalized, categorized, checked against blocklist + quotas
6. Logged to SQLite and broadcast via WebSocket to the dashboard
7. Dashboard auto-refreshes every 4 seconds; new rows flash in real-time

---

## 🔒 Privacy & Ethics

This tool is intended for network administrators monitoring their own infrastructure.
**Do NOT use to monitor devices without explicit consent of the device owner.**
Unauthorized interception of network traffic may be illegal in your jurisdiction.

---

## 🛣️ Roadmap

- [ ] HTTPS Deep Inspection — Full URL paths via mitmproxy
- [ ] Predictive Bandwidth Forecasting — Moving average model
- [ ] Per-device Time Restrictions — Block social media during lab hours
- [ ] Email Alerts — Notify admin on quota exceeded or blocked site
- [ ] MAC address capture — More reliable device identity than IP

---

## 📄 License

MIT License

---

## 👨‍💻 Author

**Original: Pankaj Shinde**  
GitHub: [@Pankaj-Shinde-07](https://github.com/Pankaj-Shinde-07)

**Modifications By: Arjun Pawashe**  
GitHub: [Arjun Pawashe](https://github.com/Arjun-Pawashe/)

---

*NetPlus Cyber NOC v4.0 · Python · FastAPI · SQLite · Vanilla JS · Chart.js*
