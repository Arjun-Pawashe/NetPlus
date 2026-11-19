# NetPlus Router Gateway — Windows 10/11 + TP-Link TL-WR740N

Zero-proxy campus network monitoring, DNS/firewall access control, local AI traffic anomaly detection, and MAC-based student attendance—ported from the original NetPlus proxy architecture to run behind a **TP-Link TL-WR740N** in **AP / Bridge mode** on Windows 10/11.

## Architecture

```
Internet Uplink (Wi-Fi / Modem)
       │
  Host PC (Windows 10/11 + ICS)
  ├── dns_sinkhole.py       UDP :53  — DNS forwarder, domain logging, blocklist sinkhole & captive probes
  ├── packet_sniffer.py     Npcap    — TLS ClientHello SNI, HTTP Host/UA, per-device byte accounting
  ├── packet_sniffer.py     TCP :80  — Captive portal 302 redirect to /attendance/register
  ├── firewall_enforcer.py  netsh    — OS-level Windows Firewall daily MB quota enforcement
  ├── router_poller.py      HTTP     — Optional TL-WR740N web-UI wireless station poller
  └── server.py             TCP :5000— FastAPI dashboard, WebSocket /ws, AI analysis & attendance
       │  (Ethernet)
  TP-Link TL-WR740N (LAN port, DHCP OFF, AP/Bridge mode)
       │  (Wi-Fi & LAN — Zero proxy config on student devices)
  Student Devices
```

## Quick Setup (Windows 10/11 + TL-WR740N)

1. **Install Prerequisites**:
   - Install **Python 3.10+** and **Npcap** (with WinPcap API-compatible mode enabled) on the Windows Host PC.
   - Install Python packages:
     ```bat
     py -3 -m pip install -r requirements.txt
     ```
2. **Configure TP-Link TL-WR740N (AP / Bridge Mode)**:
   - Connect your PC to a **LAN** port on the TL-WR740N and open `http://192.168.0.1` (or `http://tplinklogin.net`).
   - Go to **Network → LAN**: set the router LAN IP to `192.168.137.2` (outside Windows ICS's DHCP pool, inside `192.168.137.0/24`).
   - Go to **DHCP → DHCP Settings**: **Disable** the DHCP Server and reboot the router.
3. **Enable Windows Internet Connection Sharing (ICS)**:
   - Open `ncpa.cpl` → right-click your internet-connected adapter (e.g. Wi-Fi) → **Properties → Sharing**.
   - Check **Allow other network users to connect through this computer's Internet connection** and select the **Ethernet** adapter connected to the TL-WR740N's **LAN** port (leave the router's WAN port unplugged).
   - Windows ICS assigns `192.168.137.1/24` to Ethernet and acts as the DHCP/DNS gateway.
4. **Launch as Administrator**:
   - Right-click `start_netplus_router.bat` → **Run as administrator** (required for UDP 53, TCP 80, Npcap packet capture, and `netsh advfirewall` quota rules).
   - Open `http://localhost:5000`.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `NETPLUS_GATEWAY_IP` | `192.168.137.1` | Host PC ICS Ethernet IP |
| `NETPLUS_CLIENT_NETWORK` | `192.168.137.0/24` | Downstream client subnet |
| `NETPLUS_DNS_PORT` | `53` | Local DNS sinkhole UDP port |
| `NETPLUS_UPSTREAM_DNS` | `8.8.8.8` | Upstream DNS resolver |
| `NETPLUS_CAPTIVE_HTTP_PORT` | `80` | Captive portal HTTP redirect port |
| `NETPLUS_CAPTURE_IFACE` | *(auto)* | Optional Npcap interface name |
| `NETPLUS_ROUTER_POLL` | `0` | Set `1` to poll TL-WR740N `/userRpm/WlanStationRpm.htm` |
| `NETPLUS_ROUTER_IP` | `192.168.137.2` | TL-WR740N LAN IP |
| `NETPLUS_ROUTER_USER` / `PASS` | `admin` / `admin` | TL-WR740N admin credentials |

## Key New Endpoints

- `GET /api/router/status` — Live status of DNS sinkhole, Npcap sniffer, captive HTTP redirector, Windows Firewall enforcer, and optional TL-WR740N poller.
- `POST /api/router/config` — Configure/test the TL-WR740N web-UI poller at runtime.
- `GET /api/quota/enforced` — List IPs currently blocked by OS-level Windows Firewall quota rules.
