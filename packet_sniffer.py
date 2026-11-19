import os
import re
import socket
import struct
import threading
import time
from typing import Callable, Optional


def extract_tls_sni(payload: bytes) -> Optional[str]:
    """
    Parse a TLS ClientHello TCP payload and extract the Server Name Indication (SNI) hostname.
    Returns None if the payload is not a TLS ClientHello or has no SNI extension.
    """
    try:
        if len(payload) < 43:
            return None
        # Record layer: ContentType=22 (Handshake), Version 0x03xx
        if payload[0] != 0x16 or payload[1] != 0x03:
            return None
        rec_len = struct.unpack("!H", payload[3:5])[0]
        if len(payload) < 5 + rec_len and len(payload) < 60:
            return None

        pos = 5
        # Handshake type 1 = ClientHello
        if payload[pos] != 0x01:
            return None
        pos += 4  # skip type (1) + length (3)
        pos += 2  # client_version
        pos += 32  # random

        if pos >= len(payload):
            return None
        session_id_len = payload[pos]
        pos += 1 + session_id_len

        if pos + 2 > len(payload):
            return None
        cipher_suites_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2 + cipher_suites_len

        if pos >= len(payload):
            return None
        comp_methods_len = payload[pos]
        pos += 1 + comp_methods_len

        if pos + 2 > len(payload):
            return None
        extensions_len = struct.unpack("!H", payload[pos:pos + 2])[0]
        pos += 2
        end = min(len(payload), pos + extensions_len)

        while pos + 4 <= end:
            ext_type, ext_len = struct.unpack("!HH", payload[pos:pos + 4])
            pos += 4
            if ext_type == 0x0000:  # server_name
                if pos + 5 <= end:
                    list_len = struct.unpack("!H", payload[pos:pos + 2])[0]
                    name_type = payload[pos + 2]
                    name_len = struct.unpack("!H", payload[pos + 3:pos + 5])[0]
                    if name_type == 0 and pos + 5 + name_len <= pos + 2 + list_len:
                        return payload[pos + 5:pos + 5 + name_len].decode("utf-8", errors="ignore").lower()
                return None
            pos += ext_len
    except Exception:
        return None
    return None


def extract_http_info(payload: bytes):
    """Extract (method, host, user_agent) from a plain HTTP request payload."""
    try:
        text = payload[:4096].decode("utf-8", errors="ignore")
        lines = text.split("\r\n")
        if not lines or " " not in lines[0]:
            return None
        parts = lines[0].split()
        method = parts[0].upper()
        if method not in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"):
            return None
        host = ""
        ua = ""
        for line in lines[1:]:
            low = line.lower()
            if low.startswith("host:"):
                host = line.split(":", 1)[1].strip().split(":")[0].lower()
            elif low.startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip()
        if not host:
            return None
        return method, host, ua
    except Exception:
        return None


class CaptivePortalHttpRedirector:
    """
    Minimal HTTP listener on port 80 (GATEWAY_IP:80) to serve:
    - 302 Redirect to /attendance/register?token=... for unregistered students
    - 429 Quota Exceeded page if a quota-blocked client hits port 80
    """

    def __init__(
        self,
        listen_ip: str,
        port: Optional[int] = None,
        dashboard_port: int = 5000,
        issue_token_fn: Optional[Callable[[str], str]] = None,
        is_quota_exceeded_fn: Optional[Callable[[str], bool]] = None,
    ):
        self.listen_ip = listen_ip
        self.port = port if port is not None else int(os.environ.get("NETPLUS_CAPTIVE_HTTP_PORT", "80"))
        self.dashboard_port = dashboard_port
        self.issue_token_fn = issue_token_fn or (lambda _ip: "demo")
        self.is_quota_exceeded_fn = is_quota_exceeded_fn or (lambda _ip: False)
        self.running = False
        self.active = False
        self.last_error = ""
        self._sock: Optional[socket.socket] = None

    def start(self):
        if self.running:
            return
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.listen_ip, self.port))
            self._sock.listen(64)
            self._sock.settimeout(1.0)
            self.running = True
            self.active = True
            self.last_error = ""
            threading.Thread(target=self._accept_loop, daemon=True).start()
            print(f"🚪 Captive Portal HTTP Redirector listening on {self.listen_ip}:{self.port}")
        except Exception as exc:
            self.active = False
            self.last_error = str(exc)
            print(f"⚠️  Captive HTTP Redirector not started on {self.listen_ip}:{self.port}: {exc}")

    def stop(self):
        self.running = False
        self.active = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _accept_loop(self):
        while self.running and self._sock:
            try:
                conn, addr = self._sock.accept()
                threading.Thread(target=self._handle_conn, args=(conn, addr[0]), daemon=True).start()
            except socket.timeout:
                continue
            except OSError:
                break

    def _handle_conn(self, conn: socket.socket, client_ip: str):
        try:
            conn.settimeout(3.0)
            conn.recv(2048)
            if self.is_quota_exceeded_fn(client_ip):
                body = (
                    "<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;"
                    "padding:60px;background:#0b1220;color:#f8fafc;'>"
                    "<h1>Daily Data Quota Exceeded</h1>"
                    "<p>Your device has reached its daily limit on this network. Contact the lab administrator.</p>"
                    "</body></html>"
                ).encode("utf-8")
                resp = (
                    f"HTTP/1.1 429 Too Many Requests\r\nContent-Type: text/html\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                ).encode("ascii") + body
                conn.sendall(resp)
                return

            token = self.issue_token_fn(client_ip)
            location = f"http://{self.listen_ip}:{self.dashboard_port}/attendance/register?token={token}"
            resp = (
                "HTTP/1.1 302 Found\r\n"
                f"Location: {location}\r\n"
                "Cache-Control: no-store\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
            ).encode("ascii")
            conn.sendall(resp)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


class PacketSnifferEngine:
    """
    Npcap / Scapy passive packet sniffer for Windows 10/11 ICS Ethernet interface
    (connected to TL-WR740N AP/Bridge LAN port).
    Extracts TLS SNI, HTTP Host/User-Agent, and per-IP byte totals.
    """

    def __init__(
        self,
        is_client_ip_fn: Callable[[str], bool],
        on_domain_seen: Callable[[str, str, str, str, int], None],
        on_bytes_seen: Callable[[str, int], None],
        gateway_ip: str = "192.168.137.1",
        iface: Optional[str] = None,
    ):
        self.is_client_ip_fn = is_client_ip_fn
        self.on_domain_seen = on_domain_seen
        self.on_bytes_seen = on_bytes_seen
        self.gateway_ip = gateway_ip
        self.iface = iface or os.environ.get("NETPLUS_CAPTURE_IFACE", "").strip() or None

        self.running = False
        self.active = False
        self.last_error = ""
        self.captured_packets = 0
        self._byte_buffer = {}
        self._buf_lock = threading.Lock()
        self._recent_sni = {}  # (ip, domain) -> ts

    def _detect_iface(self):
        if self.iface:
            return self.iface
        try:
            from scapy.all import conf, get_if_addr
            for iface_name in conf.ifaces:
                try:
                    if get_if_addr(iface_name) == self.gateway_ip:
                        return iface_name
                except Exception:
                    continue
        except Exception:
            pass
        return None

    def start(self):
        if self.running:
            return
        try:
            import scapy.all as scapy  # noqa: F401
        except ImportError as exc:
            self.active = False
            self.last_error = f"Scapy/Npcap not installed ({exc}). Running with DNS + ARP mode."
            print(f"⚠️  Packet Sniffer disabled: {self.last_error}")
            return

        self.running = True
        threading.Thread(target=self._flush_bytes_loop, daemon=True).start()
        threading.Thread(target=self._sniff_loop, daemon=True).start()

    def stop(self):
        self.running = False
        self.active = False

    def _flush_bytes_loop(self):
        while self.running:
            time.sleep(3.0)
            with self._buf_lock:
                snapshot = dict(self._byte_buffer)
                self._byte_buffer.clear()
            for ip, byte_count in snapshot.items():
                if byte_count > 0:
                    try:
                        self.on_bytes_seen(ip, byte_count)
                    except Exception:
                        pass

    def _sniff_loop(self):
        try:
            from scapy.all import sniff
            target_iface = self._detect_iface()
            self.active = True
            self.last_error = ""
            print(f"📡 Npcap/Scapy Packet Sniffer active on interface: {target_iface or 'default'}")
            sniff(
                iface=target_iface,
                filter="ip and (tcp or udp)",
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _pkt: not self.running,
            )
        except Exception as exc:
            self.active = False
            self.last_error = str(exc)
            print(f"⚠️  Packet Sniffer stopped ({exc}). Make sure Npcap is installed and run as Administrator.")

    def _process_packet(self, pkt):
        try:
            from scapy.layers.inet import IP, TCP
            from scapy.packet import Raw
            if not pkt.haslayer(IP):
                return
            ip_layer = pkt[IP]
            src = ip_layer.src
            dst = ip_layer.dst
            pkt_len = len(pkt)
            self.captured_packets += 1

            client_ip = None
            outbound = False
            if self.is_client_ip_fn(src) and src != self.gateway_ip:
                client_ip = src
                outbound = True
            elif self.is_client_ip_fn(dst) and dst != self.gateway_ip:
                client_ip = dst

            if not client_ip:
                return

            with self._buf_lock:
                self._byte_buffer[client_ip] = self._byte_buffer.get(client_ip, 0) + pkt_len

            if outbound and pkt.haslayer(TCP) and pkt.haslayer(Raw):
                tcp = pkt[TCP]
                payload = bytes(pkt[Raw].load)
                if tcp.dport == 443:
                    sni = extract_tls_sni(payload)
                    if sni and self._should_emit(client_ip, sni):
                        self.on_domain_seen(client_ip, sni, "HTTPS-SNI", "", pkt_len)
                elif tcp.dport == 80:
                    http_info = extract_http_info(payload)
                    if http_info:
                        method, host, ua = http_info
                        if self._should_emit(client_ip, host):
                            self.on_domain_seen(client_ip, host, method, ua, pkt_len)
        except Exception:
            pass

    def _should_emit(self, client_ip: str, domain: str) -> bool:
        now = time.time()
        key = (client_ip, domain)
        last = self._recent_sni.get(key, 0)
        if now - last < 4.0:
            return False
        self._recent_sni[key] = now
        if len(self._recent_sni) > 4000:
            cutoff = now - 30.0
            self._recent_sni = {k: v for k, v in self._recent_sni.items() if v > cutoff}
        return True
