import os
import socket
import struct
import threading
import time
from typing import Callable, Optional


CAPTIVE_PROBE_DOMAINS = {
    "connectivitycheck.gstatic.com",
    "clients3.google.com",
    "captive.apple.com",
    "www.msftconnecttest.com",
    "msftconnecttest.com",
    "detectportal.firefox.com",
}


def parse_dns_question(packet: bytes):
    """Parse DNS header + first question. Returns (tx_id, flags, qname, qtype, qclass, question_end_offset)."""
    if len(packet) < 12:
        return None
    tx_id, flags, qdcount, _, _, _ = struct.unpack("!HHHHHH", packet[:12])
    if qdcount < 1:
        return None

    offset = 12
    labels = []
    while offset < len(packet):
        length = packet[offset]
        offset += 1
        if length == 0:
            break
        if (length & 0xC0) == 0xC0:
            # Compression pointer shouldn't appear in first question, bail safely
            return None
        if offset + length > len(packet):
            return None
        labels.append(packet[offset:offset + length].decode("utf-8", errors="ignore"))
        offset += length

    if offset + 4 > len(packet):
        return None
    qtype, qclass = struct.unpack("!HH", packet[offset:offset + 4])
    qname = ".".join(labels).lower()
    return tx_id, flags, qname, qtype, qclass, offset + 4


def build_dns_ip_response(query: bytes, q_end: int, ip_str: str, ttl: int = 15) -> bytes:
    """Build a minimal DNS A-record response pointing to ip_str."""
    tx_id = query[:2]
    req_flags = struct.unpack("!H", query[2:4])[0]
    rd = req_flags & 0x0100
    resp_flags = 0x8180 | rd  # Standard response, recursion available
    header = tx_id + struct.pack("!HHHHH", resp_flags, 1, 1, 0, 0)
    question = query[12:q_end]
    rdata = socket.inet_aton(ip_str)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, ttl, 4) + rdata
    return header + question + answer


def build_dns_nxdomain_response(query: bytes, q_end: int) -> bytes:
    """Build a minimal DNS NXDOMAIN response (used for AAAA/HTTPS when sinkholing)."""
    tx_id = query[:2]
    req_flags = struct.unpack("!H", query[2:4])[0]
    rd = req_flags & 0x0100
    resp_flags = 0x8183 | rd  # RCODE = 3 (NXDOMAIN)
    header = tx_id + struct.pack("!HHHHH", resp_flags, 1, 0, 0, 0)
    return header + query[12:q_end]


class DnsSinkholeServer:
    """
    Lightweight UDP DNS forwarder & sinkhole for the Windows ICS / TL-WR740N gateway.
    - Logs queried domains per client IP
    - Sinkholes blocked domains (returns 0.0.0.0 or NXDOMAIN)
    - Redirects unregistered captive probes to GATEWAY_IP when captive_redirect is enabled
    - Forwards allowed queries to upstream DNS (default 8.8.8.8)
    """

    def __init__(
        self,
        listen_ip: str = "0.0.0.0",
        port: Optional[int] = None,
        upstream_dns: Optional[str] = None,
        gateway_ip: str = "192.168.137.1",
        on_query: Optional[Callable[[str, str, str], None]] = None,
        is_blocked_fn: Optional[Callable[[str], bool]] = None,
        should_captive_redirect_fn: Optional[Callable[[str, str], bool]] = None,
    ):
        self.listen_ip = listen_ip
        self.port = port if port is not None else int(os.environ.get("NETPLUS_DNS_PORT", "53"))
        self.upstream_dns = upstream_dns or os.environ.get("NETPLUS_UPSTREAM_DNS", "8.8.8.8")
        self.gateway_ip = gateway_ip
        self.on_query = on_query
        self.is_blocked_fn = is_blocked_fn or (lambda _d: False)
        self.should_captive_redirect_fn = should_captive_redirect_fn or (lambda _ip, _d: False)

        self.running = False
        self.active = False
        self.last_error = ""
        self._sock: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._recent_cache = {}  # (client_ip, qname) -> timestamp
        self._cache_lock = threading.Lock()

    def start(self):
        if self.running:
            return
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.listen_ip, self.port))
            self._sock.settimeout(1.0)
            self.running = True
            self.active = True
            self.last_error = ""
            self._thread = threading.Thread(target=self._serve_loop, daemon=True)
            self._thread.start()
            print(f"🛰️  DNS Sinkhole listening on {self.listen_ip}:{self.port} (upstream {self.upstream_dns})")
        except PermissionError as exc:
            self.active = False
            self.last_error = f"Port {self.port} requires Administrator privileges: {exc}"
            print(f"⚠️  DNS Sinkhole not started: {self.last_error}")
        except OSError as exc:
            self.active = False
            self.last_error = str(exc)
            print(f"⚠️  DNS Sinkhole bind failed on {self.listen_ip}:{self.port}: {exc}")

    def stop(self):
        self.running = False
        self.active = False
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def _serve_loop(self):
        while self.running and self._sock:
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_packet, args=(data, addr), daemon=True).start()

    def _should_log(self, client_ip: str, qname: str) -> bool:
        now = time.time()
        key = (client_ip, qname)
        with self._cache_lock:
            last = self._recent_cache.get(key, 0)
            if now - last < 5.0:
                return False
            self._recent_cache[key] = now
            if len(self._recent_cache) > 5000:
                cutoff = now - 30.0
                self._recent_cache = {k: v for k, v in self._recent_cache.items() if v > cutoff}
        return True

    def _handle_packet(self, data: bytes, addr):
        client_ip = addr[0]
        parsed = parse_dns_question(data)
        if not parsed:
            return
        _, _, qname, qtype, _, q_end = parsed

        # Check blocklist
        if self.is_blocked_fn(qname):
            resp = build_dns_ip_response(data, q_end, "0.0.0.0", ttl=10) if qtype == 1 else build_dns_nxdomain_response(data, q_end)
            try:
                self._sock.sendto(resp, addr)
            except OSError:
                pass
            if self.on_query and self._should_log(client_ip, qname):
                self.on_query(client_ip, qname, "Blocked")
            return

        # Captive portal intercept for unregistered devices on OS connectivity probes
        if qtype == 1 and self.should_captive_redirect_fn(client_ip, qname):
            resp = build_dns_ip_response(data, q_end, self.gateway_ip, ttl=5)
            try:
                self._sock.sendto(resp, addr)
            except OSError:
                pass
            return

        # Log allowed DNS lookup (deduplicated)
        if self.on_query and self._should_log(client_ip, qname):
            self.on_query(client_ip, qname, "Allowed")

        # Forward to upstream DNS
        up_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up_sock.settimeout(3.0)
        try:
            up_sock.sendto(data, (self.upstream_dns, 53))
            resp, _ = up_sock.recvfrom(4096)
            if self._sock:
                self._sock.sendto(resp, addr)
        except Exception:
            pass
        finally:
            up_sock.close()
