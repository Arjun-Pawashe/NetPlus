import os
import sqlite3
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

# Isolate DB in a temporary path before importing engine/server
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()

import db  # noqa: E402
db.DB_PATH = _tmp_db.name

from dns_sinkhole import build_dns_ip_response, build_dns_nxdomain_response, parse_dns_question  # noqa: E402
from firewall_enforcer import WindowsFirewallEnforcer  # noqa: E402
from packet_sniffer import extract_http_info, extract_tls_sni  # noqa: E402
from router_poller import TLWR740NPoller  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
import server  # noqa: E402


def _build_dns_query(domain: str, qtype: int = 1) -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in domain.split(".")) + b"\x00"
    return header + qname + struct.pack("!HH", qtype, 1)


def _build_tls_client_hello(sni: str) -> bytes:
    name_bytes = sni.encode("ascii")
    sni_entry = struct.pack("!BH", 0, len(name_bytes)) + name_bytes
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    sni_ext = struct.pack("!HH", 0x0000, len(sni_list)) + sni_list
    exts = struct.pack("!H", len(sni_ext)) + sni_ext
    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + struct.pack("!H", 2) + b"\x13\x01"
        + b"\x01\x00"
        + exts
    )
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs


class NetPlusRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(server.app)

    def test_dns_parser_and_sinkhole_builders(self):
        q = _build_dns_query("youtube.com", qtype=1)
        parsed = parse_dns_question(q)
        self.assertIsNotNone(parsed)
        tx_id, _, qname, qtype, _, q_end = parsed
        self.assertEqual(tx_id, 0x1234)
        self.assertEqual(qname, "youtube.com")
        self.assertEqual(qtype, 1)

        resp = build_dns_ip_response(q, q_end, "0.0.0.0")
        self.assertEqual(resp[:2], b"\x12\x34")
        self.assertTrue(resp.endswith(b"\x00\x00\x00\x00"))

        nx = build_dns_nxdomain_response(q, q_end)
        self.assertEqual(nx[3] & 0x0F, 3)

    def test_tls_sni_and_http_extraction(self):
        hello = _build_tls_client_hello("leetcode.com")
        self.assertEqual(extract_tls_sni(hello), "leetcode.com")

        http_req = b"GET /index.html HTTP/1.1\r\nHost: moodle.college.edu:80\r\nUser-Agent: Mozilla/5.0 (Linux; Android 14; SM-A515F)\r\n\r\n"
        method, host, ua = extract_http_info(http_req)
        self.assertEqual(method, "GET")
        self.assertEqual(host, "moodle.college.edu")
        self.assertIn("SM-A515F", ua)

    def test_tl_wr740n_html_parser(self):
        sample_html = '''
        <script>
        var hostList = new Array(
            "AA-BB-CC-DD-EE-01", 1, 120, 45,
            "11-22-33-44-55-66", 1, 80, 12
        );
        var wlanPara = new Array(1, "CollegeLab_WiFi", 6);
        </script>
        '''
        stations = TLWR740NPoller.parse_wlan_stations(sample_html)
        self.assertEqual(len(stations), 2)
        self.assertEqual(stations[0]["mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(stations[0]["rx_packets"], 120)
        info = TLWR740NPoller.parse_status_info(sample_html)
        self.assertEqual(info["ssid"], "CollegeLab_WiFi")

    def test_firewall_enforcer_dry_run(self):
        fw = WindowsFirewallEnforcer(dry_run=True)
        fw.sync_quotas({"192.168.137.10", "192.168.137.11"})
        self.assertEqual(fw.get_enforced_ips(), ["192.168.137.10", "192.168.137.11"])
        fw.sync_quotas({"192.168.137.11"})
        self.assertEqual(fw.get_enforced_ips(), ["192.168.137.11"])
        fw.cleanup_all()
        self.assertEqual(fw.get_enforced_ips(), [])

    def test_api_config_router_status_and_core_workflows(self):
        r = self.client.get("/api/config")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json()["mode"], "router_gateway")

        r = self.client.get("/api/router/status")
        self.assertEqual(r.status_code, 200)
        self.assertIn("dns_sinkhole", r.json())
        self.assertIn("firewall", r.json())

        # Blocklist
        r = self.client.post("/api/policy/block", json={"domain": "roblox.com", "reason": "Lab policy"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(any(x["domain"] == "roblox.com" for x in self.client.get("/api/policy/rules").json()))

        # Session + Student + Attendance
        s_resp = self.client.post("/api/attendance/sessions", json={"session_type": "Lab", "title": "CN Lab", "year": "TE", "division": "A", "batch": "TE-B1"})
        self.assertEqual(s_resp.status_code, 200)
        sid = s_resp.json()["session"]["id"]

        stu_resp = self.client.post("/api/students", json={
            "mac_address": "aa:bb:cc:11:22:33",
            "prn": "PRN2026001",
            "name": "Aarav Patil",
            "department": "Computer Engineering",
            "year": "TE",
            "division": "A",
            "batch": "TE-B1",
        })
        self.assertEqual(stu_resp.status_code, 200)
        att = self.client.get(f"/api/attendance?session_id={sid}").json()
        self.assertEqual(len(att), 1)
        self.assertEqual(att[0]["prn"], "PRN2026001")

        # End session
        self.assertEqual(self.client.post(f"/api/attendance/sessions/{sid}/end").status_code, 200)

        # AI Analysis & Export
        ai = self.client.get("/api/ai/analysis")
        self.assertEqual(ai.status_code, 200)
        self.assertIn("insights", ai.json())
        exp = self.client.get("/api/export/ai-dataset?type=attendance_ml&format=json")
        self.assertEqual(exp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
