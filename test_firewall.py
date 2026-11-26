"""
test_firewall.py - Automated unit & HTTP API test suite for Cosmo Firewall.
"""

import os
import json
import time
import tempfile
import threading
import unittest
import urllib.request
import urllib.error

_TMP_DIR = tempfile.TemporaryDirectory()
os.environ["COSMO_FW_DB"] = os.path.join(_TMP_DIR.name, "test_fw.db")

import database
import engine
import server


class TestCosmoFirewall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        database.init_db()
        cls.port = 18991
        server.FW_ENGINE = engine.FirewallEngine(panel_port=cls.port)
        server.ThreadingHTTPServer.allow_reuse_address = True
        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", cls.port), server.FirewallHandler)
        cls.th = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.th.start()
        cls.base = f"http://127.0.0.1:{cls.port}"

        st, data = cls._req("/api/v1/auth/login", "POST", {"username": "dark", "password": "Aa666333"})
        assert st == 200 and data["success"], f"login failed: {data}"
        cls.token = data["token"]

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        server.FW_ENGINE.stop()
        _TMP_DIR.cleanup()

    @classmethod
    def _req(cls, path, method="GET", body=None, token=None):
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        raw = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(f"{cls.base}{path}", data=raw, headers=headers, method=method)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def test_01_dashboard_and_auth(self):
        st, d = self._req("/api/v1/dashboard", token=self.token)
        self.assertEqual(st, 200)
        self.assertTrue(d["success"])
        self.assertIn("trap_total", d["stats"])

        st2, _ = self._req("/api/v1/dashboard")
        self.assertEqual(st2, 401)

    def test_02_blacklist_and_whitelist_interaction(self):
        # Manual ban
        st, d = self._req("/api/v1/blacklist", "POST", {
            "ip": "198.51.100.10",
            "reason": "测试手动封禁",
            "expire_seconds": 3600,
        }, token=self.token)
        self.assertEqual(st, 200)
        self.assertTrue(database.is_ip_blacklisted("198.51.100.10"))

        # Adding IP to whitelist immediately unbans it and prevents re-ban
        st2, d2 = self._req("/api/v1/whitelist", "POST", {
            "entry": "198.51.100.10, 203.0.113.0/24",
            "note": "公司办公出口",
        }, token=self.token)
        self.assertEqual(st2, 200)
        self.assertFalse(database.is_ip_blacklisted("198.51.100.10"))
        self.assertTrue(database.is_ip_whitelisted("203.0.113.88"))

        ok_ban, _, _ = database.add_blacklist_ip("203.0.113.88", reason="should fail")
        self.assertFalse(ok_ban)

        # Clean whitelist
        _, wl = self._req("/api/v1/whitelist", token=self.token)
        for item in wl["whitelist"]:
            self._req("/api/v1/whitelist/delete", "POST", {"id": item["id"]}, token=self.token)

    def test_03_trap_ports_crud_and_auto_ban(self):
        st, d = self._req("/api/v1/trap_ports", "POST", {"ports": "18888, 18889", "note": "测试哨兵"}, token=self.token)
        self.assertEqual(st, 200)
        self.assertEqual(len(d["added"]), 2)

        eng = server.FW_ENGINE
        now = time.time()
        eng.record_trap_hit("198.51.100.22", 18888, now=now)
        self.assertFalse(database.is_ip_blacklisted("198.51.100.22"))
        eng.record_trap_hit("198.51.100.22", 18889, now=now + 0.5)
        self.assertTrue(database.is_ip_blacklisted("198.51.100.22"))

        # Toggle & delete
        pid = d["added"][0]["id"]
        st_t, _ = self._req("/api/v1/trap_ports/toggle", "POST", {"id": pid, "enabled": False}, token=self.token)
        self.assertEqual(st_t, 200)
        st_d, _ = self._req("/api/v1/trap_ports/delete", "POST", {"id": pid}, token=self.token)
        self.assertEqual(st_d, 200)

    def test_04_full_port_conntrack_and_npm_log_detection(self):
        eng = server.FW_ENGINE
        now = time.time()

        # Benign 80 -> 443 HTTP redirect not banned
        eng.process_conntrack_lines([
            "tcp      6 10 TIME_WAIT src=198.51.100.30 dst=172.18.0.2 sport=41001 dport=80 src=172.18.0.2 dst=198.51.100.30 sport=80 dport=41001",
            "tcp      6 10 ESTABLISHED src=198.51.100.30 dst=172.18.0.2 sport=41002 dport=443 src=172.18.0.2 dst=198.51.100.30 sport=443 dport=41002",
        ], now=now)
        self.assertFalse(database.is_ip_blacklisted("198.51.100.30"))

        # Full-port sweep (23, 3306, 55555) auto-banned
        eng.process_conntrack_lines([
            "tcp      6 5 TIME_WAIT src=198.51.100.31 dst=172.18.0.2 sport=42001 dport=23 src=172.18.0.2 dst=198.51.100.31 sport=23 dport=42001",
            "tcp      6 5 TIME_WAIT src=198.51.100.31 dst=172.18.0.2 sport=42002 dport=3306 src=172.18.0.2 dst=198.51.100.31 sport=3306 dport=42002",
            "tcp      6 5 TIME_WAIT src=198.51.100.31 dst=172.18.0.2 sport=42003 dport=55555 src=172.18.0.2 dst=198.51.100.31 sport=55555 dport=42003",
        ], now=now + 1)
        self.assertTrue(database.is_ip_blacklisted("198.51.100.31"))

        # Docker NPM exploit path scan auto-banned
        npm_lines = [
            '[26/Nov/2026:14:09:53 +1000] 404 - GET http swicv.com "/wp-admin/install.php?step=1" [Client 198.51.100.32] [Length 122] [Gzip 1.35] "Mozilla/5.0" "-"',
            '[26/Nov/2026:14:09:54 +1000] 404 - GET http swicv.com "/.env" [Client 198.51.100.32] [Length 122] [Gzip 1.35] "Mozilla/5.0" "-"',
            '[26/Nov/2026:14:09:55 +1000] 400 - WKJP http swicv.com "/" [Client 198.51.100.32] [Length 252] [Gzip -] "Mozilla/5.0" "-"',
        ]
        for ln in npm_lines:
            eng.process_web_log_line(ln, now=now + 2)
        self.assertTrue(database.is_ip_blacklisted("198.51.100.32"))

        # Dual-stack IPv4-mapped socket parsing
        self.assertEqual(database.normalize_ip("[::ffff:36.57.16.123]:9593"), "36.57.16.123")


if __name__ == "__main__":
    unittest.main()
