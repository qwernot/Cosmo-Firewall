"""
server.py - HTTP API & Web Dashboard Server for Cosmo Firewall.
"""

import os
import re
import sys
import json
import time
from urllib.parse import urlparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

import database
import engine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

PORT = int(os.environ.get("PORT", "8090"))
HOST = os.environ.get("HOST", "0.0.0.0")

FW_ENGINE = engine.FirewallEngine(panel_port=PORT)


def get_client_ip(handler: SimpleHTTPRequestHandler) -> str:
    xff = handler.headers.get("X-Forwarded-For", "")
    if xff:
        first = xff.split(",")[0].strip()
        if first:
            return first
    xri = handler.headers.get("X-Real-IP", "").strip()
    if xri:
        return xri
    return handler.client_address[0] if handler.client_address else "127.0.0.1"


class FirewallHandler(SimpleHTTPRequestHandler):
    timeout = 15

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=STATIC_DIR, **kwargs)

    def setup(self):
        super().setup()
        try:
            self.request.settimeout(15)
        except Exception:
            pass

    def log_message(self, format, *args):
        sys.stdout.write("%s - - [%s] %s\n" % (self.address_string(), self.log_date_time_string(), format % args))
        sys.stdout.flush()

    def send_json(self, data: Dict[str, Any], status_code: int = 200):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > 2 * 1024 * 1024:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    def get_auth_token(self) -> str:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def require_auth(self) -> Optional[Dict[str, Any]]:
        user = database.get_session_user(self.get_auth_token())
        if not user:
            self.send_json({"success": False, "message": "未登录或会话已过期"}, 401)
            return None
        return user

    def _guard_request(self, path: str) -> bool:
        cip = get_client_ip(self)
        if FW_ENGINE.inspect_panel_request(cip, getattr(self, "command", "GET"), path):
            self.send_json({"success": False, "message": "Forbidden"}, 403)
            return False
        if database.is_ip_blacklisted(cip):
            self.send_json({"success": False, "message": "IP 已被防火墙拦截"}, 403)
            return False
        return True

    def do_CONNECT(self):
        cip = get_client_ip(self)
        FW_ENGINE.record_probe(cip, "防火墙面板恶意 CONNECT 代理扫描", weight=3, tag="面板代理")
        self.send_error(403, "Forbidden")

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._guard_request(path):
            return

        if path == "/api/v1/health":
            self.send_json({"success": True, "service": "Cosmo Firewall", "ts": int(time.time())})
            return

        if path == "/api/v1/auth/me":
            user = self.require_auth()
            if not user:
                return
            self.send_json({"success": True, "user": user})
            return

        if path == "/api/v1/dashboard":
            if not self.require_auth():
                return
            bl = database.list_blacklist(include_expired=False)
            wl = database.list_whitelist()
            traps = database.list_trap_ports()
            status_map = FW_ENGINE.get_trap_status_map()
            listening_traps = sum(1 for t in traps if status_map.get(t["port"]) == "listening")
            total_trap_hits = sum(int(t.get("hit_count") or 0) for t in traps)
            auto_bans = sum(1 for x in bl if x["source"] in ("auto_scan", "brute_force"))
            manual_bans = sum(1 for x in bl if x["source"] == "manual")
            kernel = database.get_kernel_firewall_stats()
            settings = database.get_all_settings()
            self.send_json({
                "success": True,
                "stats": {
                    "total_bans": len(bl),
                    "auto_bans": auto_bans,
                    "manual_bans": manual_bans,
                    "whitelist_count": len(wl),
                    "trap_total": len(traps),
                    "trap_listening": listening_traps,
                    "trap_hits": total_trap_hits,
                    "defense_enabled": settings.get("defense_enabled", "1") == "1",
                    "kernel": kernel,
                },
            })
            return

        if path == "/api/v1/blacklist":
            if not self.require_auth():
                return
            self.send_json({"success": True, "blacklist": database.list_blacklist(include_expired=False)})
            return

        if path == "/api/v1/whitelist":
            if not self.require_auth():
                return
            self.send_json({"success": True, "whitelist": database.list_whitelist()})
            return

        if path == "/api/v1/trap_ports":
            if not self.require_auth():
                return
            traps = database.list_trap_ports()
            status_map = FW_ENGINE.get_trap_status_map()
            for t in traps:
                t["runtime_status"] = status_map.get(t["port"], "disabled" if not t["enabled"] else "pending")
            self.send_json({"success": True, "trap_ports": traps})
            return

        if path == "/api/v1/settings":
            if not self.require_auth():
                return
            self.send_json({"success": True, "settings": database.get_all_settings()})
            return

        if path == "/api/v1/events":
            if not self.require_auth():
                return
            self.send_json({"success": True, "events": database.list_events(limit=100)})
            return

        if path in ("", "/", "/login", "/dashboard"):
            self.path = "/index.html"
        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if not self._guard_request(path):
            return

        body = self.read_json_body()
        cip = get_client_ip(self)

        # Login
        if path == "/api/v1/auth/login":
            username = str(body.get("username") or "").strip()
            password = str(body.get("password") or "")
            user = database.authenticate_user(username, password)
            if not user:
                FW_ENGINE.record_probe(cip, "Cosmo Firewall 面板登录密码错误", weight=1, tag="面板登录", source="brute_force")
                self.send_json({"success": False, "message": "用户名或密码错误"}, 401)
                return
            FW_ENGINE.mark_trusted_ip(cip, ttl=14400)
            token = database.create_session(user["id"])
            self.send_json({"success": True, "token": token, "user": user})
            return

        user = self.require_auth()
        if not user:
            return

        if path == "/api/v1/auth/logout":
            database.delete_session(self.get_auth_token())
            self.send_json({"success": True, "message": "已退出登录"})
            return

        if path == "/api/v1/auth/password":
            ok, msg = database.change_password(
                user["id"],
                str(body.get("old_password") or ""),
                str(body.get("new_password") or ""),
            )
            self.send_json({"success": ok, "message": msg}, 200 if ok else 400)
            return

        # Blacklist endpoints
        if path == "/api/v1/blacklist":
            raw_ips = str(body.get("ip") or "").strip()
            reason = str(body.get("reason") or "管理员手动封禁").strip()
            duration = int(body.get("expire_seconds") or 0)
            tokens = [t.strip() for t in re.split(r"[\s,;]+", raw_ips) if t.strip()]
            if not tokens:
                self.send_json({"success": False, "message": "请输入至少一个 IP 地址"}, 400)
                return
            added, errors = [], []
            for tk in tokens:
                ok, msg, item = database.add_blacklist_ip(tk, reason=reason, source="manual", expire_seconds=duration)
                if ok and item:
                    added.append(item)
                else:
                    errors.append(msg)
            if not added:
                self.send_json({"success": False, "message": "；".join(errors)}, 400)
                return
            msg = f"成功封禁 {len(added)} 个 IP" + (f"（跳过 {len(errors)} 个：{errors[0]}）" if errors else "")
            self.send_json({"success": True, "message": msg, "added": added})
            return

        if path == "/api/v1/blacklist/delete":
            target = body.get("id") or body.get("ip")
            ok, msg = database.remove_blacklist_ip(target)
            if ok and body.get("ip"):
                clean = database.normalize_ip(str(body.get("ip")))
                if clean:
                    FW_ENGINE.recently_banned.pop(clean, None)
            self.send_json({"success": ok, "message": msg}, 200 if ok else 400)
            return

        if path == "/api/v1/blacklist/clear":
            src = body.get("source")
            ok, msg, cnt = database.clear_blacklist(source=src)
            FW_ENGINE.recently_banned.clear()
            self.send_json({"success": ok, "message": msg, "count": cnt})
            return

        if path == "/api/v1/blacklist/sync":
            res = database.sync_all_firewall_rules()
            FW_ENGINE.sync_trap_sockets()
            self.send_json({"success": True, "message": "已强制同步规则至内核防火墙与哨兵引擎", "detail": res})
            return

        # Whitelist endpoints
        if path == "/api/v1/whitelist":
            raw_entries = str(body.get("entry") or "").strip()
            note = str(body.get("note") or "管理员白名单").strip()
            tokens = [t.strip() for t in re.split(r"[\s,;]+", raw_entries) if t.strip()]
            if not tokens:
                self.send_json({"success": False, "message": "请输入至少一个 IP 或 CIDR 网段"}, 400)
                return
            added, errors = [], []
            for tk in tokens:
                ok, msg, item = database.add_whitelist_entry(tk, note=note)
                if ok and item:
                    added.append(item)
                    if "/" not in item["entry"]:
                        FW_ENGINE.mark_trusted_ip(item["entry"], ttl=86400)
                else:
                    errors.append(msg)
            if not added:
                self.send_json({"success": False, "message": "；".join(errors)}, 400)
                return
            msg = f"已加入白名单 {len(added)} 项" + (f"（跳过 {len(errors)} 项）" if errors else "")
            self.send_json({"success": True, "message": msg, "added": added})
            return

        if path == "/api/v1/whitelist/delete":
            target = body.get("id") or body.get("entry")
            ok, msg = database.remove_whitelist_entry(target)
            self.send_json({"success": ok, "message": msg}, 200 if ok else 400)
            return

        # Trap Ports endpoints
        if path == "/api/v1/trap_ports":
            raw_ports = str(body.get("ports") or body.get("port") or "").strip()
            note = str(body.get("note") or "").strip()
            tokens = [t.strip() for t in re.split(r"[\s,;]+", raw_ports) if t.strip()]
            if not tokens:
                self.send_json({"success": False, "message": "请输入至少一个端口号"}, 400)
                return
            added, errors = [], []
            for tk in tokens:
                ok, msg, item = database.add_trap_port(tk, note=note)
                if ok and item:
                    added.append(item)
                else:
                    errors.append(msg)
            FW_ENGINE.sync_trap_sockets()
            if not added:
                self.send_json({"success": False, "message": "；".join(errors)}, 400)
                return
            msg = f"已添加 {len(added)} 个诱捕端口" + (f"（跳过 {len(errors)} 个：{errors[0]}）" if errors else "")
            self.send_json({"success": True, "message": msg, "added": added})
            return

        if path == "/api/v1/trap_ports/toggle":
            pid = int(body.get("id") or 0)
            enabled = bool(body.get("enabled", True))
            ok, msg = database.toggle_trap_port(pid, enabled)
            if ok:
                FW_ENGINE.sync_trap_sockets()
            self.send_json({"success": ok, "message": msg}, 200 if ok else 400)
            return

        if path == "/api/v1/trap_ports/delete":
            pid = int(body.get("id") or 0)
            ok, msg, port_num = database.delete_trap_port(pid)
            if ok and port_num > 0:
                FW_ENGINE.release_trap_port(port_num)
                FW_ENGINE.sync_trap_sockets()
            self.send_json({"success": ok, "message": msg}, 200 if ok else 400)
            return

        # Settings endpoint
        if path == "/api/v1/settings":
            allowed_keys = set(database.DEFAULT_SETTINGS.keys())
            for k, v in body.items():
                if k in allowed_keys:
                    database.set_setting(k, str(v))
            FW_ENGINE.sync_trap_sockets()
            self.send_json({"success": True, "message": "防护策略已保存并即时生效", "settings": database.get_all_settings()})
            return

        self.send_json({"success": False, "message": "未知接口路径"}, 404)


def run_server(host: str = HOST, port: int = PORT):
    database.init_db()
    database.sync_all_firewall_rules()
    FW_ENGINE.panel_port = port
    FW_ENGINE.start()
    ThreadingHTTPServer.allow_reuse_address = True
    httpd = ThreadingHTTPServer((host, port), FirewallHandler)
    print(f"🛡️ Cosmo Firewall 已启动: http://{host}:{port}", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n🛑 Cosmo Firewall 正在停止...", flush=True)
        FW_ENGINE.stop()
        httpd.server_close()


if __name__ == "__main__":
    run_server()
