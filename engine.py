"""
engine.py - Standalone Full-Port (1-65535) Multi-Layer Anti-Scan & Anti-Brute-Force Engine for Cosmo Firewall.

Layers:
1. User-Configurable Sentinel Honeypot Trap Ports (1-65535, auto-skipping occupied ports).
2. Full-Port (1-65535) Kernel Conntrack Sweep & Brute-Force Detector.
3. Host SSHD Brute-Force & Preauth Scanner Detector.
4. Standard Nginx & Docker NPM (Nginx Proxy Manager) Exploit/Proxy/UA Scanner Detector.
5. Whitelist + Trusted Live Socket (ss) Guard to prevent false positives on active SSH/FRP/NPS sessions.
"""

import os
import re
import time
import socket
import shutil
import selectors
import threading
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

import database

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

RE_CONNTRACK_TCP = re.compile(
    r"^tcp\s+\d+\s+\d+\s+([A-Z_]+)\s+src=([^\s]+)\s+dst=([^\s]+)\s+sport=(\d+)\s+dport=(\d+)"
)
RE_WEB_EXPLOIT_PATH = re.compile(
    r"(?i)(?:"
    r"/\.(?:env|git|svn|hg|aws|ssh|DS_Store|bash_history)|"
    r"/(?:wp-login\.php|wp-admin|xmlrpc\.php|wp-includes)|"
    r"/(?:phpmyadmin|pma|myadmin|adminer|dbadmin)|"
    r"/(?:autodiscover/autodiscover|ecp/Current|owa/auth)|"
    r"/(?:HNAP1|evox/about|boaform|GponForm|sdk\b|_ignition)|"
    r"/(?:actuator|cgi-bin|vendor/phpunit|thinkphp|invokefunction|jmx-console|solr/)"
    r")"
)
RE_NGINX_LINE = re.compile(
    r'^([0-9a-fA-F\.:]+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"([^"]*)"\s+(\d{3})\s+\S+\s+"[^"]*"\s+"([^"]*)"'
)
# Docker Nginx Proxy Manager log format:
# [26/Nov/2026:14:09:53 +1000] 404 - GET http swicv.com "/wp-admin/install.php?step=1" [Client 104.23.223.13] ... "UA" "-"
RE_NPM_LINE = re.compile(
    r'^\[[^\]]+\]\s+(?:-|\d{3})\s+(?:\d{3}|-)\s+([A-Z]+)\s+\S+\s+\S+\s+"([^"]*)"\s+\[Client\s+([0-9a-fA-F\.:]+)\].*?"([^"]*)"\s+"[^"]*"$'
)
RE_SCANNER_UA = re.compile(
    r"(?i)(?:zgrab|masscan|censysinspect|nmap|sqlmap|nuclei|nikto|dirbuster|gobuster|acunetix|nessus|xray)"
)
RE_SSHD_ACCEPTED = re.compile(r"Accepted\s+(?:password|publickey|keyboard-interactive\S*)\s+for\s+\S+\s+from\s+([0-9a-fA-F\.:]+)")
RE_SSHD_FAILED = re.compile(r"Failed\s+(?:password|none)\s+for\s+.*from\s+([0-9a-fA-F\.:]+)")
RE_SSHD_INVALID_USER = re.compile(r"Invalid user\s+.*from\s+([0-9a-fA-F\.:]+)")
RE_SSHD_PREAUTH = re.compile(
    r"Connection\s+(?:closed|reset)\s+by\s+(?:authenticating user\s+\S+\s+|invalid user\s+\S*\s*)?([0-9a-fA-F\.:]+)\s+port\s+\d+\s+\[preauth\]"
)

SENSITIVE_PORTS = {21, 22, 23, 445, 1433, 1521, 3306, 3389, 5432, 5900, 5901, 6379, 8291, 27017}


class FirewallEngine:
    def __init__(self, panel_port: int = 8090):
        self.panel_port = panel_port
        self.lock = threading.RLock()
        self._stop_event = threading.Event()

        self.trusted_ips: Dict[str, float] = {}
        self.recently_banned: Dict[str, float] = {}
        self.probe_events: Dict[str, List[Tuple[float, int, str, str]]] = {}
        self.trap_hits: Dict[str, Dict[int, float]] = {}
        self.port_conns: Dict[str, Dict[int, List[float]]] = {}
        self.port_groups: Dict[str, Dict[int, int]] = {}

        self.seen_conntrack: Dict[Tuple[str, int, int], float] = {}
        self._conntrack_primed: bool = False

        # Sentinel trap socket management
        self.trap_sockets: Dict[int, socket.socket] = {}
        # port -> "listening" | "occupied" | "disabled" | "permission_denied"
        self.trap_status: Dict[int, str] = {}
        self.trap_selector: Optional[selectors.BaseSelector] = None

    def get_policy(self) -> Dict[str, Any]:
        s = database.get_all_settings()
        trusted_ports: Set[int] = set()
        for tok in str(s.get("trusted_service_ports", "22,7000,7001,8024")).split(","):
            tok = tok.strip()
            if tok.isdigit():
                trusted_ports.add(int(tok))
        return {
            "enabled": s.get("defense_enabled", "1") == "1",
            "threshold": max(2, int(s.get("threshold", "5") or "5")),
            "ban_duration": max(60, int(s.get("ban_duration", "86400") or "86400")),
            "window_sec": max(30, int(s.get("window_sec", "600") or "600")),
            "full_port_conntrack": s.get("full_port_conntrack", "1") == "1",
            "sshd_monitor": s.get("sshd_monitor", "1") == "1",
            "web_monitor": s.get("web_monitor", "1") == "1",
            "trusted_service_ports": trusted_ports,
            "auto_trust_ttl": max(300, int(s.get("auto_trust_ttl", "7200") or "7200")),
        }

    def mark_trusted_ip(self, raw_ip: str, ttl: Optional[int] = None):
        clean = database.normalize_ip(raw_ip)
        if not clean:
            return
        if ttl is None:
            ttl = self.get_policy()["auto_trust_ttl"]
        now = time.time()
        with self.lock:
            self.trusted_ips[clean] = now + ttl
            self.probe_events.pop(clean, None)
            self.trap_hits.pop(clean, None)
            self.port_conns.pop(clean, None)
            self.port_groups.pop(clean, None)

    def is_exempt(self, clean_ip: str, now: Optional[float] = None) -> bool:
        if not clean_ip:
            return True
        if database.is_auto_ban_exempt_ip(clean_ip):
            return True
        if now is None:
            now = time.time()
        with self.lock:
            exp = self.trusted_ips.get(clean_ip)
            if exp is not None:
                if exp > now:
                    return True
                self.trusted_ips.pop(clean_ip, None)
        return False

    def _has_live_trusted_socket(self, clean_ip: str) -> bool:
        """Last-millisecond kernel check: never auto-ban an IP with active SSH/FRP/NPS ESTAB session."""
        pol = self.get_policy()
        ports = sorted(pol["trusted_service_ports"])
        if not ports:
            return False
        ss_bin = database._find_bin("ss")
        if not ss_bin:
            return False
        try:
            expr = "( " + " or ".join(f"sport = :{p}" for p in ports) + " )"
            res = subprocess.run(
                [ss_bin, "-tnH", "state", "established", expr],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=2,
            )
            if res.returncode == 0 and res.stdout:
                for ln in res.stdout.splitlines():
                    parts = ln.split()
                    if len(parts) >= 4:
                        peer = database.normalize_ip(parts[3])
                        if peer == clean_ip:
                            self.mark_trusted_ip(clean_ip)
                            return True
        except Exception:
            pass
        return False

    def _trigger_ban(self, clean_ip: str, reason: str, ban_duration: int, source: str = "auto_scan", now: Optional[float] = None) -> bool:
        if now is None:
            now = time.time()
        if database.is_ip_whitelisted(clean_ip):
            return False
        if self._has_live_trusted_socket(clean_ip):
            return False
        with self.lock:
            if now - self.recently_banned.get(clean_ip, 0.0) < 120:
                return False
            self.recently_banned[clean_ip] = now
            self.probe_events.pop(clean_ip, None)
            self.trap_hits.pop(clean_ip, None)
            self.port_conns.pop(clean_ip, None)
            self.port_groups.pop(clean_ip, None)

        if database.is_ip_blacklisted(clean_ip):
            database.apply_firewall_drop(clean_ip)
            return False

        ok, _, _ = database.add_blacklist_ip(clean_ip, reason=reason, source=source, expire_seconds=ban_duration)
        if ok:
            print(f"🛡️ [Cosmo Firewall] 自动封禁 {clean_ip} | {reason} | 时长 {ban_duration}s", flush=True)
        return ok

    # ----------------- Detection Core -----------------

    def record_probe(self, raw_ip: str, reason: str, weight: int = 1, tag: str = "probe", source: str = "auto_scan", now: Optional[float] = None) -> bool:
        pol = self.get_policy()
        if not pol["enabled"]:
            return False
        if now is None:
            now = time.time()
        clean_ip = database.normalize_ip(raw_ip)
        if not clean_ip or self.is_exempt(clean_ip, now):
            return False

        threshold = pol["threshold"]
        window_sec = pol["window_sec"]
        ban_duration = pol["ban_duration"]

        with self.lock:
            if now - self.recently_banned.get(clean_ip, 0.0) < 120:
                return False
            evs = self.probe_events.setdefault(clean_ip, [])
            evs.append((now, max(1, weight), tag, reason))
            evs[:] = [e for e in evs if now - e[0] <= window_sec]

            total_score = sum(e[1] for e in evs)
            if total_score >= threshold:
                return self._trigger_ban(
                    clean_ip,
                    f"{reason} (累计异常评分 {total_score}/{threshold})",
                    ban_duration,
                    source=source,
                    now=now,
                )
        return False

    def record_trap_hit(self, raw_ip: str, trap_port: int, now: Optional[float] = None) -> bool:
        pol = self.get_policy()
        database.increment_trap_port_hit(trap_port)
        clean_ip = database.normalize_ip(raw_ip)
        if clean_ip:
            database.record_event("trap_hit", ip=clean_ip, port=trap_port, detail=f"触碰哨兵诱捕端口 {trap_port}")
        if not pol["enabled"]:
            return False
        if now is None:
            now = time.time()
        if not clean_ip or self.is_exempt(clean_ip, now):
            return False

        window_sec = pol["window_sec"]
        ban_duration = pol["ban_duration"]
        threshold = pol["threshold"]

        with self.lock:
            if now - self.recently_banned.get(clean_ip, 0.0) < 120:
                return False
            pm = self.trap_hits.setdefault(clean_ip, {})
            pm[trap_port] = now
            for p in [k for k, ts in pm.items() if now - ts > window_sec]:
                pm.pop(p, None)

            if len(pm) >= 2:
                ports_str = ",".join(str(p) for p in sorted(pm.keys())[:6])
                return self._trigger_ban(
                    clean_ip,
                    f"全端口扫描哨兵诱捕拦截 (连续探测未分配端口: {ports_str})",
                    ban_duration,
                    now=now,
                )

        trap_weight = max(2, (threshold + 1) // 2)
        return self.record_probe(
            clean_ip,
            f"探测未分配哨兵诱捕端口 ({trap_port})",
            weight=trap_weight,
            tag=f"诱捕:{trap_port}",
            now=now,
        )

    def record_port_connection(self, raw_ip: str, dport: int, group_id: int = 0, now: Optional[float] = None) -> bool:
        pol = self.get_policy()
        if not pol["enabled"]:
            return False
        if now is None:
            now = time.time()
        clean_ip = database.normalize_ip(raw_ip)
        if not clean_ip or self.is_exempt(clean_ip, now):
            return False

        window_sec = pol["window_sec"]
        threshold = pol["threshold"]
        ban_duration = pol["ban_duration"]

        with self.lock:
            if now - self.recently_banned.get(clean_ip, 0.0) < 120:
                return False

            ip_ports = self.port_conns.setdefault(clean_ip, {})
            hist = ip_ports.setdefault(dport, [])
            hist.append(now)
            hist[:] = [t for t in hist if now - t <= window_sec]

            gmap = self.port_groups.setdefault(clean_ip, {})
            if group_id > 0:
                gmap[dport] = group_id

            for p in [k for k, h in ip_ports.items() if not h]:
                ip_ports.pop(p, None)
                gmap.pop(p, None)

            active_ports = sorted(ip_ports.keys())
            distinct_groups = {gmap[p] for p in active_ports if gmap.get(p, 0) > 0}
            unassigned = [p for p in active_ports if gmap.get(p, 0) == 0]
            probe_pts = sum(e[1] for e in self.probe_events.get(clean_ip, []) if now - e[0] <= window_sec)

            cross_limit = max(3, min(threshold - 1, 4))
            single_group_limit = max(6, threshold + 1)

            if (
                (len(active_ports) >= 3 and len(distinct_groups) >= 3)
                or (len(active_ports) >= cross_limit and len(distinct_groups) >= 2)
                or len(unassigned) >= 3
                or len(active_ports) >= single_group_limit
                or (len(active_ports) >= 2 and probe_pts >= 1)
            ):
                ports_preview = ",".join(str(p) for p in active_ports[:6])
                return self._trigger_ban(
                    clean_ip,
                    f"全端口横向扫描拦截 (短时间探测端口: {ports_preview})",
                    ban_duration,
                    now=now,
                )

            # Single-port sensitive brute-force or general flood
            if dport in SENSITIVE_PORTS:
                recent_180s = [t for t in hist if now - t <= min(window_sec, 180)]
                sens_limit = max(10, threshold * 2)
                if len(recent_180s) >= sens_limit:
                    return self._trigger_ban(
                        clean_ip,
                        f"敏感端口高频暴力破解拦截 (端口 {dport} 触发 {len(recent_180s)} 次爆破连接)",
                        ban_duration,
                        source="brute_force",
                        now=now,
                    )
            else:
                recent_60s = [t for t in hist if now - t <= 60]
                if len(recent_60s) >= 180:
                    buckets = {int(t // 5) for t in recent_60s}
                    if len(buckets) >= 6:
                        return self._trigger_ban(
                            clean_ip,
                            f"端口异常高频洪泛攻击拦截 (端口 {dport} 1分钟内触发 {len(recent_60s)} 次连接)",
                            ban_duration,
                            now=now,
                        )
        return False

    # ----------------- Log & Conntrack Parsers -----------------

    def process_conntrack_lines(self, lines: List[str], now: Optional[float] = None, prime_only: bool = False) -> int:
        if now is None:
            now = time.time()
        pol = self.get_policy()
        if not pol["enabled"] or not pol["full_port_conntrack"]:
            return 0
        with self.lock:
            trap_ports = set(self.trap_sockets.keys())
        trusted_svc = pol["trusted_service_ports"]

        bans = 0
        for raw_ln in lines:
            m = RE_CONNTRACK_TCP.match(raw_ln.strip())
            if not m:
                continue
            state, src_ip, dst_ip, sport_s, dport_s = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
            if state == "SYN_SENT" or src_ip == dst_ip:
                continue
            sport = int(sport_s)
            dport = int(dport_s)
            if dport < 1 or dport > 65535 or dport in trap_ports or dport == 22:
                continue

            clean_ip = database.normalize_ip(src_ip)
            if not clean_ip or self.is_exempt(clean_ip, now):
                continue

            fk = (clean_ip, sport, dport)
            with self.lock:
                if fk in self.seen_conntrack:
                    self.seen_conntrack[fk] = now
                    continue
                self.seen_conntrack[fk] = now

            if prime_only:
                continue

            if dport in trusted_svc:
                # Single-tag suspicion only on failed handshake so expired background clients aren't locked out
                if state in ("CLOSE", "TIME_WAIT", "CLOSE_WAIT"):
                    with self.lock:
                        already = any((now - e[0] <= pol["window_sec"] and e[2] == f"SVC:{dport}") for e in self.probe_events.get(clean_ip, []))
                    if not already:
                        if self.record_probe(clean_ip, f"核心服务端口 ({dport}) 异常握手探测", weight=1, tag=f"SVC:{dport}", now=now):
                            bans += 1
                continue

            if dport in (80, 443):
                gid = 200001
            elif dport in (self.panel_port, 8080, 8081, 8088, 8443):
                gid = 200002
            else:
                gid = 0

            if self.record_port_connection(clean_ip, dport, group_id=gid, now=now):
                bans += 1
        return bans

    def process_sshd_line(self, raw_line: str, now: Optional[float] = None) -> bool:
        line = ANSI_RE.sub("", raw_line).strip()
        if not line:
            return False
        m_acc = RE_SSHD_ACCEPTED.search(line)
        if m_acc:
            self.mark_trusted_ip(m_acc.group(1), ttl=14400)
            return False
        m_inv = RE_SSHD_INVALID_USER.search(line)
        if m_inv:
            return self.record_probe(m_inv.group(1), "SSH 非法用户名枚举爆破", weight=2, tag="SSH:22", source="brute_force", now=now)
        m_fail = RE_SSHD_FAILED.search(line)
        if m_fail:
            return self.record_probe(m_fail.group(1), "SSH 登录密码暴力破解", weight=2, tag="SSH:22", source="brute_force", now=now)
        m_pre = RE_SSHD_PREAUTH.search(line)
        if m_pre:
            return self.record_probe(m_pre.group(1), "SSH 端口扫描探测断开", weight=1, tag="SSH:22", now=now)
        return False

    def process_web_log_line(self, raw_line: str, now: Optional[float] = None) -> bool:
        line = raw_line.strip()
        if not line:
            return False
        # 1. Standard Nginx format
        m = RE_NGINX_LINE.match(line)
        if m:
            ip, req_line, status_s, ua = m.group(1), m.group(2), m.group(3), m.group(4)
            status = int(status_s)
            if req_line.startswith("CONNECT ") or "\\x04\\x01" in req_line or "\\x05\\x01" in req_line or "\\x16\\x03" in req_line:
                return self.record_probe(ip, "Web 端口恶意代理或畸形协议扫描", weight=2, tag="Web协议", now=now)
            if RE_SCANNER_UA.search(ua):
                return self.record_probe(ip, f"自动化漏洞扫描工具探测 ({ua[:24]})", weight=2, tag="扫描器UA", now=now)
            if status >= 400 and RE_WEB_EXPLOIT_PATH.search(req_line):
                parts = req_line.split()
                uri = parts[1][:30] if len(parts) >= 2 else req_line[:30]
                return self.record_probe(ip, f"Web 高危漏洞路径扫描 ({uri})", weight=2, tag="Web漏洞", now=now)
            return False

        # 2. Docker Nginx Proxy Manager (NPM) format
        mn = RE_NPM_LINE.match(line)
        if mn:
            method, uri, ip, ua = mn.group(1), mn.group(2), mn.group(3), mn.group(4)
            if method == "CONNECT" or method not in ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"):
                return self.record_probe(ip, f"NPM 反代恶意畸形请求扫描 ({method})", weight=2, tag="NPM协议", now=now)
            if RE_SCANNER_UA.search(ua):
                return self.record_probe(ip, f"NPM 反代扫描工具探测 ({ua[:24]})", weight=2, tag="NPM扫描器", now=now)
            if RE_WEB_EXPLOIT_PATH.search(uri):
                return self.record_probe(ip, f"NPM 反代高危漏洞路径扫描 ({uri[:30]})", weight=2, tag="NPM漏洞", now=now)
        return False

    def inspect_panel_request(self, client_ip: str, method: str, path: str) -> bool:
        if method.upper() == "CONNECT":
            return self.record_probe(client_ip, "防火墙面板恶意 CONNECT 代理扫描", weight=3, tag="面板代理")
        if RE_WEB_EXPLOIT_PATH.search(path):
            return self.record_probe(client_ip, f"防火墙面板漏洞路径扫描 ({path[:28]})", weight=2, tag="面板漏洞")
        return False

    # ----------------- Sentinel Trap Listener -----------------

    def _get_host_listening_ports(self, own_traps: Set[int]) -> Set[int]:
        occupied: Set[int] = {self.panel_port, 22, 80, 443}
        ss_bin = database._find_bin("ss")
        if ss_bin:
            try:
                r = subprocess.run([ss_bin, "-tlnH"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2)
                if r.returncode == 0 and r.stdout:
                    for ln in r.stdout.splitlines():
                        parts = ln.split()
                        if len(parts) >= 4 and ":" in parts[3]:
                            tail = parts[3].rsplit(":", 1)[-1]
                            if tail.isdigit():
                                lp = int(tail)
                                if lp not in own_traps:
                                    occupied.add(lp)
            except Exception:
                pass
        return occupied

    def release_trap_port(self, port: int):
        with self.lock:
            sock = self.trap_sockets.pop(port, None)
            if sock:
                try:
                    if self.trap_selector:
                        self.trap_selector.unregister(sock)
                except Exception:
                    pass
                try:
                    sock.close()
                except Exception:
                    pass

    def sync_trap_sockets(self):
        if self.trap_selector is None:
            return
        pol = self.get_policy()
        db_ports = database.list_trap_ports()
        is_root = database._is_root_linux()

        with self.lock:
            own_traps = set(self.trap_sockets.keys())
        occupied = self._get_host_listening_ports(own_traps)

        desired: Set[int] = set()
        new_status: Dict[int, str] = {}

        for row in db_ports:
            p = int(row["port"])
            if not pol["enabled"] or not row["enabled"]:
                new_status[p] = "disabled"
                continue
            if p < 1024 and not is_root:
                new_status[p] = "permission_denied"
                continue
            if p in occupied:
                new_status[p] = "occupied"
                continue
            desired.add(p)

        with self.lock:
            current = set(self.trap_sockets.keys())
            for p in current - desired:
                self.release_trap_port(p)
            for p in desired:
                if p in self.trap_sockets:
                    new_status[p] = "listening"
                    continue
                s = None
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.setblocking(False)
                    s.bind(("0.0.0.0", p))
                    s.listen(32)
                    self.trap_selector.register(s, selectors.EVENT_READ, data=p)
                    self.trap_sockets[p] = s
                    new_status[p] = "listening"
                except PermissionError:
                    new_status[p] = "permission_denied"
                    if s:
                        try:
                            s.close()
                        except Exception:
                            pass
                except OSError:
                    new_status[p] = "occupied"
                    if s:
                        try:
                            s.close()
                        except Exception:
                            pass
            self.trap_status = new_status

    def get_trap_status_map(self) -> Dict[int, str]:
        with self.lock:
            return dict(self.trap_status)

    def _trap_worker(self):
        try:
            self.trap_selector = selectors.DefaultSelector()
        except Exception:
            return
        last_sync = 0.0
        while not self._stop_event.is_set():
            try:
                now = time.time()
                if now - last_sync >= 15:
                    self.sync_trap_sockets()
                    last_sync = now
                if not self.trap_sockets:
                    time.sleep(1.5)
                    continue
                events = self.trap_selector.select(timeout=1.0)
                for key, _ in events:
                    tp = key.data
                    srv = key.fileobj
                    for _ in range(16):
                        try:
                            conn, addr = srv.accept()
                        except (BlockingIOError, OSError):
                            break
                        rip = addr[0] if addr else ""
                        try:
                            conn.close()
                        except Exception:
                            pass
                        if rip:
                            self.record_trap_hit(rip, tp)
            except Exception:
                time.sleep(1.5)

    # ----------------- Background Monitor Worker -----------------

    def _read_incremental(self, path: str, state: Dict[str, int]) -> List[str]:
        if not os.path.isfile(path):
            return []
        try:
            st = os.stat(path)
            ino, size = st.st_ino, st.st_size
            pos = state.get("pos", 0)
            if state.get("ino", 0) != ino or size < pos:
                pos = 0
            lines: List[str] = []
            if size > pos:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(pos)
                    lines = f.readlines()
                    pos = f.tell()
            state["ino"] = ino
            state["pos"] = pos
            return lines
        except Exception:
            return []

    def _read_journal(self, unit: str, holder: Dict[str, str]) -> List[str]:
        jctl = database._find_bin("journalctl")
        if not jctl:
            return []
        try:
            cmd = [jctl, "-u", unit, "--no-pager", "--show-cursor", "-n", "120"]
            if holder.get("cursor"):
                cmd = [jctl, "-u", unit, "--no-pager", "--show-cursor", f"--after-cursor={holder['cursor']}"]
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3)
            if r.returncode != 0 or not r.stdout:
                return []
            out = []
            for ln in r.stdout.splitlines():
                if ln.startswith("-- cursor:"):
                    holder["cursor"] = ln.split(":", 1)[1].strip()
                elif not ln.startswith("-- "):
                    out.append(ln)
            return out
        except Exception:
            return []

    def _poll_conntrack(self, now: float):
        ct = database._find_bin("conntrack")
        if not ct:
            return
        try:
            r = subprocess.run([ct, "-L", "-p", "tcp"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3)
            if r.returncode == 0 and r.stdout:
                prime = not self._conntrack_primed
                self._conntrack_primed = True
                self.process_conntrack_lines(r.stdout.splitlines(), now=now, prime_only=prime)
        except Exception:
            pass

    def _prune_memory(self, now: float):
        window_sec = self.get_policy()["window_sec"]
        with self.lock:
            for ip in [k for k, exp in self.trusted_ips.items() if exp <= now]:
                self.trusted_ips.pop(ip, None)
            for ip in [k for k, ts in self.recently_banned.items() if now - ts > 600]:
                self.recently_banned.pop(ip, None)
            for fk in [k for k, ts in self.seen_conntrack.items() if now - ts > 300]:
                self.seen_conntrack.pop(fk, None)
            for ip in list(self.probe_events.keys()):
                evs = [e for e in self.probe_events[ip] if now - e[0] <= window_sec]
                if evs:
                    self.probe_events[ip] = evs
                else:
                    self.probe_events.pop(ip, None)
            for ip in list(self.trap_hits.keys()):
                pm = {p: ts for p, ts in self.trap_hits[ip].items() if now - ts <= window_sec}
                if pm:
                    self.trap_hits[ip] = pm
                else:
                    self.trap_hits.pop(ip, None)
            for ip in list(self.port_conns.keys()):
                pm = {p: [t for t in h if now - t <= window_sec] for p, h in self.port_conns[ip].items()}
                pm = {p: h for p, h in pm.items() if h}
                if pm:
                    self.port_conns[ip] = pm
                else:
                    self.port_conns.pop(ip, None)
                    self.port_groups.pop(ip, None)

    def _monitor_worker(self):
        web_files = [
            "/var/log/nginx/access.log",
            "/root/npm/data/logs/fallback_http_access.log",
        ]
        sshd_files = ["/var/log/secure", "/var/log/auth.log"]
        file_states: Dict[str, Dict[str, int]] = {}
        sshd_cursor: Dict[str, str] = {}

        for p in web_files + sshd_files:
            if os.path.isfile(p):
                try:
                    st = os.stat(p)
                    file_states[p] = {"ino": st.st_ino, "pos": st.st_size}
                except Exception:
                    pass
        self._read_journal("sshd", sshd_cursor)
        self._poll_conntrack(time.time())

        last_clean = time.time()
        last_ct = time.time()
        last_sshd = 0.0

        while not self._stop_event.is_set():
            try:
                time.sleep(2.5)
                now = time.time()
                if now - last_clean >= 60:
                    last_clean = now
                    database.clean_expired_blacklist()
                    self._prune_memory(now)

                pol = self.get_policy()
                if not pol["enabled"]:
                    continue

                if pol["web_monitor"]:
                    for wf in web_files:
                        if os.path.isfile(wf):
                            st_d = file_states.setdefault(wf, {})
                            for ln in self._read_incremental(wf, st_d):
                                self.process_web_log_line(ln, now=now)

                if pol["sshd_monitor"] and (now - last_sshd >= 8):
                    last_sshd = now
                    active_sf = next((sf for sf in sshd_files if os.path.isfile(sf)), "")
                    lines = self._read_incremental(active_sf, file_states.setdefault(active_sf, {})) if active_sf else self._read_journal("sshd", sshd_cursor)
                    for ln in lines:
                        self.process_sshd_line(ln, now=now)

                if pol["full_port_conntrack"] and (now - last_ct >= 5):
                    last_ct = now
                    self._poll_conntrack(now)
            except Exception:
                time.sleep(2)

    def start(self):
        t1 = threading.Thread(target=self._trap_worker, daemon=True, name="CosmoFWTrapThread")
        t1.start()
        t2 = threading.Thread(target=self._monitor_worker, daemon=True, name="CosmoFWMonitorThread")
        t2.start()

    def stop(self):
        self._stop_event.set()
        with self.lock:
            for p in list(self.trap_sockets.keys()):
                self.release_trap_port(p)
