"""
database.py - SQLite persistence & Linux kernel ipset/iptables/conntrack enforcement for Cosmo Firewall.
"""

import os
import re
import time
import hmac
import shutil
import hashlib
import secrets
import sqlite3
import ipaddress
import threading
import subprocess
from typing import Any, Dict, List, Optional, Set, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.environ.get("COSMO_FW_DB", os.path.join(DATA_DIR, "firewall.db"))

IPSET_V4 = "cosmo_fw_blacklist"
IPSET_V6 = "cosmo_fw_blacklist6"
IPSET_WL_V4 = "cosmo_fw_whitelist"
IPSET_WL_V6 = "cosmo_fw_whitelist6"

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
_DB_LOCK = threading.RLock()
_FW_LOCK = threading.RLock()

_AUTO_EXEMPT_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

DEFAULT_TRAP_PORTS = [
    (2375, "Docker API 诱捕"),
    (3389, "Windows RDP 诱捕"),
    (5900, "VNC 远程桌面诱捕"),
    (9200, "Elasticsearch 诱捕"),
    (9998, "低位边界哨兵"),
    (9999, "低位边界哨兵"),
    (50001, "高位端口段哨兵"),
    (55555, "高位常用扫描哨兵"),
    (60001, "高位端口段哨兵"),
    (65000, "高位边界哨兵"),
]

DEFAULT_SETTINGS = {
    "site_title": "Cosmo Firewall",
    "defense_enabled": "1",
    "defense_mode": "safe",           # safe (稳健推荐) | standard (标准) | observe (仅观察不封禁)
    "progressive_ban": "1",           # 1=阶梯封禁(15m->2h->24h), 0=直接按ban_duration封禁
    "threshold": "5",
    "ban_duration": "86400",
    "window_sec": "600",
    "full_port_conntrack": "1",
    "sshd_monitor": "1",
    "web_monitor": "1",
    "trusted_service_ports": "22,7000,7001,8024",
    "excluded_ports": "80,443,8080,8081,8088,8443",
    "auto_trust_ttl": "7200",
    "auto_unban_enabled": "1",
    "auto_unban_daily_limit": "2",
}

_DOMAIN_RE = re.compile(r"^(?=.{3,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}$")


def get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def hash_password(password: str, salt: Optional[str] = None) -> str:
    if not salt:
        salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"pbkdf2_sha256${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        parts = stored.split("$")
        if len(parts) != 3 or parts[0] != "pbkdf2_sha256":
            return False
        calc = hash_password(password, salt=parts[1])
        return hmac.compare_digest(calc, stored)
    except Exception:
        return False


def normalize_ip(raw_ip: str) -> Optional[str]:
    """Normalize IPv4/IPv6 (unwrapping ports, brackets, IPv4-mapped IPv6, and ANSI escapes)."""
    if not raw_ip:
        return None
    s = _ANSI_RE.sub("", str(raw_ip)).strip().strip("(),;\"'")
    if not s:
        return None
    if s.startswith("[") and "]:" in s:
        s = s[1:s.index("]")]
    elif "]:" in s:
        s = s.split("]:", 1)[0].lstrip("[")
    else:
        s = s.strip("[]")
        if ":" in s and s.count(":") == 1:
            parts = s.split(":")
            if parts[1].isdigit():
                s = parts[0]
        elif s.lower().startswith("::ffff:") and s.count(":") == 3:
            idx = s.rfind(":")
            if s[idx + 1:].isdigit():
                s = s[:idx]
    if "%" in s:
        s = s.split("%", 1)[0]
    try:
        parsed = ipaddress.ip_address(s)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None:
            return str(parsed.ipv4_mapped)
        return str(parsed)
    except ValueError:
        return None


def normalize_ip_or_cidr(raw_val: str) -> Optional[str]:
    """Normalize either a single IP or a CIDR network string."""
    if not raw_val:
        return None
    s = str(raw_val).strip()
    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
            return str(net)
        except ValueError:
            return None
    return normalize_ip(s)


def _find_bin(name: str) -> Optional[str]:
    p = shutil.which(name)
    if p:
        return p
    for d in ("/usr/sbin", "/sbin", "/usr/bin", "/bin"):
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return None


def _is_root_linux() -> bool:
    return os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0


def is_protected_ip(ip: str) -> bool:
    clean = normalize_ip(ip)
    if not clean or clean in ("127.0.0.1", "::1", "0.0.0.0", "::"):
        return True
    try:
        parsed = ipaddress.ip_address(clean)
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_link_local or parsed.is_multicast:
            return True
    except Exception:
        return True
    return False


def is_auto_ban_exempt_ip(ip: str) -> bool:
    """Return True if IP is loopback/LAN/VPC or matched by user whitelist."""
    clean = normalize_ip(ip)
    if not clean or is_protected_ip(clean):
        return True
    try:
        parsed = ipaddress.ip_address(clean)
        for net in _AUTO_EXEMPT_NETS:
            if parsed.version == net.version and parsed in net:
                return True
    except Exception:
        return True
    if is_ip_whitelisted(clean):
        return True
    return False


def init_db():
    with _DB_LOCK:
        conn = get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS ip_blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    reason TEXT NOT NULL DEFAULT '',
                    source TEXT NOT NULL DEFAULT 'manual',
                    hit_count INTEGER NOT NULL DEFAULT 1,
                    created_at INTEGER NOT NULL,
                    expire_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS ip_whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry TEXT UNIQUE NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    is_domain INTEGER NOT NULL DEFAULT 0,
                    resolved_ip TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS trap_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    port INTEGER UNIQUE NOT NULL,
                    note TEXT NOT NULL DEFAULT '',
                    enabled INTEGER NOT NULL DEFAULT 1,
                    hit_count INTEGER NOT NULL DEFAULT 0,
                    last_hit_at INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS event_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_type TEXT NOT NULL,
                    ip TEXT NOT NULL DEFAULT '',
                    port INTEGER NOT NULL DEFAULT 0,
                    detail TEXT NOT NULL DEFAULT '',
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS unban_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    applicant_ip TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at INTEGER NOT NULL,
                    handled_at INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            now = int(time.time())
            # Seed default admin
            admin_user = os.environ.get("ADMIN_USER", "admin").strip() or "admin"
            admin_pass = os.environ.get("ADMIN_PASS", "admin").strip() or "admin"
            row = conn.execute("SELECT id FROM users WHERE username = ?;", (admin_user,)).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?);",
                    (admin_user, hash_password(admin_pass), now),
                )
            # Seed default settings
            for k, v in DEFAULT_SETTINGS.items():
                conn.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?);", (k, v))
            # Safe schema migration for existing ip_whitelist tables
            wl_cols = {r["name"] for r in conn.execute("PRAGMA table_info(ip_whitelist);").fetchall()}
            if "is_domain" not in wl_cols:
                conn.execute("ALTER TABLE ip_whitelist ADD COLUMN is_domain INTEGER NOT NULL DEFAULT 0;")
            if "resolved_ip" not in wl_cols:
                conn.execute("ALTER TABLE ip_whitelist ADD COLUMN resolved_ip TEXT NOT NULL DEFAULT '';")
            # Seed default trap ports only if table is empty
            cnt = conn.execute("SELECT COUNT(*) AS c FROM trap_ports;").fetchone()["c"]
            if cnt == 0:
                for p, note in DEFAULT_TRAP_PORTS:
                    conn.execute(
                        "INSERT OR IGNORE INTO trap_ports (port, note, enabled, hit_count, last_hit_at, created_at) VALUES (?, ?, 1, 0, 0, ?);",
                        (p, note, now),
                    )
            conn.commit()
        finally:
            conn.close()


# ----------------- Auth & Sessions -----------------

def authenticate_user(username: str, password: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?;", (username.strip(),)).fetchone()
        if not row or not verify_password(password, row["password_hash"]):
            return None
        return {"id": row["id"], "username": row["username"]}
    finally:
        conn.close()


def create_session(user_id: int, ttl_sec: int = 86400 * 7) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    with _DB_LOCK:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?);",
                (token, user_id, now, now + ttl_sec),
            )
            conn.commit()
        finally:
            conn.close()
    return token


def get_session_user(token: str) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    now = int(time.time())
    conn = get_conn()
    try:
        row = conn.execute(
            """
            SELECT u.id, u.username, s.expires_at
            FROM sessions s JOIN users u ON s.user_id = u.id
            WHERE s.token = ?;
            """,
            (token,),
        ).fetchone()
        if not row or row["expires_at"] < now:
            return None
        return {"id": row["id"], "username": row["username"]}
    finally:
        conn.close()


def delete_session(token: str):
    if not token:
        return
    with _DB_LOCK:
        conn = get_conn()
        try:
            conn.execute("DELETE FROM sessions WHERE token = ?;", (token,))
            conn.commit()
        finally:
            conn.close()


def change_password(user_id: int, old_password: str, new_password: str) -> Tuple[bool, str]:
    if not new_password or len(new_password) < 6:
        return False, "新密码长度不能少于 6 位"
    with _DB_LOCK:
        conn = get_conn()
        try:
            row = conn.execute("SELECT password_hash FROM users WHERE id = ?;", (user_id,)).fetchone()
            if not row or not verify_password(old_password, row["password_hash"]):
                return False, "原密码不正确"
            conn.execute("UPDATE users SET password_hash = ? WHERE id = ?;", (hash_password(new_password), user_id))
            conn.commit()
            return True, "密码修改成功"
        finally:
            conn.close()


# ----------------- Settings -----------------

def get_setting(key: str, default: str = "") -> str:
    conn = get_conn()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?;", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def get_all_settings() -> Dict[str, str]:
    res = dict(DEFAULT_SETTINGS)
    conn = get_conn()
    try:
        for r in conn.execute("SELECT key, value FROM settings;").fetchall():
            res[r["key"]] = r["value"]
        return res
    finally:
        conn.close()


def set_setting(key: str, value: str):
    with _DB_LOCK:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value;",
                (key, str(value)),
            )
            conn.commit()
        finally:
            conn.close()


# ----------------- Events -----------------

def record_event(event_type: str, ip: str = "", port: int = 0, detail: str = ""):
    now = int(time.time())
    with _DB_LOCK:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO event_logs (event_type, ip, port, detail, created_at) VALUES (?, ?, ?, ?, ?);",
                (event_type, ip, int(port or 0), detail[:240], now),
            )
            # Keep latest 500 events
            conn.execute(
                "DELETE FROM event_logs WHERE id NOT IN (SELECT id FROM event_logs ORDER BY id DESC LIMIT 500);"
            )
            conn.commit()
        finally:
            conn.close()


def list_events(limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT * FROM event_logs ORDER BY id DESC LIMIT ?;",
            (max(1, min(limit, 500)),),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ----------------- Whitelist -----------------

def list_whitelist() -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM ip_whitelist ORDER BY id DESC;").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def resolve_domain_ip(domain: str) -> Optional[str]:
    """Resolve a DDNS domain name to an IPv4 (preferred) or IPv6 address."""
    import socket
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return normalize_ip(infos[0][4][0])
    except Exception:
        pass
    try:
        infos = socket.getaddrinfo(domain, None, socket.AF_INET6, socket.SOCK_STREAM)
        if infos:
            return normalize_ip(infos[0][4][0])
    except Exception:
        pass
    return None


def is_ip_whitelisted(raw_ip: str) -> bool:
    clean = normalize_ip(raw_ip)
    if not clean:
        return False
    try:
        parsed = ipaddress.ip_address(clean)
    except ValueError:
        return False
    conn = get_conn()
    try:
        rows = conn.execute("SELECT entry, is_domain, resolved_ip FROM ip_whitelist;").fetchall()
        for r in rows:
            target = (r["resolved_ip"] if r["is_domain"] else r["entry"]) or ""
            if not target:
                continue
            try:
                if "/" in target:
                    net = ipaddress.ip_network(target, strict=False)
                    if parsed.version == net.version and parsed in net:
                        return True
                else:
                    if ipaddress.ip_address(target) == parsed:
                        return True
            except Exception:
                continue
        return False
    finally:
        conn.close()


def add_whitelist_entry(raw_entry: str, note: str = "") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    s = str(raw_entry or "").strip()
    clean = normalize_ip_or_cidr(s)
    is_dom = 0
    resolved = ""
    if not clean:
        if _DOMAIN_RE.match(s.lower()):
            clean = s.lower()
            is_dom = 1
            resolved = resolve_domain_ip(clean) or ""
        else:
            return False, f"无效的 IP、CIDR 网段或域名格式: {raw_entry}", None
    now = int(time.time())
    with _DB_LOCK:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO ip_whitelist (entry, note, is_domain, resolved_ip, created_at) VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(entry) DO UPDATE SET note = excluded.note, is_domain = excluded.is_domain, resolved_ip = excluded.resolved_ip;",
                (clean, (note or "").strip() or ("DDNS 动态白名单" if is_dom else "管理员白名单"), is_dom, resolved, now),
            )
            row = conn.execute("SELECT * FROM ip_whitelist WHERE entry = ?;", (clean,)).fetchone()
            conn.commit()
        finally:
            conn.close()

    effective_target = resolved if is_dom else clean
    if effective_target:
        if "/" not in effective_target:
            remove_blacklist_ip(effective_target)
        apply_firewall_whitelist(effective_target)
    detail = f"{note or '加入白名单'}" + (f" (当前解析: {resolved})" if is_dom and resolved else "")
    record_event("whitelist_add", ip=effective_target or clean, detail=detail)
    msg = f"已将 {clean} 加入白名单" + (f"（当前解析 IP: {resolved}）" if is_dom and resolved else ("（域名暂未解析到 IP，后台将持续自动同步）" if is_dom else ""))
    return True, msg, dict(row) if row else None


def refresh_ddns_whitelist() -> int:
    """Re-resolve all DDNS domain whitelist entries and sync kernel ipset if IP changed."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT id, entry, resolved_ip FROM ip_whitelist WHERE is_domain = 1;").fetchall()
    finally:
        conn.close()
    changed = 0
    for r in rows:
        dom = r["entry"]
        old_ip = r["resolved_ip"] or ""
        new_ip = resolve_domain_ip(dom) or ""
        if new_ip and new_ip != old_ip:
            with _DB_LOCK:
                c2 = get_conn()
                try:
                    c2.execute("UPDATE ip_whitelist SET resolved_ip = ? WHERE id = ?;", (new_ip, r["id"]))
                    c2.commit()
                finally:
                    c2.close()
            if old_ip:
                remove_firewall_whitelist(old_ip)
            remove_blacklist_ip(new_ip)
            apply_firewall_whitelist(new_ip)
            record_event("whitelist_ddns", ip=new_ip, detail=f"DDNS 域名 {dom} 动态 IP 更新: {old_ip or '无'} -> {new_ip}")
            changed += 1
    return changed


def count_recent_auto_bans(raw_ip: str, hours: int = 24) -> int:
    """Count how many times this IP was auto-banned in the past N hours (for progressive ban duration)."""
    clean = normalize_ip(raw_ip)
    if not clean:
        return 0
    since = int(time.time()) - hours * 3600
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM event_logs WHERE event_type = 'ban' AND ip = ? AND created_at >= ?;",
            (clean, since),
        ).fetchone()
        return int(row["c"]) if row else 0
    finally:
        conn.close()


def remove_whitelist_entry(entry_or_id: Any) -> Tuple[bool, str]:
    with _DB_LOCK:
        conn = get_conn()
        try:
            if isinstance(entry_or_id, int) or str(entry_or_id).isdigit():
                row = conn.execute("SELECT * FROM ip_whitelist WHERE id = ?;", (int(entry_or_id),)).fetchone()
            else:
                clean = normalize_ip_or_cidr(str(entry_or_id))
                row = conn.execute("SELECT * FROM ip_whitelist WHERE entry = ?;", (clean or str(entry_or_id).strip().lower(),)).fetchone()
            if not row:
                return False, "白名单记录不存在"
            entry = row["entry"]
            fw_target = row["resolved_ip"] if row["is_domain"] else entry
            conn.execute("DELETE FROM ip_whitelist WHERE id = ?;", (row["id"],))
            conn.commit()
        finally:
            conn.close()
    if fw_target:
        remove_firewall_whitelist(fw_target)
    record_event("whitelist_del", ip=fw_target or entry, detail=f"移出白名单 ({entry})")
    return True, f"已将 {entry} 移出白名单"


# ----------------- Blacklist -----------------

def is_ip_blacklisted(raw_ip: str) -> bool:
    clean = normalize_ip(raw_ip)
    if not clean:
        return False
    now = int(time.time())
    conn = get_conn()
    try:
        row = conn.execute("SELECT expire_at FROM ip_blacklist WHERE ip = ?;", (clean,)).fetchone()
        if not row:
            return False
        return row["expire_at"] == 0 or row["expire_at"] > now
    finally:
        conn.close()


def get_blacklist_entry(raw_ip: str) -> Optional[Dict[str, Any]]:
    clean = normalize_ip(raw_ip)
    if not clean:
        return None
    now = int(time.time())
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM ip_blacklist WHERE ip = ?;", (clean,)).fetchone()
        if not row:
            return None
        d = dict(row)
        if d["expire_at"] > 0 and d["expire_at"] <= now:
            return None
        d["remaining_seconds"] = max(0, d["expire_at"] - now) if d["expire_at"] > 0 else 0
        return d
    finally:
        conn.close()


def count_recent_auto_unbans(raw_ip: str, hours: int = 24) -> int:
    clean = normalize_ip(raw_ip)
    if not clean:
        return 0
    since = int(time.time()) - hours * 3600
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS c FROM unban_requests WHERE ip = ? AND status = 'auto_approved' AND created_at >= ?;",
            (clean, since),
        ).fetchone()
        return int(row["c"]) if row else 0
    finally:
        conn.close()


def create_unban_request(raw_ip: str, applicant_ip: str, reason: str, status: str = "pending") -> Dict[str, Any]:
    clean = normalize_ip(raw_ip) or str(raw_ip).strip()
    now = int(time.time())
    handled = now if status in ("auto_approved", "approved", "rejected") else 0
    with _DB_LOCK:
        conn = get_conn()
        try:
            cur = conn.execute(
                "INSERT INTO unban_requests (ip, applicant_ip, reason, status, created_at, handled_at) VALUES (?, ?, ?, ?, ?, ?);",
                (clean, applicant_ip, (reason or "").strip()[:240], status, now, handled),
            )
            row = conn.execute("SELECT * FROM unban_requests WHERE id = ?;", (cur.lastrowid,)).fetchone()
            conn.commit()
            return dict(row) if row else {}
        finally:
            conn.close()


def list_unban_requests(limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM unban_requests ORDER BY id DESC LIMIT ?;", (max(1, min(limit, 500)),)).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def handle_unban_request(req_id: int, approve: bool = True) -> Tuple[bool, str, str]:
    now = int(time.time())
    with _DB_LOCK:
        conn = get_conn()
        try:
            row = conn.execute("SELECT * FROM unban_requests WHERE id = ?;", (int(req_id),)).fetchone()
            if not row:
                return False, "解封申请记录不存在", ""
            ip_val = row["ip"]
            new_st = "approved" if approve else "rejected"
            conn.execute("UPDATE unban_requests SET status = ?, handled_at = ? WHERE id = ?;", (new_st, now, int(req_id)))
            conn.commit()
        finally:
            conn.close()
    if approve:
        remove_blacklist_ip(ip_val)
        return True, f"已通过解封申请并解除 {ip_val} 封禁", ip_val
    return True, f"已驳回 {ip_val} 的解封申请", ip_val


def add_blacklist_ip(raw_ip: str, reason: str = "管理员手动封禁", source: str = "manual", expire_seconds: int = 86400) -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    clean = normalize_ip(raw_ip)
    if not clean:
        return False, f"无效的 IP 地址: {raw_ip}", None
    if is_protected_ip(clean):
        return False, f"IP {clean} 属于受保护本机地址，禁止封禁", None
    if is_ip_whitelisted(clean):
        return False, f"IP {clean} 在白名单中，禁止封禁", None

    now = int(time.time())
    expire_at = (now + int(expire_seconds)) if int(expire_seconds) > 0 else 0

    with _DB_LOCK:
        conn = get_conn()
        try:
            conn.execute(
                """
                INSERT INTO ip_blacklist (ip, reason, source, hit_count, created_at, expire_at)
                VALUES (?, ?, ?, 1, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    reason = excluded.reason,
                    source = excluded.source,
                    hit_count = ip_blacklist.hit_count + 1,
                    expire_at = excluded.expire_at;
                """,
                (clean, (reason or "").strip() or "管理员手动封禁", source, now, expire_at),
            )
            row = conn.execute("SELECT * FROM ip_blacklist WHERE ip = ?;", (clean,)).fetchone()
            conn.commit()
        finally:
            conn.close()

    apply_firewall_drop(clean)
    record_event("ban", ip=clean, detail=f"[{source}] {reason}")
    return True, f"已封禁 {clean}", dict(row) if row else None


def remove_blacklist_ip(ip_or_id: Any) -> Tuple[bool, str]:
    with _DB_LOCK:
        conn = get_conn()
        try:
            if isinstance(ip_or_id, int) or str(ip_or_id).isdigit():
                row = conn.execute("SELECT * FROM ip_blacklist WHERE id = ?;", (int(ip_or_id),)).fetchone()
            else:
                clean = normalize_ip(str(ip_or_id))
                row = conn.execute("SELECT * FROM ip_blacklist WHERE ip = ?;", (clean or str(ip_or_id),)).fetchone()
            if not row:
                return False, "黑名单记录不存在"
            ip_val = row["ip"]
            conn.execute("DELETE FROM ip_blacklist WHERE id = ?;", (row["id"],))
            conn.commit()
        finally:
            conn.close()
    remove_firewall_drop(ip_val)
    record_event("unban", ip=ip_val, detail="解除封禁")
    return True, f"已解封 {ip_val}"


def list_blacklist(include_expired: bool = False) -> List[Dict[str, Any]]:
    now = int(time.time())
    conn = get_conn()
    try:
        if include_expired:
            rows = conn.execute("SELECT * FROM ip_blacklist ORDER BY id DESC;").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM ip_blacklist WHERE expire_at = 0 OR expire_at > ? ORDER BY id DESC;",
                (now,),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            exp = d["expire_at"]
            d["is_expired"] = (exp > 0 and exp <= now)
            d["remaining_seconds"] = max(0, exp - now) if exp > 0 else 0
            out.append(d)
        return out
    finally:
        conn.close()


def clear_blacklist(source: Optional[str] = None) -> Tuple[bool, str, int]:
    with _DB_LOCK:
        conn = get_conn()
        try:
            if source == "auto":
                rows = conn.execute("SELECT ip FROM ip_blacklist WHERE source IN ('auto_scan', 'brute_force');").fetchall()
                conn.execute("DELETE FROM ip_blacklist WHERE source IN ('auto_scan', 'brute_force');")
            elif source:
                rows = conn.execute("SELECT ip FROM ip_blacklist WHERE source = ?;", (source,)).fetchall()
                conn.execute("DELETE FROM ip_blacklist WHERE source = ?;", (source,))
            else:
                rows = conn.execute("SELECT ip FROM ip_blacklist;").fetchall()
                conn.execute("DELETE FROM ip_blacklist;")
            conn.commit()
        finally:
            conn.close()
    for r in rows:
        remove_firewall_drop(r["ip"])
    return True, f"已清理 {len(rows)} 条黑名单记录", len(rows)


def clean_expired_blacklist() -> int:
    now = int(time.time())
    with _DB_LOCK:
        conn = get_conn()
        try:
            rows = conn.execute("SELECT ip FROM ip_blacklist WHERE expire_at > 0 AND expire_at <= ?;", (now,)).fetchall()
            if rows:
                conn.execute("DELETE FROM ip_blacklist WHERE expire_at > 0 AND expire_at <= ?;", (now,))
                conn.commit()
        finally:
            conn.close()
    for r in rows:
        remove_firewall_drop(r["ip"])
    return len(rows)


# ----------------- Trap Ports -----------------

def list_trap_ports() -> List[Dict[str, Any]]:
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM trap_ports ORDER BY port ASC;").fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def add_trap_port(port: int, note: str = "") -> Tuple[bool, str, Optional[Dict[str, Any]]]:
    try:
        p = int(port)
    except Exception:
        return False, "端口必须是整数", None
    if p < 1 or p > 65535:
        return False, "端口必须在 1–65535 之间", None
    if p in (22, 80, 443):
        return False, f"端口 {p} 为系统核心保留端口，不建议设为诱捕端口", None
    now = int(time.time())
    with _DB_LOCK:
        conn = get_conn()
        try:
            conn.execute(
                "INSERT INTO trap_ports (port, note, enabled, hit_count, last_hit_at, created_at) VALUES (?, ?, 1, 0, 0, ?) "
                "ON CONFLICT(port) DO UPDATE SET note = excluded.note, enabled = 1;",
                (p, (note or "").strip() or f"自定义哨兵端口 {p}", now),
            )
            row = conn.execute("SELECT * FROM trap_ports WHERE port = ?;", (p,)).fetchone()
            conn.commit()
            return True, f"已添加探测诱捕端口 {p}", dict(row) if row else None
        finally:
            conn.close()


def toggle_trap_port(port_id: int, enabled: bool) -> Tuple[bool, str]:
    with _DB_LOCK:
        conn = get_conn()
        try:
            cur = conn.execute("UPDATE trap_ports SET enabled = ? WHERE id = ?;", (1 if enabled else 0, int(port_id)))
            conn.commit()
            if cur.rowcount == 0:
                return False, "诱捕端口记录不存在"
            return True, "状态已更新"
        finally:
            conn.close()


def delete_trap_port(port_id: int) -> Tuple[bool, str, int]:
    with _DB_LOCK:
        conn = get_conn()
        try:
            row = conn.execute("SELECT port FROM trap_ports WHERE id = ?;", (int(port_id),)).fetchone()
            if not row:
                return False, "诱捕端口记录不存在", 0
            p = row["port"]
            conn.execute("DELETE FROM trap_ports WHERE id = ?;", (int(port_id),))
            conn.commit()
            return True, f"已删除诱捕端口 {p}", p
        finally:
            conn.close()


def increment_trap_port_hit(port: int):
    now = int(time.time())
    with _DB_LOCK:
        conn = get_conn()
        try:
            conn.execute(
                "UPDATE trap_ports SET hit_count = hit_count + 1, last_hit_at = ? WHERE port = ?;",
                (now, int(port)),
            )
            conn.commit()
        finally:
            conn.close()


# ----------------- Linux Kernel ipset / iptables / conntrack -----------------

def _ensure_ipset_rules() -> bool:
    if not _is_root_linux():
        return False
    ipset_bin = _find_bin("ipset")
    ipt_bin = _find_bin("iptables")
    if not ipset_bin or not ipt_bin:
        return False
    try:
        # Create blacklist & whitelist ipsets
        subprocess.run([ipset_bin, "create", IPSET_V4, "hash:ip", "hashsize", "4096", "maxelem", "262144", "-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        subprocess.run([ipset_bin, "create", IPSET_WL_V4, "hash:net", "hashsize", "1024", "maxelem", "65536", "-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
        for chain in ("INPUT", "DOCKER-USER"):
            # Ensure DROP rule
            r_chk = subprocess.run([ipt_bin, "-C", chain, "-m", "set", "--match-set", IPSET_V4, "src", "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if r_chk.returncode != 0:
                subprocess.run([ipt_bin, "-I", chain, "1", "-m", "set", "--match-set", IPSET_V4, "src", "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            # Ensure WHITELIST ACCEPT rule above DROP
            r_wl = subprocess.run([ipt_bin, "-C", chain, "-m", "set", "--match-set", IPSET_WL_V4, "src", "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if r_wl.returncode != 0:
                subprocess.run([ipt_bin, "-I", chain, "1", "-m", "set", "--match-set", IPSET_WL_V4, "src", "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        # Allow blocked users to reach the /unban self-service portal port on INPUT when auto_unban_enabled=1
        if get_setting("auto_unban_enabled", "1") == "1":
            fw_port = str(int(os.environ.get("PORT", "8090")))
            r_up = subprocess.run([ipt_bin, "-C", "INPUT", "-p", "tcp", "--dport", fw_port, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if r_up.returncode != 0:
                subprocess.run([ipt_bin, "-I", "INPUT", "1", "-p", "tcp", "--dport", fw_port, "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)

        ip6t_bin = _find_bin("ip6tables")
        if ip6t_bin:
            subprocess.run([ipset_bin, "create", IPSET_V6, "hash:ip", "family", "inet6", "hashsize", "1024", "maxelem", "65536", "-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            subprocess.run([ipset_bin, "create", IPSET_WL_V6, "hash:net", "family", "inet6", "hashsize", "1024", "maxelem", "65536", "-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
            r_chk6 = subprocess.run([ip6t_bin, "-C", "INPUT", "-m", "set", "--match-set", IPSET_V6, "src", "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if r_chk6.returncode != 0:
                subprocess.run([ip6t_bin, "-I", "INPUT", "1", "-m", "set", "--match-set", IPSET_V6, "src", "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            r_wl6 = subprocess.run([ip6t_bin, "-C", "INPUT", "-m", "set", "--match-set", IPSET_WL_V6, "src", "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            if r_wl6.returncode != 0:
                subprocess.run([ip6t_bin, "-I", "INPUT", "1", "-m", "set", "--match-set", IPSET_WL_V6, "src", "-j", "ACCEPT"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        return True
    except Exception:
        return False


def apply_firewall_drop(ip: str):
    if not _is_root_linux():
        return
    clean = normalize_ip(ip)
    if not clean or is_protected_ip(clean):
        return
    with _FW_LOCK:
        try:
            is_v6 = ":" in clean
            if _ensure_ipset_rules():
                ipset_bin = _find_bin("ipset")
                set_name = IPSET_V6 if is_v6 else IPSET_V4
                subprocess.run([ipset_bin, "add", set_name, clean, "-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            else:
                ipt = _find_bin("ip6tables" if is_v6 else "iptables")
                if ipt:
                    if subprocess.run([ipt, "-C", "INPUT", "-s", clean, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2).returncode != 0:
                        subprocess.run([ipt, "-I", "INPUT", "1", "-s", clean, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            ct = _find_bin("conntrack")
            if ct:
                subprocess.run([ct, "-D", "-s", clean], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except Exception:
            pass


def remove_firewall_drop(ip: str):
    if not _is_root_linux():
        return
    clean = normalize_ip(ip)
    if not clean:
        return
    with _FW_LOCK:
        try:
            is_v6 = ":" in clean
            ipset_bin = _find_bin("ipset")
            if ipset_bin:
                subprocess.run([ipset_bin, "del", IPSET_V6 if is_v6 else IPSET_V4, clean, "-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
            ipt = _find_bin("ip6tables" if is_v6 else "iptables")
            if ipt:
                for _ in range(3):
                    if subprocess.run([ipt, "-D", "INPUT", "-s", clean, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2).returncode != 0:
                        break
        except Exception:
            pass


def apply_firewall_whitelist(entry: str):
    if not _is_root_linux():
        return
    clean = normalize_ip_or_cidr(entry)
    if not clean:
        return
    with _FW_LOCK:
        try:
            if _ensure_ipset_rules():
                ipset_bin = _find_bin("ipset")
                set_name = IPSET_WL_V6 if ":" in clean else IPSET_WL_V4
                subprocess.run([ipset_bin, "add", set_name, clean, "-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except Exception:
            pass


def remove_firewall_whitelist(entry: str):
    if not _is_root_linux():
        return
    clean = normalize_ip_or_cidr(entry)
    if not clean:
        return
    with _FW_LOCK:
        try:
            ipset_bin = _find_bin("ipset")
            if ipset_bin:
                set_name = IPSET_WL_V6 if ":" in clean else IPSET_WL_V4
                subprocess.run([ipset_bin, "del", set_name, clean, "-exist"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        except Exception:
            pass


def sync_all_firewall_rules() -> Dict[str, Any]:
    """Re-apply all active blacklist & whitelist entries into kernel ipset/iptables."""
    clean_expired_blacklist()
    refresh_ddns_whitelist()
    wl = list_whitelist()
    bl = list_blacklist(include_expired=False)
    for item in wl:
        target = item["resolved_ip"] if item.get("is_domain") else item["entry"]
        if target:
            apply_firewall_whitelist(target)
    for item in bl:
        apply_firewall_drop(item["ip"])
    return {
        "root": _is_root_linux(),
        "whitelist_synced": len(wl),
        "blacklist_synced": len(bl),
    }


def get_kernel_firewall_stats() -> Dict[str, Any]:
    """Return kernel ipset/iptables enforcement mode & dropped packet counter."""
    is_root = _is_root_linux()
    ipset_bin = _find_bin("ipset")
    ipt_bin = _find_bin("iptables")
    ct_bin = _find_bin("conntrack")
    dropped_pkts = 0
    dropped_bytes = 0
    mode = "simulation"
    if is_root and ipset_bin and ipt_bin:
        mode = "ipset+iptables"
        try:
            r = subprocess.run([ipt_bin, "-L", "INPUT", "-n", "-v", "-x"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2)
            if r.returncode == 0:
                for ln in r.stdout.splitlines():
                    if IPSET_V4 in ln and "DROP" in ln:
                        parts = ln.split()
                        if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                            dropped_pkts += int(parts[0])
                            dropped_bytes += int(parts[1])
        except Exception:
            pass
    elif is_root and ipt_bin:
        mode = "iptables"
    return {
        "is_root": is_root,
        "mode": mode,
        "has_ipset": bool(ipset_bin),
        "has_iptables": bool(ipt_bin),
        "has_conntrack": bool(ct_bin),
        "dropped_packets": dropped_pkts,
        "dropped_bytes": dropped_bytes,
    }
