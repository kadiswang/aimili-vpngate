#!/usr/bin/env python3
from __future__ import annotations

print("[DEBUG] vpngate_manager.py loaded from: " + __file__, flush=True)

import base64
import csv
import json
import os
import queue
import re
import select
import shlex
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from collections import deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
import concurrent.futures
import sys
import uuid

# Prefer IPv4 resolution to avoid slow AAAA DNS timeouts (e.g. in WSL),
# but fall back to system default (IPv6) if IPv4 resolution fails.
# This ensures pure-IPv6 VPS (with NAT64/clatd) can still function.
_orig_getaddrinfo = socket.getaddrinfo
def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        # Try IPv4 first for speed; fall back to system default (allows IPv6/NAT64)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)
socket.getaddrinfo = _ipv4_getaddrinfo

class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if ":" in host or host == "":
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET
        
        try:
            super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host in ("::", "") else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
                # 关闭第一次失败时可能已创建的 socket
                try:
                    self.socket.close()
                except Exception:
                    pass
                self.address_family = socket.AF_INET
                super().__init__((fallback_host, port), RequestHandlerClass, bind_and_activate)
            else:
                raise e

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()

import vpn_utils
import proxy_server

def env_int(name: str, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    raw = os.environ.get(name)
    try:
        value = int(raw) if raw not in (None, "") else default
    except (TypeError, ValueError):
        print(f"[配置警告] 环境变量 {name}={raw!r} 不是有效整数，使用默认值 {default}", flush=True)
        value = default
    if min_value is not None and value < min_value:
        print(f"[配置警告] 环境变量 {name}={value} 小于允许值 {min_value}，使用默认值 {default}", flush=True)
        return default
    if max_value is not None and value > max_value:
        print(f"[配置警告] 环境变量 {name}={value} 大于允许值 {max_value}，使用默认值 {default}", flush=True)
        return default
    return value

def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and parsed < min_value:
        return default
    if max_value is not None and parsed > max_value:
        return default
    return parsed

API_URL = "https://www.vpngate.net/api/iphone/"
FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1260, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1260, 1)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 300, 1)
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 1)
MANUAL_TEST_NODE_LIMIT = env_int("MANUAL_TEST_NODE_LIMIT", 5, 1, 20)
INITIAL_CONNECT_TEST_LIMIT = env_int("INITIAL_CONNECT_TEST_LIMIT", 10, 1, 50)
OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
LOCAL_PROXY_PORT = env_int("LOCAL_PROXY_PORT", 7928, 1, 65535)
UI_HOST = os.environ.get("UI_HOST", "::")
UI_PORT = env_int("UI_PORT", 8790, 1, 65535)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"

SESSION_CLEANUP_INTERVAL = 300  # 5 minutes
SESSION_TIMEOUT = 30 * 24 * 3600  # 30 days
LOGIN_RATE_LIMIT_WINDOW = 300  # 5 minutes
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10
CSRF_TOKEN_EXPIRY = 30 * 60  # 30 minutes
CONFIG_CACHE_TTL = 5.0  # 5 seconds
LOG_TAIL_LINES = 500  # max lines returned via API
NODE_CACHE_TTL = 2.0  # seconds
MAX_CONFIG_TEXT_LENGTH = 8192  # truncate config_text for API responses
NODE_EXPORT_FIELDS = [
    "id", "country", "country_short", "host_name", "ip",
    "score", "ping", "speed", "sessions", "owner", "asn",
    "as_name", "location", "ip_type", "quality", "latency_ms",
    "probe_status", "probe_message", "probed_at",
]

lock = threading.RLock()
maintenance_lock = threading.Lock()
active_sessions: dict[str, float] = {}
active_ws_clients: list = []
ws_clients_lock = threading.Lock()
active_openvpn_process: subprocess.Popen[str] | None = None
active_openvpn_node_id = ""
is_connecting = False
last_active_ping_time = 0.0
last_active_latency = 0

last_collector_heartbeat = 0.0
last_checker_heartbeat = 0.0
last_pinger_heartbeat = 0.0
server_start_time = time.time()

_nodes_cache: list[dict[str, Any]] | None = None
_nodes_cache_time = 0.0
_NODES_CACHE_TTL = NODE_CACHE_TTL

def _cleanup_expired_sessions() -> None:
    now = time.time()
    expired = [t for t, exp in active_sessions.items() if exp <= now]
    for t in expired:
        active_sessions.pop(t, None)


def _get_or_cleanup_sessions() -> dict[str, float]:
    _cleanup_expired_sessions()
    return active_sessions


def _cached_load_ui_config() -> dict[str, Any]:
    global _config_cache, _config_cache_time
    now = time.time()
    if _config_cache is not None and now - _config_cache_time < CONFIG_CACHE_TTL:
        return _config_cache
    result = load_ui_config()
    with lock:
        _config_cache = result
        _config_cache_time = now
    return result


_config_cache: dict[str, Any] | None = None
_config_cache_time = 0.0
_last_cleanup_time = 0.0


def load_ui_config() -> dict[str, Any]:
    with lock:
        auth_file = DATA_DIR / "ui_auth.json"
        config = {
            "username": "",
            "secret_path": "EJsW2EeBo9lY",
            "password": "",
            "host": UI_HOST,
            "port": UI_PORT,
            "proxy_port": LOCAL_PROXY_PORT,
            "routing_mode": "auto",
            "force_country": "",
            "routing_ip_type": "all",
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_fail_fallback": True,
            "upstream_proxy": { "enabled": False }
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback", "upstream_proxy"]:
                    if key not in data:
                        updated = True
            except Exception:
                pass
        
        if not config.get("username"):
            config["username"] = generate_random_username()
            updated = True
            
        if not config.get("password"):
            config["password"] = generate_random_password()
            updated = True

        normalized_port = bounded_int(config.get("port"), UI_PORT, 1, 65535)
        if normalized_port != config.get("port"):
            config["port"] = normalized_port
            updated = True

        normalized_proxy_port = bounded_int(config.get("proxy_port"), LOCAL_PROXY_PORT, 1024, 65535)
        if normalized_proxy_port == normalized_port:
            fallback_proxy_port = LOCAL_PROXY_PORT if LOCAL_PROXY_PORT != normalized_port else 7928
            if fallback_proxy_port == normalized_port:
                fallback_proxy_port = 7929
            normalized_proxy_port = fallback_proxy_port
        if normalized_proxy_port != config.get("proxy_port"):
            config["proxy_port"] = normalized_proxy_port
            updated = True
            
        if not auth_file.exists() or updated:
            try:
                DATA_DIR.mkdir(exist_ok=True, parents=True)
                write_json(auth_file, config)
            except Exception:
                pass
                
        return config


def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass

def upstream_proxy_auth_file() -> str | None:
    username, password = vpn_utils.get_upstream_proxy_auth()
    if username is None:
        return None
    try:
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        UPSTREAM_PROXY_AUTH_FILE.write_text(f"{username}\n{password or ''}\n", encoding="utf-8")
        try:
            UPSTREAM_PROXY_AUTH_FILE.chmod(0o600)
        except OSError:
            pass
        return str(UPSTREAM_PROXY_AUTH_FILE)
    except Exception as exc:
        print(f"[上游代理认证] 写入认证文件失败: {exc}", flush=True)
        return None

def write_json(path: Path, data: Any) -> None:
    with lock:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
        if path == NODES_FILE:
            global _nodes_cache
            _nodes_cache = None

def read_json(path: Path, default: Any) -> Any:
    with lock:
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default

import hashlib
import random

def generate_random_password() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(random.choices(chars, k=12))
        # Ensure it contains at least one lowercase, one uppercase, and one digit
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd

def generate_random_username() -> str:
    import string
    chars = string.ascii_letters + string.digits
    while True:
        uname = "".join(random.choices(chars, k=12))
        # Ensure it starts with a letter and contains at least one lowercase, one uppercase, and one digit
        if uname[0].isalpha():
            has_lower = any(c.islower() for c in uname)
            has_upper = any(c.isupper() for c in uname)
            has_digit = any(c.isdigit() for c in uname)
            if has_lower and has_upper and has_digit:
                return uname

# 初始化时优先从 ui_auth.json 加载保存的代理出站端口和网页端口配置以覆盖环境变量
try:
    _init_cfg = _cached_load_ui_config()
    if "proxy_port" in _init_cfg:
        LOCAL_PROXY_PORT = bounded_int(_init_cfg["proxy_port"], LOCAL_PROXY_PORT, 1024, 65535)
    if "port" in _init_cfg:
        UI_PORT = bounded_int(_init_cfg["port"], UI_PORT, 1, 65535)
    if "host" in _init_cfg:
        UI_HOST = _init_cfg["host"]
except Exception:
    pass

_login_attempts: dict[str, list[float]] = {}
_login_attempts_lock = threading.Lock()

_csrf_tokens: dict[str, tuple[float, str]] = {}
_csrf_lock = threading.Lock()


def _check_login_rate_limit(ip: str) -> bool:
    now = time.time()
    with _login_attempts_lock:
        if ip not in _login_attempts:
            _login_attempts[ip] = []
        timestamps = [_t for _t in _login_attempts[ip] if now - _t < LOGIN_RATE_LIMIT_WINDOW]
        _login_attempts[ip] = timestamps
        return len(timestamps) < LOGIN_RATE_LIMIT_MAX_ATTEMPTS


def _record_login_attempt(ip: str) -> None:
    now = time.time()
    with _login_attempts_lock:
        if ip not in _login_attempts:
            _login_attempts[ip] = []
        _login_attempts[ip].append(now)


def _generate_csrf_token() -> str:
    token = uuid.uuid4().hex + uuid.uuid4().hex
    with _csrf_lock:
        _csrf_tokens[token] = (time.time() + CSRF_TOKEN_EXPIRY, token)
    return token


def _validate_csrf_token(token: str | None) -> bool:
    if not token:
        return False
    with _csrf_lock:
        entry = _csrf_tokens.get(token)
        if not entry:
            return False
        expiry, _ = entry
        if time.time() > expiry:
            _csrf_tokens.pop(token, None)
            return False
        _csrf_tokens[token] = (time.time() + CSRF_TOKEN_EXPIRY, token)
        return True
    salt = "aimilivpn_secure_salt_2026"
    return hashlib.sha256((username + ":" + password + salt).encode("utf-8")).hexdigest()

def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    with lock:
        if now - _last_cleanup_time < 3600:
            return
        _last_cleanup_time = now
    try:
        three_days_sec = 3 * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = re.match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= three_days_sec:
                        with lock:
                            path.unlink()
                        print(f"[清理] 已删除3天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > three_days_sec:
                        with lock:
                            path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)

def log_to_json(level: str, module: str, message: str) -> None:
    try:
        logs_dir = DATA_DIR / "logs"
        logs_dir.mkdir(exist_ok=True, parents=True)
        date_str = time.strftime("%Y-%m-%d", time.localtime())
        log_file = logs_dir / f"{date_str}.json"
        entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "level": level,
            "module": module,
            "message": message
        }
        with lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)


_audit_log_lock = threading.Lock()
_audit_logs: list[dict[str, Any]] = []
_MAX_AUDIT_LOGS = 1000


def log_audit(action: str, module: str, detail: str, user: str = "system") -> None:
    entry = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "action": action,
        "module": module,
        "detail": detail,
        "user": user,
    }
    with _audit_log_lock:
        _audit_logs.append(entry)
        if len(_audit_logs) > _MAX_AUDIT_LOGS:
            _audit_logs[:] = _audit_logs[-_MAX_AUDIT_LOGS:]
    log_to_json("AUDIT", module, f"[{action}] {detail} (user: {user})")


_event_stream_lock = threading.Lock()
_event_callbacks: list[callable] = []


def register_event_callback(cb: callable) -> None:
    with _event_stream_lock:
        _event_callbacks.append(cb)


def broadcast_event(event_type: str, data: dict[str, Any] | None = None) -> None:
    with _event_stream_lock:
        for cb in _event_callbacks:
            try:
                cb(event_type, data)
            except Exception:
                pass

def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)

def read_nodes() -> list[dict[str, Any]]:
    global _nodes_cache, _nodes_cache_time
    now = time.time()
    with lock:
        if _nodes_cache is not None and now - _nodes_cache_time < _NODES_CACHE_TTL:
            print(f"[DEBUG] read_nodes returning cached {len(_nodes_cache)} nodes", flush=True)
            return _nodes_cache
        raw = read_json(NODES_FILE, [])
        print(f"[DEBUG] read_nodes reading {NODES_FILE}, got {len(raw) if isinstance(raw, list) else 'non-list'} items", flush=True)
        if not isinstance(raw, list):
            _nodes_cache = []
            return []
        _nodes_cache = [item for item in raw if isinstance(item, dict)]
        _nodes_cache_time = now
        print(f"[DEBUG] read_nodes cached {len(_nodes_cache)} nodes", flush=True)
        return _nodes_cache

def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    state.setdefault("api_url", API_URL)
    state.setdefault("target_valid_nodes", TARGET_VALID_NODES)
    state.setdefault("fetch_interval_seconds", FETCH_INTERVAL_SECONDS)
    state.setdefault("check_interval_seconds", CHECK_INTERVAL_SECONDS)
    _proxy_display = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
    state["local_proxy"] = f"http://{_proxy_display}:{LOCAL_PROXY_PORT}"
    state.setdefault("last_fetch_status", "not_started")
    state.setdefault("last_check_message", "")
    state.setdefault("blacklisted_nodes", 0)
    
    # Pre-populate settings inputs in UI
    ui_cfg = _cached_load_ui_config()
    state["username"] = ui_cfg.get("username", "admin")
    state["port"] = ui_cfg.get("port", 8790)
    state["secret_path"] = ui_cfg.get("secret_path", "EJsW2EeBo9lY")
    state["password_set"] = bool(ui_cfg.get("password"))
    state["proxy_port"] = ui_cfg.get("proxy_port", 7928)
    state["routing_mode"] = ui_cfg.get("routing_mode", "auto")
    state["force_country"] = ui_cfg.get("force_country", "")
    state["routing_ip_type"] = ui_cfg.get("routing_ip_type", "all")
    state["connection_enabled"] = ui_cfg.get("connection_enabled", True)
    state["fixed_node_id"] = ui_cfg.get("fixed_node_id", "")
    state["favorite_node_ids"] = ui_cfg.get("favorite_node_ids", [])
    state["fav_fail_fallback"] = ui_cfg.get("fav_fail_fallback", True)
    state["upstream_proxy"] = ui_cfg.get("upstream_proxy", { "enabled": False })
    state["country_translations"] = vpn_utils.COUNTRY_TRANSLATIONS
    state["maintenance_running"] = maintenance_lock.locked()
    
    return state

def safe_name(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())
    return value.strip("._") or "node"

def clear_active_connection_state(message: str) -> None:
    global active_openvpn_process, active_openvpn_node_id
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    with lock:
        nodes = read_nodes()
        for item in nodes:
            item["active"] = False
        write_json(NODES_FILE, nodes)
    set_state(
        active_openvpn_node_id="",
        is_connecting=False,
        active_node_latency="无活动连接",
        last_check_message=message,
    )

def parse_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0

def proxy_basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n"

def recv_exact_from_socket(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise RuntimeError("Unexpected EOF while reading proxy response")
        data += chunk
    return data

def read_http_response_head(sock: socket.socket, limit: int = 65536) -> bytes:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if len(data) > limit:
            raise RuntimeError("Proxy response header too large")
    if b"\r\n\r\n" not in data:
        raise RuntimeError("Incomplete HTTP proxy response header")
    return data

def socks5_address_bytes(host: str) -> tuple[int, bytes]:
    try:
        return 1, socket.inet_aton(host)
    except OSError:
        pass
    try:
        return 4, socket.inet_pton(socket.AF_INET6, host)
    except OSError:
        pass
    host_bytes = host.encode("idna")
    if len(host_bytes) > 255:
        raise RuntimeError("SOCKS5 target host name is too long")
    return 3, bytes([len(host_bytes)]) + host_bytes

def read_socks5_connect_reply(sock: socket.socket) -> None:
    header = recv_exact_from_socket(sock, 4)
    if header[0] != 5:
        raise RuntimeError("Invalid SOCKS5 reply version")
    atyp = header[3]
    if atyp == 1:
        recv_exact_from_socket(sock, 4)
    elif atyp == 3:
        domain_len = recv_exact_from_socket(sock, 1)[0]
        recv_exact_from_socket(sock, domain_len)
    elif atyp == 4:
        recv_exact_from_socket(sock, 16)
    else:
        raise RuntimeError(f"Invalid SOCKS5 reply address type: {atyp}")
    recv_exact_from_socket(sock, 2)
    if header[1] != 0:
        raise RuntimeError(f"SOCKS5 connection request rejected, code={header[1]}")

def format_host_port(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"

def fetch_api_text_via_proxy(url: str, ptype: str, phost: str, pport: int, use_ssl_verify: bool = True, proxy_user: str | None = None, proxy_pass: str | None = None) -> str:
    import socket
    import ssl
    import urllib.parse

    parsed = urllib.parse.urlsplit(url)
    domain = parsed.hostname or "www.vpngate.net"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    is_https = parsed.scheme == "https"
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    is_ipv6 = ":" in phost
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(12)
        s.connect((phost, pport))
        if proxy_user is None:
            proxy_user, proxy_pass = vpn_utils.get_upstream_proxy_auth()
        if ptype == "socks":
            # SOCKS5 Handshake
            if proxy_user is not None:
                s.sendall(b"\x05\x02\x00\x02")
            else:
                s.sendall(b"\x05\x01\x00")
            resp = recv_exact_from_socket(s, 2)
            if len(resp) < 2 or resp[0] != 5:
                raise RuntimeError("SOCKS5 authentication failed or unsupported")
            if resp[1] == 2:
                if proxy_user is None:
                    raise RuntimeError("SOCKS5 proxy requires username/password authentication")
                user_bytes = proxy_user.encode("utf-8")
                pass_bytes = (proxy_pass or "").encode("utf-8")
                if len(user_bytes) > 255 or len(pass_bytes) > 255:
                    raise RuntimeError("SOCKS5 proxy credentials are too long")
                s.sendall(b"\x01" + bytes([len(user_bytes)]) + user_bytes + bytes([len(pass_bytes)]) + pass_bytes)
                auth_resp = recv_exact_from_socket(s, 2)
                if len(auth_resp) < 2 or auth_resp[1] != 0:
                    raise RuntimeError("SOCKS5 username/password authentication failed")
            elif resp[1] != 0:
                raise RuntimeError("SOCKS5 authentication method unsupported")
            # SOCKS5 Connect
            atyp, addr_bytes = socks5_address_bytes(domain)
            req = b"\x05\x01\x00" + bytes([atyp]) + addr_bytes + port.to_bytes(2, 'big')
            s.sendall(req)
            read_socks5_connect_reply(s)
            # If HTTPS, wrap socket with SSL
            if is_https:
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
        else: # http proxy
            if is_https:
                # HTTP CONNECT tunnel
                authority = format_host_port(domain, port)
                auth_header = proxy_basic_auth_header(proxy_user, proxy_pass or "") if proxy_user is not None else ""
                req_str = f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nUser-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n{auth_header}Proxy-Connection: Keep-Alive\r\n\r\n"
                s.sendall(req_str.encode('ascii'))
                resp = read_http_response_head(s)
                status_line = resp.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
                status_parts = status_line.split()
                status_code = int(status_parts[1]) if len(status_parts) >= 2 and status_parts[1].isdigit() else 0
                if status_code != 200:
                    raise RuntimeError(f"HTTP CONNECT tunnel failed: {status_line}")
                # Wrap socket with SSL
                ctx = ssl.create_default_context() if use_ssl_verify else ssl._create_unverified_context()
                s = ctx.wrap_socket(s, server_hostname=domain)
            else:
                # Direct HTTP request through proxy: request URI must be absolute
                pass

        # Send HTTP GET request
        if ptype == "http" and not is_https:
            request_uri = url
        else:
            request_uri = path
            
        req_headers = (
            f"GET {request_uri} HTTP/1.1\r\n"
            f"Host: {domain}\r\n"
            f"User-Agent: Mozilla/5.0 vpngate-openvpn-manager/2.0\r\n"
            f"Accept: text/plain,*/*\r\n"
            f"{proxy_basic_auth_header(proxy_user, proxy_pass or '') if ptype == 'http' and not is_https and proxy_user is not None else ''}"
            f"Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode('utf-8'))

        # Read response
        response_data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_data += chunk
            if len(response_data) > 10 * 1024 * 1024: # max 10MB safety guard
                break
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # Parse HTTP response
    header_end = response_data.find(b"\r\n\r\n")
    if header_end == -1:
        raise RuntimeError("Invalid HTTP response format")
    
    headers_part = response_data[:header_end].decode('utf-8', errors='replace')
    body_part = response_data[header_end+4:]

    # Check for HTTP status code
    lines = headers_part.splitlines()
    if not lines:
        raise RuntimeError("Empty response headers")
    status_line = lines[0]
    status_parts = status_line.split()
    if len(status_parts) >= 2:
        try:
            status_code = int(status_parts[1])
            if status_code != 200:
                raise RuntimeError(f"HTTP Server returned status {status_code}: {status_line}")
        except ValueError:
            pass

    # Handle chunked transfer encoding
    is_chunked = False
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            if k.strip().lower() == "transfer-encoding" and "chunked" in v.lower():
                is_chunked = True
                break

    if is_chunked:
        decoded = b""
        idx = 0
        while idx < len(body_part):
            c_end = body_part.find(b"\r\n", idx)
            if c_end == -1:
                break
            chunk_size_str = body_part[idx:c_end].split(b";")[0].strip()
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError:
                break
            if chunk_size == 0:
                break
            idx = c_end + 2
            decoded += body_part[idx : idx + chunk_size]
            idx += chunk_size + 2
        body_part = decoded

    return body_part.decode('utf-8', errors='replace')

def _get_upstream_from_config() -> tuple[str | None, str | None, int | None, str | None, str | None]:
    try:
        ui_cfg = _cached_load_ui_config()
        up = ui_cfg.get("upstream_proxy", {})
        if up.get("enabled") and up.get("host") and up.get("port"):
            return (
                up.get("type", "socks"),
                up["host"],
                int(up["port"]),
                up.get("user") or None,
                up.get("pass") or None
            )
    except Exception:
        pass
    return None, None, None, None, None

def fetch_api_text(url: str | None = None, use_ssl_verify: bool = True) -> str:
    if url is None:
        url = API_URL
    
    ptype, phost, pport = vpn_utils.get_upstream_proxy()
    proxy_user, proxy_pass = None, None
    
    if not (ptype and phost and pport):
        ptype, phost, pport, proxy_user, proxy_pass = _get_upstream_from_config()
    
    if ptype and phost and pport:
        try:
            print(f"[fetch_api_text] 使用上游代理 ({ptype}://{phost}:{pport}) 获取 API...", flush=True)
            return fetch_api_text_via_proxy(url, ptype, phost, pport, use_ssl_verify, proxy_user, proxy_pass)
        except Exception as e:
            print(f"[fetch_api_text] 通过代理获取 API 失败: {e}，尝试直连...", flush=True)
            log_to_json("WARNING", "Main", f"使用代理 {ptype}://{phost}:{pport} 获取 API 失败: {e}")

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Mozilla/5.0 vpngate-openvpn-manager/2.0",
            "Accept": "text/plain,*/*",
        },
    )
    if url.startswith("https://") and not use_ssl_verify:
        import ssl
        ctx = ssl._create_unverified_context()
        with urllib.request.urlopen(request, timeout=12, context=ctx) as response:
            return response.read().decode("utf-8", errors="replace")
    else:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.read().decode("utf-8", errors="replace")

def parse_vpngate_rows(text: str) -> list[dict[str, str]]:
    lines = [line for line in text.splitlines() if line and not line.startswith("*")]
    if lines and lines[0].startswith("#"):
        lines[0] = lines[0][1:]
    return list(csv.DictReader(lines))

def decode_config(encoded: str) -> str:
    return base64.b64decode(encoded.encode("ascii"), validate=False).decode("utf-8", errors="replace")

def load_blacklist() -> dict[str, dict[str, Any]]:
    now = time.time()
    raw = read_json(BLACKLIST_FILE, {})
    if not isinstance(raw, dict):
        return {}
    cleaned: dict[str, dict[str, Any]] = {}
    changed = False
    for key, entry in raw.items():
        if not isinstance(entry, dict):
            changed = True
            continue
        until = float(entry.get("until", 0) or 0)
        if until and until > now:
            cleaned[str(key)] = entry
        else:
            changed = True
    if changed:
        write_json(BLACKLIST_FILE, cleaned)
    return cleaned

def mark_blacklisted(node: dict[str, Any], message: str) -> None:
    node_id = str(node.get("id") or "").strip()
    if not node_id:
        return
    blacklist = load_blacklist()
    now = time.time()
    blacklist[node_id] = {
        "id": node_id,
        "ip": node.get("ip") or node.get("remote_host") or "",
        "country": node.get("country", ""),
        "reason": message,
        "marked_at": now,
        "until": now + INVALID_BACKOFF_SECONDS,
    }
    write_json(BLACKLIST_FILE, blacklist)

def row_to_node(row: dict[str, str], config_text: str) -> dict[str, Any]:
    ip = row.get("IP", "")
    country_short = row.get("CountryShort", "")
    remote_host, remote_port, proto = vpn_utils.parse_remote(config_text, ip)
    node_id = safe_name("_".join([country_short or "XX", ip or remote_host, str(remote_port), proto]))
    config_path = CONFIG_DIR / f"{node_id}.ovpn"
    
    country_long = row.get("CountryLong", "")
    country_zh = vpn_utils.COUNTRY_TRANSLATIONS.get(country_long, vpn_utils.COUNTRY_TRANSLATIONS.get(country_long.strip(), country_long))
    return {
        "id": node_id,
        "country": country_zh,
        "country_en": country_long,
        "country_short": country_short,
        "host_name": row.get("HostName", ""),
        "ip": ip,
        "score": parse_int(row.get("Score")),
        "ping": parse_int(row.get("Ping")),
        "speed": parse_int(row.get("Speed")),
        "sessions": parse_int(row.get("NumVpnSessions")),
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
        "latency_ms": 0,
        "config_file": str(config_path),
        "config_text": config_text,
        "proto": proto,
        "remote_host": remote_host,
        "remote_port": remote_port,
        "fetched_at": time.time(),
        "probe_status": "not_checked",
        "probe_message": "",
        "probed_at": 0,
    }

def fetch_candidates() -> list[dict[str, Any]]:
    blacklist = load_blacklist()
    candidates: list[dict[str, Any]] = []
    seen_ips: dict[str, dict[str, Any]] = {}  # ip -> node（保留质量更高的）
    last_err = None

    # 1. 拉取 VPNGate 官方 API
    log_to_json("INFO", "Main", "开始拉取官方 API 节点列表...")
    vpngate_nodes = _fetch_vpngate_nodes(blacklist, seen_ips)
    candidates.extend(vpngate_nodes)

    # 2. 拉取 PublicVPNList（可选，带超时保护）
    try:
        import publicvpnlist as pvl
        log_to_json("INFO", "Main", "开始拉取 PublicVPNList 节点列表...")
        pvl_nodes: list[dict[str, Any]] = []
        pvl_error: list[str] = []

        def _pvl_worker() -> None:
            try:
                result = pvl.fetch_publicvpnlist_nodes()
                pvl_nodes.extend(result)
            except Exception as exc:
                pvl_error.append(str(exc))

        t = threading.Thread(target=_pvl_worker, daemon=True)
        t.start()
        t.join(timeout=120)
        if t.is_alive():
            log_to_json(
                "WARNING",
                "Main",
                "PublicVPNList 拉取超时 (120s)，已跳过该来源",
            )
            print("[fetch_candidates] PublicVPNList 拉取超时，跳过", flush=True)
        elif pvl_error:
            raise RuntimeError(pvl_error[0])
        else:
            _merge_nodes(pvl_nodes, seen_ips, candidates)
            log_to_json("INFO", "Main", f"PublicVPNList 获取 {len(pvl_nodes)} 个节点")
    except Exception as e:
        print(f"[fetch_candidates] PublicVPNList 拉取失败: {e}", flush=True)
        log_to_json("WARNING", "Main", f"PublicVPNList 拉取失败: {e}")

    if not candidates:
        err_msg = "所有节点来源均未获取到有效节点"
        print(f"[错误代码 1001] {err_msg}", flush=True)
        log_to_json("ERROR", "Main", f"[错误代码 1001] {err_msg}")
        set_state(
            last_fetch_status="error",
            last_fetch_message=err_msg,
        )
        raise RuntimeError(err_msg)

    set_state(
        last_fetch_at=time.time(),
        last_fetch_status="ok",
        last_fetch_message=f"Fetched {len(candidates)} unique candidates across multiple sources.",
        blacklisted_nodes=len(blacklist),
    )
    log_to_json("INFO", "Main", f"成功获取节点，共 {len(candidates)} 个候选节点")
    return candidates


def _fetch_vpngate_nodes(blacklist: dict[str, Any], seen_ips: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """拉取 VPNGate 官方 API 节点"""
    nodes: list[dict[str, Any]] = []
    has_cache = len(cached_nodes()) > 0
    max_attempts = 1 if has_cache else 3

    attempts_targets = [(API_URL, True), (API_URL, False)]
    if API_URL.startswith("https://"):
        attempts_targets.append((API_URL.replace("https://", "http://"), True))

    last_err = None
    for url, verify_ssl in attempts_targets:
        for i in range(max_attempts):
            if i > 0:
                backoff = min(1.5 * (2 ** (i - 1)), 30)
                print(f"[fetch_candidates] 第 {i+1} 次重试等待 {backoff:.1f}s...", flush=True)
                time.sleep(backoff)
            try:
                api_text = fetch_api_text(url, verify_ssl)
                rows = parse_vpngate_rows(api_text)
                for row in rows[:MAX_SCAN_ROWS]:
                    ip = row.get("IP", "")
                    if not ip or ip in seen_ips:
                        continue
                    encoded = row.get("OpenVPN_ConfigData_Base64", "")
                    if not encoded:
                        continue
                    try:
                        config_text = decode_config(encoded)
                        node = row_to_node(row, config_text)
                    except Exception as row_exc:
                        print(f"[fetch_candidates] 跳过损坏的节点配置记录: {row_exc}", flush=True)
                        log_to_json("WARNING", "Main", f"跳过损坏的节点配置记录: {row_exc}")
                        continue
                    entry = blacklist.get(node["id"])
                    if entry and float(entry.get("until", 0) or 0) > time.time():
                        continue
                    nodes.append(node)
                    seen_ips[ip] = node
                if nodes:
                    return nodes
            except Exception as e:
                last_err = e
                print(f"[fetch_candidates] 拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}", flush=True)
                log_to_json("WARNING", "Main", f"拉取失败 (URL: {url}, 验证: {verify_ssl}): {e}")
        if nodes:
            break

    if not nodes and last_err:
        err_code, diag_msg = vpn_utils.diagnose_api_failure(API_URL)
        full_err_msg = f"获取官方 API 节点最终失败: {last_err} | 诊断结果: {diag_msg}"
        print(f"[错误代码 {err_code}] {full_err_msg}", flush=True)
        log_to_json("ERROR", "Main", f"[错误代码 {err_code}] {full_err_msg}")
        set_state(
            last_fetch_status="error",
            last_fetch_error_code=err_code,
            last_fetch_message=diag_msg,
        )
    return nodes


def _merge_nodes(
    new_nodes: list[dict[str, Any]],
    seen_ips: dict[str, dict[str, Any]],
    candidates: list[dict[str, Any]],
) -> None:
    """合并新节点到候选池，按 IP 去重，保留质量更高的"""
    for node in new_nodes:
        ip = node.get("ip", "")
        if not ip:
            continue
        existing = seen_ips.get(ip)
        if existing is None:
            candidates.append(node)
            seen_ips[ip] = node
            continue

        # 比较质量：优先保留 speed 更高 或 latency 更低 的
        new_speed = _safe_float(node.get("speed"), 0)
        old_speed = _safe_float(existing.get("speed"), 0)
        new_latency = _safe_int(node.get("latency_ms"), 9999)
        old_latency = _safe_int(existing.get("latency_ms"), 9999)

        if new_speed > old_speed or new_latency < old_latency:
            candidates.remove(existing)
            candidates.append(node)
            seen_ips[ip] = node


def _safe_float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def _safe_int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (ValueError, TypeError):
        return default

def cached_nodes() -> list[dict[str, Any]]:
    return read_nodes()

_openvpn_version = None

def split_openvpn_command() -> list[str]:
    try:
        return shlex.split(OPENVPN_CMD, posix=(os.name != "nt")) or ["openvpn"]
    except ValueError as exc:
        raise RuntimeError(f"OPENVPN_CMD 配置无法解析: {exc}") from exc

def get_openvpn_version() -> float:
    global _openvpn_version
    if _openvpn_version is not None:
        return _openvpn_version
    try:
        cmd = split_openvpn_command()
        res = subprocess.run(cmd + ["--version"], capture_output=True, text=True, timeout=2)
        match = re.search(r"OpenVPN\s+(\d+\.\d+)", res.stdout or res.stderr)
        if match:
            _openvpn_version = float(match.group(1))
            return _openvpn_version
    except Exception:
        pass
    _openvpn_version = 2.4
    return _openvpn_version

def openvpn_command(config_file: str, route_nopull: bool, dev: str = "tun0") -> list[str]:
    command = split_openvpn_command()
    command.extend(
        [
            "--config",
            config_file,
            "--dev",
            dev,
            "--dev-type",
            "tun",
            "--pull-filter",
            "ignore",
            "route-ipv6",
            "--pull-filter",
            "ignore",
            "ifconfig-ipv6",
            "--route-delay",
            "2",
            "--connect-retry-max",
            "1",
            "--connect-timeout",
            "15",
            "--auth-user-pass",
            str(AUTH_FILE),
            "--auth-nocache",
        ]
    )
    
    version = get_openvpn_version()
    if version >= 2.5:
        command.extend(["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])
    else:
        command.extend(["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"])

    command.extend(["--verb", "3"])
    
    if os.path.exists("/etc/ssl/certs"):
        command.extend(["--capath", "/etc/ssl/certs"])
    
    try:
        content = Path(config_file).read_text(encoding="utf-8", errors="replace")
        if vpn_utils.is_config_tcp(content):
            ptype, host, port = vpn_utils.get_upstream_proxy()
            auth_file = upstream_proxy_auth_file()
            if ptype == "socks" and host and port:
                command.extend(["--socks-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
            elif ptype == "http" and host and port:
                command.extend(["--http-proxy", host, str(port)])
                if auth_file:
                    command.append(auth_file)
    except Exception:
        pass
        
    if route_nopull:
        command.append("--route-nopull")
    return command

def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()

def kill_existing_openvpn_processes() -> None:
    if not sys.platform.startswith("linux"):
        return
    try:
        own_markers = [
            str(DATA_DIR),
            str(CONFIG_DIR),
            str(AUTH_FILE),
            str(UPSTREAM_PROXY_AUTH_FILE),
        ]
        killed_pids: list[int] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            return
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            pid = int(proc_dir.name)
            if pid == os.getpid():
                continue
            try:
                raw = (proc_dir / "cmdline").read_bytes()
            except OSError:
                continue
            if not raw:
                continue
            args = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
            if not args:
                continue
            cmdline = " ".join(args)
            executable = Path(args[0]).name.lower()
            if "openvpn" not in executable and "openvpn" not in cmdline.lower():
                continue
            if any(marker and marker in cmdline for marker in own_markers):
                try:
                    os.kill(pid, signal.SIGTERM)
                    killed_pids.append(pid)
                except ProcessLookupError:
                    pass
                except PermissionError:
                    print(f"[Cleanup] No permission to terminate OpenVPN PID {pid}", flush=True)
        if killed_pids:
            time.sleep(0.5)
            for pid in killed_pids:
                try:
                    raw = (proc_root / str(pid) / "cmdline").read_bytes()
                    cmdline = " ".join(part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part)
                    if any(marker and marker in cmdline for marker in own_markers):
                        os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                except (OSError, PermissionError):
                    pass
            print(f"[Cleanup] Terminated AimiliVPN OpenVPN processes: {killed_pids}", flush=True)
    except Exception as e:
        print(f"[Cleanup Error] Failed to kill existing OpenVPN processes: {e}", flush=True)

def update_handshake_status(line_lower: str) -> None:
    status_map = {
        "resolving": ("解析域名", "正在解析服务器域名与 IP 地址..."),
        "udp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tcp link local": ("物理连接", "已创建本地套接字，开始尝试发送数据包..."),
        "tls: initial packet": ("证书握手", "已成功发送首包，正在与远程服务器建立 TLS 安全通道..."),
        "verify ok": ("证书校验", "服务器证书校验成功，正在进行身份验证..."),
        "peer connection initiated": ("协商加密", "控制通道已建立，已初始化与服务器的加密对等连接..."),
        "push_request": ("请求配置", "正在向服务器发送 PUSH_REQUEST 请求配置参数与 IP 分配..."),
        "push_reply": ("应用配置", "已接收服务器 PUSH_REPLY，获取到 IP 分配，正在准备配置网卡..."),
        "tun/tap device": ("创建网卡", "正在创建虚拟通道并打开 TUN 虚拟网卡设备..."),
        "do_ifconfig": ("网卡配置", "正在为虚拟网卡配置 IP 地址及相关网络属性..."),
    }
    for key, (short_status, detailed_desc) in status_map.items():
        if key in line_lower:
            set_state(active_node_latency=short_status, last_check_message=detailed_desc)
            break

def run_openvpn_until_ready(config_file: str, keep_alive: bool, route_nopull: bool, timeout: int | None = None, dev: str = "tun0") -> tuple[bool, str, subprocess.Popen[str] | None]:
    limit = timeout if timeout is not None else OPENVPN_TEST_TIMEOUT_SECONDS
    try:
        process = subprocess.Popen(
            openvpn_command(config_file, route_nopull, dev),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd=str(ROOT_DIR),
        )
    except FileNotFoundError:
        return False, "[错误代码 2001] [ERR_OVPN_CMD_NOT_FOUND] 未找到 openvpn 命令。原因: 系统未安装 openvpn，或 PATH 环境变量不正确。", None
    except OSError as exc:
        return False, f"[错误代码 2002] [ERR_OVPN_START_FAILED] openvpn 启动失败: {exc}。原因: 系统权限不足或配置冲突。", None

    lines: queue.Queue[str | None] = queue.Queue()
    startup_done = [False]
    openvpn_logs: list[str] = []

    def reader() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            line_str = line.rstrip()
            if not startup_done[0]:
                openvpn_logs.append(line_str)
                lines.put(line_str)
            else:
                if keep_alive:
                    print(f"[OpenVPN] {line_str}", flush=True)
                    level = "INFO"
                    line_lower = line_str.lower()
                    if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
                        level = "ERROR"
                    elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
                        level = "WARNING"
                    log_to_json(level, "VPN", f"[OpenVPN] {line_str}")
        if not startup_done[0]:
            lines.put(None)

    threading.Thread(target=reader, daemon=True).start()
    started = time.time()
    tail: list[str] = []
    ok = False
    message = "OpenVPN did not complete initialization."
    while time.time() - started < limit:
        try:
            line = lines.get(timeout=0.5)
        except queue.Empty:
            if process.poll() is not None:
                break
            continue
        if line is None:
            break
        if line:
            tail.append(line)
            tail = tail[-50:]
            if keep_alive:
                print(f"[OpenVPN] {line}", flush=True)
        lower = line.lower()
        if keep_alive:
            update_handshake_status(lower)
        if "initialization sequence completed" in lower:
            ok = True
            message = f"OpenVPN connected in {int((time.time() - started) * 1000)} ms."
            break
        if "auth_failed" in lower or "authentication failed" in lower:
            message = "AUTH_FAILED"
            break
        if "cannot ioctl" in lower or "fatal error" in lower:
            message = line[-220:]
            break
    else:
        message = f"OpenVPN timeout after {limit}s."

    # Bulk write accumulated startup logs
    for line_str in openvpn_logs:
        level = "INFO"
        line_lower = line_str.lower()
        if "error" in line_lower or "failed" in line_lower or "cannot" in line_lower or "fatal" in line_lower or "permission denied" in line_lower:
            level = "ERROR"
        elif "warning" in line_lower or "warn" in line_lower or "deprecated" in line_lower:
            level = "WARNING"
        log_to_json(level, "VPN", f"[OpenVPN] {line_str}")

    if not ok:
        err_code, diag_msg = vpn_utils.diagnose_openvpn_failure(tail)
        message = f"[错误代码 {err_code}] {diag_msg} (原始日志尾部: {tail[-1][-100:] if tail else '无'})"
    startup_done[0] = True
    if not keep_alive or not ok:
        stop_process(process)
        process = None
    return ok, message, process


def setup_policy_routing(interface: str = "tun0") -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    try:
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
    except Exception:
        pass
    
    success = False
    for attempt in range(1, 4):
        try:
            subprocess.run(["ip", "route", "add", "default", "dev", interface, "table", "100"], check=True, timeout=2)
            subprocess.run(["ip", "rule", "add", "oif", interface, "table", "100"], check=True, timeout=2)
            # 配置反向路径过滤 rp_filter 为 loose 模式 (2)，防止回包被内核静默丢弃
            for proc_path in ["all", "default", interface]:
                try:
                    subprocess.run(["sysctl", "-w", f"net.ipv4.conf.{proc_path}.rp_filter=2"], capture_output=True, timeout=2)
                except Exception:
                    pass
            print(f"[policy_routing] Enabled policy routing for interface {interface} (attempt {attempt} success)", flush=True)
            success = True
            break
        except Exception as e:
            print(f"[policy_routing] Attempt {attempt} failed to enable policy routing: {e}", flush=True)
            time.sleep(1)
            
    if not success:
        print("[路由配置失败] [错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由，这可能会导致通过 VPN 接口的出站路由无法正常解析。请检查系统是否支持策略路由、iproute2 工具是否完整，以及是否具有 root 权限。", flush=True)
        log_to_json("ERROR", "Routing", "[错误代码 3003] [ERR_ROUTE_TABLE_ADD_FAILED] 策略路由配置失败。原因: 无法向路由表 100 添加默认路由")

def cleanup_policy_routing() -> None:
    try:
        subprocess.run(["ip", "rule", "del", "table", "100"], capture_output=True, timeout=2)
        subprocess.run(["ip", "route", "flush", "table", "100"], capture_output=True, timeout=2)
        print("[policy_routing] Cleared policy routing table 100", flush=True)
    except Exception:
        pass

def stop_active_openvpn() -> None:
    global active_openvpn_process, active_openvpn_node_id
    with lock:
        cleanup_policy_routing()
        config_to_delete = None
        if active_openvpn_node_id:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == active_openvpn_node_id), None)
            if node:
                config_to_delete = node.get("config_file")
                
        stop_process(active_openvpn_process)
        active_openvpn_process = None
        active_openvpn_node_id = ""
        kill_existing_openvpn_processes()
        
        if config_to_delete:
            try:
                path = Path(config_to_delete)
                if path.exists():
                    path.unlink()
            except Exception:
                pass

def active_openvpn_running() -> bool:
    return active_openvpn_process is not None and active_openvpn_process.poll() is None

def sort_all_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    available_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "available" or n.get("active")],
        key=lambda n: (
            0 if n.get("ip_type") in ("residential", "mobile") else 1,
            parse_int(n.get("latency_ms")) or 999999,
            -parse_int(n.get("score"))
        )
    )
    untested_nodes = sorted(
        [n for n in nodes if n.get("probe_status") in ("not_checked", "testing") and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), parse_int(n.get("ping")))
    )
    unavailable_nodes = sorted(
        [n for n in nodes if n.get("probe_status") == "unavailable" and not n.get("active")],
        key=lambda n: (-parse_int(n.get("score")), -float(n.get("probed_at", 0)))
    )
    return available_nodes + untested_nodes + unavailable_nodes

def apply_routing_filters(
    nodes: list[dict[str, Any]],
    ui_cfg: dict[str, Any],
    include_unknown_ip_type: bool = False,
) -> list[dict[str, Any]]:
    candidates = list(nodes)
    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_region" and target_country:
        candidates = [
            n for n in candidates
            if country_matches(n.get("country"), target_country)
        ]
    elif routing_mode == "favorites":
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        candidates = [n for n in candidates if n.get("id") in fav_ids]

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    if routing_ip_type == "residential":
        candidates = [
            n for n in candidates
            if n.get("ip_type") in ("residential", "mobile")
            or (include_unknown_ip_type and not n.get("ip_type"))
        ]
    elif routing_ip_type == "hosting":
        candidates = [
            n for n in candidates
            if n.get("ip_type") == "hosting"
            or (include_unknown_ip_type and not n.get("ip_type"))
        ]

    return candidates

def normalized_country_name(country: Any) -> str:
    value = str(country or "").strip()
    return vpn_utils.COUNTRY_TRANSLATIONS.get(value, value)

def country_matches(node_country: Any, target_country: Any) -> bool:
    return bool(target_country) and normalized_country_name(node_country) == normalized_country_name(target_country)

def probe_priority_key(node: dict[str, Any]) -> tuple[int, int, int, int]:
    ping = parse_int(node.get("ping")) or 999999
    return (
        ping,
        -parse_int(node.get("score")),
        -parse_int(node.get("speed")),
        parse_int(node.get("sessions")),
    )

def current_fixed_node_id(ui_cfg: dict[str, Any]) -> str:
    if active_openvpn_node_id:
        return active_openvpn_node_id
    nodes = read_nodes()
    active_node = next((n for n in nodes if n.get("active") and n.get("id")), None)
    if active_node:
        return str(active_node.get("id") or "")
    return str(ui_cfg.get("fixed_node_id") or "").strip()

def validate_node_allowed_by_routing(node: dict[str, Any], ui_cfg: dict[str, Any]) -> None:
    routing_mode = ui_cfg.get("routing_mode", "auto")
    node_id = str(node.get("id") or "")

    if routing_mode == "fixed_region":
        target_country = ui_cfg.get("force_country", "")
        if target_country and not country_matches(node.get("country"), target_country):
            raise RuntimeError(f"当前已锁定国家【{target_country}】，不能连接其他国家节点")
    elif routing_mode == "favorites":
        fav_ids = set(ui_cfg.get("favorite_node_ids", []))
        if node_id not in fav_ids:
            raise RuntimeError("当前处于仅用收藏模式，不能连接未收藏节点")

    routing_ip_type = ui_cfg.get("routing_ip_type", "all")
    node_ip_type = node.get("ip_type")
    if routing_ip_type == "residential" and node_ip_type not in ("residential", "mobile"):
        raise RuntimeError("当前已锁定住宅 IP 出站，不能连接非住宅节点")
    if routing_ip_type == "hosting" and node_ip_type != "hosting":
        raise RuntimeError("当前已锁定机房 IP 出站，不能连接非机房节点")

def enforce_active_node_allowed_by_routing(ui_cfg: dict[str, Any], reason: str = "路由规则已更新") -> str | None:
    active_id = active_openvpn_node_id
    if not active_id:
        return None

    nodes = read_nodes()
    active_node = next((item for item in nodes if item.get("id") == active_id), None)
    if not active_node:
        clear_active_connection_state(f"{reason}，当前活动节点已不在节点列表中，已断开连接")
        return "当前活动节点已不在节点列表中，已断开连接"

    try:
        validate_node_allowed_by_routing(active_node, ui_cfg)
        return None
    except Exception as exc:
        msg = f"{reason}，当前活动节点 {active_id} 不符合新规则，已断开连接: {exc}"
        print(f"[路由规则] {msg}", flush=True)
        log_to_json("WARNING", "Routing", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(
            active_openvpn_node_id="",
            active_node_latency="无活动连接",
            proxy_ok=False,
            proxy_ip="-",
            proxy_latency_ms=0,
            proxy_error=msg,
            last_check_message=msg,
        )

        if ui_cfg.get("connection_enabled", True) and ui_cfg.get("routing_mode") != "fixed_ip":
            threading.Thread(target=auto_switch_node, daemon=True).start()
        return msg

def reconnect_fixed_node_if_needed(ui_cfg: dict[str, Any]) -> bool:
    global is_connecting
    if ui_cfg.get("routing_mode") != "fixed_ip" or active_openvpn_running():
        return False
    target_id = current_fixed_node_id(ui_cfg)
    if not target_id:
        return False
    nodes = read_nodes()
    if not any(n.get("id") == target_id for n in nodes):
        return False

    print(f"[维护线程] 固定 IP 模式下 OpenVPN 未运行，正在重新拉起同一节点: {target_id}", flush=True)
    previous_connecting = is_connecting
    is_connecting = False
    try:
        connect_node(target_id)
        return active_openvpn_running()
    except Exception as e:
        print(f"[维护线程] 重新拉起固定节点 {target_id} 失败: {e}", flush=True)
        return False
    finally:
        is_connecting = previous_connecting

active_test_indexes = set()
test_indexes_lock = threading.Lock()

def get_free_test_index() -> int:
    with test_indexes_lock:
        for idx in range(2, 100):
            if idx not in active_test_indexes:
                active_test_indexes.add(idx)
                return idx
        raise RuntimeError("没有可用的 OpenVPN 测试网卡编号，请稍后重试")

def release_test_index(idx: int) -> None:
    with test_indexes_lock:
        active_test_indexes.discard(idx)

def test_config_path(node_id: str) -> Path:
    safe_id = safe_name(node_id)
    return CONFIG_DIR / f".test_{safe_id}_{uuid.uuid4().hex}.ovpn"

def test_node_by_id(node_id: str) -> dict[str, Any]:
    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")
    config_text = node.get("config_text") or ""
    h = str(node.get("remote_host") or node.get("ip"))
    p = parse_int(node.get("remote_port"))
    fallback_ping = parse_int(node.get("ping"))

    if not config_text.strip():
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        ok = latency > 0
        message = "端口开放，节点可达" if ok else "端口关闭或不可达"
        enriched = {
            "id": node_id,
            "ip": h,
            "remote_host": h,
            "remote_port": p,
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }
        if ok:
            vpn_utils.enrich_ip_info([enriched])
        with lock:
            nodes = read_nodes()
            node = next((item for item in nodes if item.get("id") == node_id), None)
            if node:
                node["latency_ms"] = latency
                node["probe_status"] = "available" if ok else "unavailable"
                node["probe_message"] = message
                node["probed_at"] = time.time()
                if ok:
                    node["owner"] = enriched["owner"]
                    node["asn"] = enriched["asn"]
                    node["as_name"] = enriched["as_name"]
                    node["location"] = enriched["location"]
                    node["ip_type"] = enriched["ip_type"]
                    node["quality"] = enriched["quality"]
                sorted_nodes = sort_all_nodes(nodes)
                write_json(NODES_FILE, sorted_nodes)
                res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
                return res
        return {
            "id": node_id,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": enriched["owner"],
            "asn": enriched["asn"],
            "as_name": enriched["as_name"],
            "location": enriched["location"],
            "ip_type": enriched["ip_type"],
            "quality": enriched["quality"],
        }

    temp_path = test_config_path(node_id)
    try:
        CONFIG_DIR.mkdir(exist_ok=True, parents=True)
        temp_path.write_text(config_text, encoding="utf-8")
    except Exception as e:
        raise RuntimeError(f"Failed to write temp config file: {e}")

    latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
    
    idx = None
    try:
        idx = get_free_test_index()
        ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=f"tun{idx}")
    finally:
        if idx is not None:
            release_test_index(idx)
        try:
            if temp_path.exists():
                temp_path.unlink()
        except Exception:
            pass

    temp_node = {
        "id": node_id,
        "ip": h,
        "remote_host": h,
        "remote_port": p,
        "owner": "",
        "asn": "",
        "as_name": "",
        "location": "",
        "ip_type": "",
        "quality": "",
    }
    if ok:
        vpn_utils.enrich_ip_info([temp_node])

    with lock:
        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if node:
            node["latency_ms"] = latency
            node["probe_status"] = "available" if ok else "unavailable"
            node["probe_message"] = message
            node["probed_at"] = time.time()
            if ok:
                node["owner"] = temp_node["owner"]
                node["asn"] = temp_node["asn"]
                node["as_name"] = temp_node["as_name"]
                node["location"] = temp_node["location"]
                node["ip_type"] = temp_node["ip_type"]
                node["quality"] = temp_node["quality"]
            
            sorted_nodes = sort_all_nodes(nodes)
            write_json(NODES_FILE, sorted_nodes)
            res = next((item for item in sorted_nodes if item.get("id") == node_id), node)
            return res
        else:
            return {}

def test_multiple_nodes(node_ids: list[str]) -> list[dict[str, Any]]:
    with lock:
        nodes = read_nodes()
        to_test = [n for n in nodes if n.get("id") in node_ids]
        
    def test_worker(args: tuple[int, dict[str, Any]]) -> dict[str, Any]:
        idx, n_info = args
        node_id = n_info["id"]
        config_text = n_info.get("config_text") or ""
        h = str(n_info.get("remote_host") or n_info.get("ip"))
        p = parse_int(n_info.get("remote_port"))
        fallback_ping = parse_int(n_info.get("ping"))

        if not config_text.strip():
            latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
            ok = latency > 0
            message = "端口开放，节点可达" if ok else "端口关闭或不可达"
            enriched = {
                "id": node_id,
                "ip": h,
                "remote_host": h,
                "remote_port": p,
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }
            if ok:
                vpn_utils.enrich_ip_info([enriched])
            return {
                "id": node_id,
                "latency_ms": latency,
                "probe_status": "available" if ok else "unavailable",
                "probe_message": message,
                "probed_at": time.time(),
                "owner": enriched["owner"],
                "asn": enriched["asn"],
                "as_name": enriched["as_name"],
                "location": enriched["location"],
                "ip_type": enriched["ip_type"],
                "quality": enriched["quality"],
            }

        temp_path = test_config_path(node_id)
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            temp_path.write_text(config_text, encoding="utf-8")
        except Exception as e:
            return {
                "id": node_id,
                "latency_ms": 0,
                "probe_status": "unavailable",
                "probe_message": f"Failed to write configuration: {e}",
                "probed_at": time.time(),
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
            }
            
        latency = vpn_utils.ping_latency_ms(h, p, fallback_ping)
        tun_idx = None
        try:
            tun_idx = get_free_test_index()
            dev_name = f"tun{tun_idx}"
            ok, message, _ = run_openvpn_until_ready(str(temp_path), keep_alive=False, route_nopull=True, timeout=12, dev=dev_name)
        finally:
            if tun_idx is not None:
                release_test_index(tun_idx)
            try:
                if temp_path.exists():
                    temp_path.unlink()
            except Exception:
                pass
            
        temp_node = {
            "id": node_id,
            "ip": n_info.get("ip") or h,
            "remote_host": h,
            "remote_port": p,
            "latency_ms": latency,
            "probe_status": "available" if ok else "unavailable",
            "probe_message": message,
            "probed_at": time.time(),
            "owner": "",
            "asn": "",
            "as_name": "",
            "location": "",
            "ip_type": "",
            "quality": "",
        }
        return temp_node

    updated_nodes_map = {}
    max_workers = min(5, max(1, len(to_test)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_worker, (idx, n)): n["id"] for idx, n in enumerate(to_test)}
        for future in concurrent.futures.as_completed(futures):
            nid = futures[future]
            try:
                res = future.result()
                updated_nodes_map[nid] = res
            except Exception as e:
                updated_nodes_map[nid] = {
                    "id": nid,
                    "probe_status": "unavailable",
                    "probe_message": f"Test exception: {e}",
                    "latency_ms": 0
                }
                
    # 批量查询并丰富可用节点的地理及 ISP 信息，防止并发时被定位 API 接口限流
    successful_nodes = [res for res in updated_nodes_map.values() if res.get("probe_status") == "available"]
    if successful_nodes:
        try:
            vpn_utils.enrich_ip_info(successful_nodes)
        except Exception as ee:
            print(f"[test_multiple_nodes] 批量富化 IP 失败: {ee}", flush=True)

    with lock:
        current_nodes = read_nodes()
        for n in current_nodes:
            nid = n.get("id")
            if nid in updated_nodes_map:
                n.update(updated_nodes_map[nid])
        sorted_nodes = sort_all_nodes(current_nodes)
        write_json(NODES_FILE, sorted_nodes)
        
    return list(updated_nodes_map.values())

def auto_switch_node(attempt: int = 0) -> None:
    if attempt >= 3:
        print("[自动切换] 连续切换失败已达 3 次，停止切换以防止主线程死锁，将在后台重新加载节点...", flush=True)
        return
        
    ui_cfg = load_ui_config()
    connection_enabled = ui_cfg.get("connection_enabled", True)
    if not connection_enabled:
        print("[自动切换] 连接已禁用，不进行自动切换。", flush=True)
        return

    routing_mode = ui_cfg.get("routing_mode", "auto")
    target_country = ui_cfg.get("force_country", "")

    if routing_mode == "fixed_ip":
        print("[自动切换] 当前处于固定 IP 模式，不进行自动连接或切换。", flush=True)
        return

    # Find the next best available node
    with lock:
        nodes = read_nodes()
        candidates = [
            n for n in nodes 
            if n.get("probe_status") == "available" 
            and not n.get("active")
        ]
        candidates = apply_routing_filters(candidates, ui_cfg)
            
        candidates.sort(key=lambda n: (parse_int(n.get("latency_ms")) or 999999, -parse_int(n.get("score"))))
        
    if candidates:
        next_node = candidates[0]
        msg = f"当前连接已失效或代理连通性检测失败，正在自动切换至最佳备用节点: {next_node['id']}"
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("INFO", "VPN", msg)
        try:
            connect_node(next_node["id"])
        except Exception as e:
            err_msg = f"切换到备用节点 {next_node['id']} 失败: {e}，将尝试下一个..."
            print(f"[自动切换] {err_msg}", flush=True)
            log_to_json("WARNING", "VPN", err_msg)
            auto_switch_node(attempt + 1)
    else:
        msg = "没有可用的备选节点，将自动断开并清理当前连接状态，同时在后台异步获取新节点..."
        if routing_mode == "fixed_region" and target_country:
            msg = f"没有可用的【{target_country}】备选节点，已断开连接，将在后台持续尝试获取新节点..."
        print(f"[自动切换] {msg}", flush=True)
        log_to_json("WARNING", "VPN", msg)
        stop_active_openvpn()
        with lock:
            nodes = read_nodes()
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
        set_state(active_openvpn_node_id="", last_check_message=msg)
        
        def bg_fetch_and_switch():
            try:
                # 避免所有节点不可用时连续拉取/测试导致 CPU 与 tun 网卡风暴。
                time.sleep(60)
                maintain_valid_nodes(force=False)
                auto_switch_node(attempt + 1)
            except Exception as e:
                print(f"[自动切换后台补齐] 获取并测试节点失败: {e}", flush=True)
        
        threading.Thread(target=bg_fetch_and_switch, daemon=True).start()

def connect_node(node_id: str) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    node_id = str(node_id or "").strip()
    if not node_id:
        raise ValueError("Node id is required")
    stopped_existing = False
    with lock:
        if is_connecting:
            print("[连接] 正在建立其他连接中，跳过此请求", flush=True)
            raise RuntimeError("当前已有连接或节点检测任务正在运行，请稍后再试")
        is_connecting = True
        set_state(is_connecting=True, active_node_latency="正在连接", last_check_message=f"正在初始化连接配置: {node_id}")
        
    try:
        log_to_json("INFO", "VPN", f"开始连接节点: {node_id}")

        nodes = read_nodes()
        node = next((item for item in nodes if item.get("id") == node_id), None)
        if not node:
            raise ValueError(f"Node not found: {node_id}")

        # 按需下载：publicvpnlist 节点无配置时先下载 ovpn
        if node.get("source") == "publicvpnlist" and not node.get("config_text"):
            # 优先用 data_id 字段，否则从节点 ID 解析（格式 pvl_{data_id}_{ip}_{port}_{proto}）
            data_id = node.get("data_id") or (node_id.split("_", 3)[1] if node_id.startswith("pvl_") and "_" in node_id else None)
            if data_id:
                set_state(active_node_latency="下载配置", last_check_message=f"正在从 PublicVPNList 下载配置文件...")
                print(f"[连接] 按需下载节点配置: {data_id}", flush=True)
                import publicvpnlist as pvl_module
                dl_result = pvl_module.download_node_config(data_id)
                if dl_result:
                    node["config_text"] = dl_result["config_text"]
                    node["remote_host"] = dl_result["remote_host"]
                    node["remote_port"] = dl_result["remote_port"]
                    node["ip"] = dl_result["remote_host"]
                    node["proto"] = dl_result["proto"]
                    config_dir = Path(node.get("config_file", "")).parent or (DATA_DIR / "configs")
                    config_dir.mkdir(exist_ok=True, parents=True)
                    node["config_file"] = str(config_dir / f"{node_id}.ovpn")
                    (config_dir / f"{node_id}.ovpn").write_text(dl_result["config_text"], encoding="utf-8")
                    with lock:
                        for item in nodes:
                            if item.get("id") == node_id:
                                item.update(node)
                        write_json(NODES_FILE, nodes)
                    print(f"[连接] 配置下载完成: {dl_result['remote_host']}:{dl_result['remote_port']}", flush=True)
                else:
                    raise RuntimeError(f"无法下载节点配置，该节点可能已下线")
            else:
                raise RuntimeError("无法解析节点 data_id，无法下载配置")

        ui_cfg = load_ui_config()
        validate_node_allowed_by_routing(node, ui_cfg)
        ui_cfg["connection_enabled"] = True
        if ui_cfg.get("routing_mode") == "fixed_ip":
            ui_cfg["fixed_node_id"] = node_id
        auth_file = DATA_DIR / "ui_auth.json"
        with lock:
            DATA_DIR.mkdir(exist_ok=True, parents=True)
            write_json(auth_file, ui_cfg)
        
        set_state(active_node_latency="清理连接", last_check_message="正在关闭与清理旧的 VPN 连接及网卡...")
        stop_active_openvpn()
        stopped_existing = True

        set_state(active_node_latency="写入配置", last_check_message="正在写入 OpenVPN 节点配置文件...")
        config_path = Path(node["config_file"])
        try:
            CONFIG_DIR.mkdir(exist_ok=True, parents=True)
            config_path.write_text(node.get("config_text") or "", encoding="utf-8")
        except Exception as e:
            raise RuntimeError(f"Failed to write configuration: {e}")

        set_state(active_node_latency="启动核心", last_check_message="正在启动 OpenVPN Core 核心服务并建立连接...")
        ok, message, process = run_openvpn_until_ready(str(node["config_file"]), keep_alive=True, route_nopull=True)
        if not ok or process is None:
            try:
                if config_path.exists():
                    config_path.unlink()
            except Exception:
                pass
            node["probe_status"] = "unavailable"
            node["probe_message"] = message
            for item in nodes:
                item["active"] = False
            write_json(NODES_FILE, nodes)
            log_to_json("ERROR", "VPN", f"连接节点 {node_id} 失败: {message}")
            print(f"[连接核心失败] 无法与 VPN 节点 {node_id} 建立隧道连接！详情: {message}", flush=True)
            set_state(active_openvpn_node_id="", is_connecting=False, active_node_latency="无活动连接", last_check_message=f"连接失败: {message}")
            with lock:
                active_openvpn_node_id = ""
            raise RuntimeError(message)
            
        with lock:
            active_openvpn_process = process
            active_openvpn_node_id = node_id
        
        set_state(active_node_latency="配置路由", last_check_message="正在配置策略路由规则与流量转发...")
        setup_policy_routing("tun0")
        
        global last_active_ping_time, last_active_latency
        last_active_ping_time = time.time()
        last_active_latency = 0
        
        set_state(active_node_latency="测试延迟", last_check_message="正在直连测试代理出口延迟与可用性...")
        try:
            ip = node.get("ip") or node.get("remote_host")
            port = parse_int(node.get("remote_port"))
            fallback = parse_int(node.get("ping"))
            latency = vpn_utils.ping_latency_ms(ip, port, fallback)
            if latency > 0:
                last_active_latency = latency
        except Exception:
            pass
            
        for item in nodes:
            item["active"] = item.get("id") == node_id
            if item["active"]:
                _ph = f"[{LOCAL_PROXY_HOST}]" if ":" in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST
                item["probe_message"] = f"Active node. HTTP proxy: http://{_ph}:{LOCAL_PROXY_PORT}"
        write_json(NODES_FILE, nodes)
        
        set_state(last_check_message="正在测试本地代理出站联通性与出口 IP...")
        res = check_proxy_health()
        if res["ok"]:
            set_state(
                proxy_ok=True,
                proxy_ip=res["ip"],
                proxy_latency_ms=res["latency_ms"],
                proxy_error=""
            )
        else:
            set_state(
                proxy_ok=False,
                proxy_ip="-",
                proxy_latency_ms=0,
                proxy_error=res.get("error", "未知错误")
            )
            
        latency_str = f"{last_active_latency} ms" if last_active_latency > 0 else "检测超时"
        set_state(active_openvpn_node_id=node_id, is_connecting=False, last_check_message=f"Connected {node_id}", active_node_latency=latency_str)
        log_to_json("INFO", "VPN", f"节点 {node_id} 连接成功，出口网卡 tun0 已启用")
        return f"Connected {node_id}"
    except Exception as exc:
        if stopped_existing or (active_openvpn_node_id == node_id and not active_openvpn_running()):
            clear_active_connection_state(f"连接失败: {exc}")
        else:
            set_state(is_connecting=False, last_check_message=f"连接失败: {exc}")
        raise
    finally:
        with lock:
            is_connecting = False


def _batch_download_pvl_configs(nodes_without_config: list[dict[str, Any]]) -> None:
    """后台并行下载 publicvpnlist 节点的 ovpn 配置。"""
    import publicvpnlist as pvl_module
    from concurrent.futures import ThreadPoolExecutor, as_completed

    def _download_one(node: dict[str, Any]) -> bool:
        node_id = node.get("id", "")
        if not node_id:
            return False
        data_id = node.get("data_id") or (node_id.split("_", 3)[1] if node_id.startswith("pvl_") and "_" in node_id else None)
        if not data_id:
            return False
        try:
            result = pvl_module.download_node_config(data_id)
            if not result:
                print(f"[批量下载] {node_id}: 下载失败", flush=True)
                return False
            with lock:
                current = read_nodes()
                for n in current:
                    if n.get("id") == node_id:
                        n["config_text"] = result["config_text"]
                        n["remote_host"] = result["remote_host"]
                        n["remote_port"] = result["remote_port"]
                        n["ip"] = result["remote_host"]
                        n["proto"] = result["proto"]
                        config_dir = Path(n.get("config_file", "")).parent or (DATA_DIR / "configs")
                        config_dir.mkdir(exist_ok=True, parents=True)
                        n["config_file"] = str(config_dir / f"{node_id}.ovpn")
                        (config_dir / f"{node_id}.ovpn").write_text(result["config_text"], encoding="utf-8")
                        break
                write_json(NODES_FILE, current)
            print(f"[批量下载] {node_id}: OK ({result['remote_host']}:{result['remote_port']})", flush=True)
            return True
        except Exception as e:
            print(f"[批量下载] {node_id}: 异常 - {e}", flush=True)
            return False

    print(f"[批量下载] 启动 {len(nodes_without_config)} 个 PublicVPNList 节点的并行下载（最大 10 并发）", flush=True)
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(_download_one, n): n for n in nodes_without_config}
        ok = sum(1 for f in as_completed(futures) if f.result())
        fail = len(futures) - ok
    print(f"[批量下载] 完成: 成功 {ok}, 失败 {fail}", flush=True)


def maintain_valid_nodes(force: bool = False) -> str:
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    ensure_dirs()
    if not maintenance_lock.acquire(blocking=False):
        msg = "节点维护任务正在运行，请稍后再试"
        set_state(last_check_message=msg)
        return msg
    with lock:
        if is_connecting:
            maintenance_lock.release()
            msg = "当前已有连接或节点测试任务正在运行，请稍后再试"
            set_state(last_check_message=msg)
            return msg
        is_connecting = True
    try:
        if force:
            with lock:
                stop_active_openvpn()
            reconnect_fixed_node_if_needed(load_ui_config())
        elif not active_openvpn_running():
            ui_cfg = load_ui_config()
            routing_mode = ui_cfg.get("routing_mode", "auto")
            connection_enabled = ui_cfg.get("connection_enabled", True)
            if connection_enabled:
                if routing_mode == "fixed_ip":
                    reconnect_fixed_node_if_needed(ui_cfg)
                else:
                    has_active_id = False
                    with lock:
                        if active_openvpn_node_id:
                            has_active_id = True
                            stop_active_openvpn()
                    if has_active_id:
                        print("[维护线程] 检测到当前 OpenVPN 进程已意外退出，准备自动切换节点", flush=True)
                        is_connecting = False
                        auto_switch_node()
                        is_connecting = True

        try:
            set_state(is_connecting=True, last_check_message="正在拉取最新的免费 VPN 节点列表...")
            candidates = fetch_candidates()
        except Exception as exc:
            vpn_utils.check_and_fix_dns()
            diag_msg = str(exc)
            if not any(token in diag_msg for token in ["[ERR_", "错误代码"]):
                err_code, raw_diag = vpn_utils.diagnose_api_failure(API_URL)
                diag_msg = f"[错误代码 {err_code}] 获取节点失败: {exc} | 诊断结果: {raw_diag}"
            set_state(last_fetch_at=time.time(), last_fetch_status="error", last_fetch_message=diag_msg)
            candidates = []

        if not candidates:
            return "没有拉取到新节点"

        with lock:
            current_nodes = read_nodes()
            current_by_id = {
                str(n.get("id")): n
                for n in current_nodes
                if n.get("id")
            }

            # 以当前节点为基础，保留所有旧节点，避免节点随时间消失
            merged = list(current_nodes)
            seen_ids = {str(n.get("id")) for n in merged if n.get("id")}

            for cand in candidates:
                cid = str(cand.get("id", ""))
                if not cid:
                    continue
                previous = current_by_id.get(cid)
                if previous:
                    # 已存在的节点：用 candidates 的数据替换，保留 probe 状态
                    for key in [
                        "probe_status",
                        "probe_message",
                        "latency_ms",
                        "probed_at",
                        "owner",
                        "asn",
                        "as_name",
                        "location",
                        "ip_type",
                        "quality",
                        "fraud_score",
                    ]:
                        if previous.get(key) not in (None, ""):
                            cand[key] = previous.get(key)
                    for idx, n in enumerate(merged):
                        if n.get("id") == cid:
                            merged[idx] = cand
                            break
                elif cid not in seen_ids:
                    merged.append(cand)
                    seen_ids.add(cid)

            if len(merged) > 1000:
                merged = merged[:1000]
                
            for n in merged:
                config_path = Path(n["config_file"])
                if not config_path.exists():
                    try:
                        config_path.write_text(n["config_text"], encoding="utf-8")
                    except Exception:
                        pass
                        
            write_json(NODES_FILE, merged)

        # 后台批量下载 publicvpnlist 节点的 ovpn 配置（非阻塞）
        pvl_nodes_without_config = [n for n in merged if n.get("source") == "publicvpnlist" and not n.get("config_text")]
        if pvl_nodes_without_config:
            print(f"[批量下载] 发现 {len(pvl_nodes_without_config)} 个 PublicVPNList 节点缺少配置，启动后台下载", flush=True)
            threading.Thread(
                target=_batch_download_pvl_configs,
                args=(pvl_nodes_without_config,),
                daemon=True,
            ).start()

        initial_tested_ids: set[str] = set()
        ui_cfg = load_ui_config()
        should_fast_connect = (
            ui_cfg.get("connection_enabled", True)
            and ui_cfg.get("routing_mode", "auto") != "fixed_ip"
            and not active_openvpn_running()
        )
        if should_fast_connect:
            with lock:
                current_nodes = read_nodes()
                fast_candidates = [
                    n for n in current_nodes
                    if not n.get("active") and n.get("probe_status") != "unavailable"
                ]
                fast_candidates = apply_routing_filters(fast_candidates, ui_cfg, include_unknown_ip_type=True)
                fast_candidates.sort(key=probe_priority_key)
                fast_test_ids = [
                    n["id"] for n in fast_candidates
                    if n.get("id")
                ][:INITIAL_CONNECT_TEST_LIMIT]

            if fast_test_ids:
                initial_tested_ids = set(fast_test_ids)
                msg = f"首次快速连接模式：优先测试 {len(fast_test_ids)} 个高优先级节点，发现可用节点后立即连接"
                print(f"[快速首连] {msg}", flush=True)
                log_to_json("INFO", "Main", msg)
                set_state(is_connecting=True, last_check_message=msg)
                test_multiple_nodes(fast_test_ids)

                with lock:
                    fast_nodes = read_nodes()
                    available_candidates = [
                        n for n in fast_nodes
                        if n.get("probe_status") == "available" and not n.get("active")
                    ]
                    available_candidates = apply_routing_filters(available_candidates, ui_cfg)

                if available_candidates:
                    is_connecting = False
                    set_state(is_connecting=False, last_check_message="快速首连已找到可用节点，正在建立连接...")
                    auto_switch_node()
                    if active_openvpn_running():
                        valid_nodes_count = len([n for n in read_nodes() if n.get("probe_status") == "available"])
                        message = f"Fetched {len(candidates)} nodes. Fast-tested {len(fast_test_ids)} nodes and connected."
                        set_state(
                            last_check_at=time.time(),
                            last_check_message=message,
                            active_openvpn_node_id=active_openvpn_node_id,
                            valid_nodes=valid_nodes_count,
                        )
                        return message
                    is_connecting = True

        # Test remaining non-active nodes from the list
        with lock:
            current_nodes = read_nodes()
            to_test = [
                n for n in current_nodes
                if not n.get("active") and n.get("id") not in initial_tested_ids
            ]
            to_test_ids = [n["id"] for n in to_test]
            
        msg = f"开始对列表中所有候选节点进行周期连通性与延迟测试，待检测节点共 {len(to_test_ids)} 个"
        print(f"[周期检测] {msg}", flush=True)
        log_to_json("INFO", "Main", msg)
        
        set_state(is_connecting=True, last_check_message="正在并发检测所有节点可用性...")
        test_multiple_nodes(to_test_ids)
        is_connecting = False
        
        with lock:
            merged = read_nodes()
            
            # Identify available, unavailable, and active nodes
            available_nodes = [n["id"] for n in merged if n.get("probe_status") == "available"]
            unavailable_nodes = [n["id"] for n in merged if n.get("probe_status") == "unavailable"]
            active_node = next((n["id"] for n in merged if n.get("active")), "无")
            
            status_report = (
                f"周期节点检测完成。实时同步状态: 获取到候选节点共 {len(merged)} 个。 "
                f"其中【可用节点】{len(available_nodes)} 个: {available_nodes[:15]}...; "
                f"【不可用节点】{len(unavailable_nodes)} 个; "
                f"当前【正在正常运行的活动连接节点】为: {active_node}。"
            )
            print(f"[周期检测] {status_report}", flush=True)
            log_to_json("INFO", "Main", status_report)
            
            if active_node != "无" and not active_openvpn_running():
                warn_msg = f"[诊断警告] 活动节点 {active_node} 被标记为活动状态，但 OpenVPN 进程实际并未正常运行！"
                print(warn_msg, flush=True)
                log_to_json("WARNING", "Main", warn_msg)
            
            if not active_openvpn_running():
                ui_cfg = load_ui_config()
                connection_enabled = ui_cfg.get("connection_enabled", True)
                if connection_enabled:
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    
                    if routing_mode != "fixed_ip":
                        available_candidates = [n for n in merged if n.get("probe_status") == "available"]
                        available_candidates = apply_routing_filters(available_candidates, ui_cfg)
                        
                        if available_candidates:
                            auto_switch_node()

        valid_nodes_count = len([n for n in merged if n.get("probe_status") == "available"])
        message = f"Fetched {len(candidates)} nodes. Tested {len(to_test_ids)} non-active nodes."
        set_state(
            last_check_at=time.time(),
            last_check_message=message,
            active_openvpn_node_id=active_openvpn_node_id,
            valid_nodes=valid_nodes_count,
        )
        return message
    except Exception as e:
        raise e
    finally:
        is_connecting = False
        maintenance_lock.release()


def collector_loop() -> None:
    global last_collector_heartbeat
    while True:
        last_collector_heartbeat = time.time()
        success = False
        try:
            print("[守护线程] 开始执行节点拉取与可用性检测周期任务...", flush=True)
            log_to_json("INFO", "Main", "开始执行节点拉取与可用性检测周期任务...")
            res = maintain_valid_nodes(force=False)
            if "没有拉取到新节点" not in res:
                success = True
            log_to_json("INFO", "Main", f"周期同步与检测任务完成，结果: {res}")
        except Exception as exc:
            err_msg = f"周期节点同步任务执行异常: {exc}"
            print(f"[错误] {err_msg}", flush=True)
            log_to_json("ERROR", "Main", err_msg)
            set_state(last_check_at=time.time(), last_check_message=f"check error: {exc}")
            
        if not active_openvpn_running() and not success:
            sleep_time = 30
        else:
            sleep_time = CHECK_INTERVAL_SECONDS
            
        time.sleep(sleep_time)

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AimiliVPN - 安全登录</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      min-height: 100vh;
      overflow: hidden;
      background: linear-gradient(135deg, #eef2ff 0%, #fdf2f8 50%, #ecfeff 100%);
      position: relative;
    }
    [data-theme="dark"] body {
      background: radial-gradient(ellipse at 25% 20%, #152038 0%, #0d1117 60%);
    }

    /* Blob decorations */
    .login-blob {
      position: fixed;
      border-radius: 50%;
      filter: blur(80px);
      opacity: 0.6;
      pointer-events: none;
      z-index: 0;
    }
    .login-blob:nth-child(1) { width: 400px; height: 400px; background: rgba(99,102,241,0.35); top: -120px; left: -80px; animation: blobFloat1 12s ease-in-out infinite; }
    .login-blob:nth-child(2) { width: 320px; height: 320px; background: rgba(236,72,153,0.30); top: 60%; right: -60px; animation: blobFloat2 10s ease-in-out infinite; }
    .login-blob:nth-child(3) { width: 280px; height: 280px; background: rgba(20,184,166,0.25); bottom: -80px; left: 30%; animation: blobFloat3 14s ease-in-out infinite; }
    .login-blob:nth-child(4) { width: 200px; height: 200px; background: rgba(251,191,36,0.20); top: 30%; left: 15%; animation: blobFloat4 9s ease-in-out infinite; }
    .login-blob:nth-child(5) { width: 240px; height: 240px; background: rgba(56,189,248,0.25); top: 10%; right: 20%; animation: blobFloat5 11s ease-in-out infinite; }
    [data-theme="dark"] .login-blob { opacity: 0.35; }
    [data-theme="dark"] .login-blob:nth-child(1) { background: rgba(99,102,241,0.25); }
    [data-theme="dark"] .login-blob:nth-child(2) { background: rgba(236,72,153,0.20); }
    [data-theme="dark"] .login-blob:nth-child(3) { background: rgba(20,184,166,0.18); }
    [data-theme="dark"] .login-blob:nth-child(4) { background: rgba(251,191,36,0.15); }
    [data-theme="dark"] .login-blob:nth-child(5) { background: rgba(56,189,248,0.18); }

    @keyframes blobFloat1 { 0%,100%{transform:translate(0,0)scale(1)} 33%{transform:translate(60px,-40px)scale(1.08)} 66%{transform:translate(-30px,20px)scale(0.95)} }
    @keyframes blobFloat2 { 0%,100%{transform:translate(0,0)scale(1)} 50%{transform:translate(-50px,-60px)scale(1.05)} }
    @keyframes blobFloat3 { 0%,100%{transform:translate(0,0)scale(1)} 33%{transform:translate(40px,30px)scale(1.1)} 66%{transform:translate(-20px,-20px)scale(0.9)} }
    @keyframes blobFloat4 { 0%,100%{transform:translate(0,0)} 50%{transform:translate(30px,-30px)} }
    @keyframes blobFloat5 { 0%,100%{transform:translate(0,0)scale(1)} 50%{transform:translate(-30px,20px)scale(0.9)} }

    .login-grid {
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background-image: radial-gradient(circle, rgba(99,102,241,0.04) 1px, transparent 1px);
      background-size: 32px 32px;
      -webkit-mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
      mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
    }

    .login-container {
      position: relative; z-index: 1;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 24px 16px;
    }

    .login-toolbar {
      position: fixed; top: 20px; right: 24px; z-index: 10;
      display: inline-flex; align-items: center; gap: 10px;
    }
    .login-toolbar button {
      width: 40px; height: 40px; min-width: 40px;
      border-radius: 50%; padding: 0;
      display: flex; align-items: center; justify-content: center;
      cursor: pointer; border: 1px solid rgba(255,255,255,0.6);
      background: rgba(255,255,255,0.7);
      backdrop-filter: blur(8px);
      color: #64748b; font-size: 16px;
      transition: all .2s;
    }
    [data-theme="dark"] .login-toolbar button {
      background: rgba(255,255,255,0.08);
      border-color: rgba(255,255,255,0.1);
      color: #94a3b8;
    }
    .login-toolbar button:hover { background: #fff; color: #6366f1; box-shadow: 0 2px 8px rgba(99,102,241,0.15); }
    [data-theme="dark"] .login-toolbar button:hover { background: rgba(255,255,255,0.15); color: #60a5fa; }

    .login-card {
      position: relative;
      width: 100%;
      max-width: 400px;
      background: rgba(255,255,255,0.72);
      -webkit-backdrop-filter: blur(24px) saturate(180%);
      backdrop-filter: blur(24px) saturate(180%);
      border: 1px solid rgba(255,255,255,0.6);
      border-radius: 20px;
      padding: 40px 32px 32px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.04), 0 18px 50px rgba(99,102,241,0.18);
      z-index: 2;
    }
    [data-theme="dark"] .login-card {
      background: rgba(28,30,36,0.55);
      border-color: rgba(255,255,255,0.10);
      box-shadow: 0 1px 3px rgba(0,0,0,0.4), 0 20px 60px rgba(59,130,246,0.22);
    }

    .brand {
      text-align: center;
      margin-bottom: 28px;
    }
    .brand-name {
      font-size: 28px;
      font-weight: 800;
      background: linear-gradient(135deg, #6366f1, #ec4899);
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    [data-theme="dark"] .brand-name {
      background: linear-gradient(135deg, #60a5fa, #1d4ed8);
      -webkit-background-clip: text;
      background-clip: text;
    }
    .brand-sub {
      font-size: 14px;
      color: #94a3b8;
      margin-top: 6px;
    }
    [data-theme="dark"] .brand-sub { color: #64748b; }

    .welcome {
      text-align: center;
      font-size: 30px;
      font-weight: 700;
      margin-bottom: 28px;
      color: #1e293b;
    }
    [data-theme="dark"] .welcome { color: #f1f5f9; }

    .form-group {
      margin-bottom: 20px;
    }
    label {
      display: block;
      font-size: 13px;
      font-weight: 600;
      color: #64748b;
      margin-bottom: 8px;
    }
    [data-theme="dark"] label { color: #94a3b8; }
    .input-wrap {
      position: relative;
      display: flex;
      align-items: center;
    }
    .input-wrap .input-icon {
      position: absolute;
      left: 14px;
      color: #94a3b8;
      font-size: 15px;
      pointer-events: none;
    }
    [data-theme="dark"] .input-wrap .input-icon { color: #64748b; }
    .input-wrap input {
      width: 100%;
      height: 46px;
      padding: 0 14px 0 42px;
      background: #fff;
      border: 1.5px solid #e2e8f0;
      border-radius: 10px;
      color: #1e293b;
      font-family: inherit;
      font-size: 14px;
      outline: none;
      transition: border-color .2s, box-shadow .2s;
    }
    [data-theme="dark"] .input-wrap input {
      background: #1a1b1f;
      border-color: #334155;
      color: #f1f5f9;
    }
    .input-wrap input:focus {
      border-color: #6366f1;
      box-shadow: 0 0 0 3px rgba(99,102,241,0.1);
    }
    .input-wrap input::placeholder { color: #cbd5e1; }
    [data-theme="dark"] .input-wrap input::placeholder { color: #475569; }

    .error-message {
      color: #ef4444;
      font-size: 13px;
      margin-top: 8px;
      display: none;
    }
    .error-message.show { display: block; }

    .login-btn {
      width: 100%;
      height: 46px;
      border: none;
      border-radius: 10px;
      background: linear-gradient(135deg, #6366f1, #7c3aed);
      color: #fff;
      font-family: inherit;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity .2s, transform .1s;
      margin-top: 4px;
    }
    .login-btn:hover { opacity: 0.9; }
    .login-btn:active { transform: scale(0.98); }
    .login-btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; }
  </style>
</head>
  <body>
    <div class="login-blob"></div>
    <div class="login-blob"></div>
    <div class="login-blob"></div>
    <div class="login-blob"></div>
    <div class="login-blob"></div>
    <div class="login-grid"></div>

    <div class="login-toolbar">
      <button id="login_theme_btn" onclick="toggleLoginTheme()" title="切换主题">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
      </button>
    </div>

    <div class="login-container">
      <div class="login-card">
      <div class="brand">
        <div class="brand-name">AimiliVPN</div>
        <div class="brand-sub">VPN 节点管理系统</div>
      </div>
      <div class="welcome">欢迎回来</div>

      <form id="login_form" onsubmit="handleLogin(event)">
        <div class="form-group">
          <label for="username">管理账号</label>
          <div class="input-wrap">
            <span class="input-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
            </span>
            <input type="text" id="username" name="username" placeholder="请输入管理账号" required autocomplete="username">
          </div>
        </div>
        <div class="form-group">
          <label for="password">安全密码</label>
          <div class="input-wrap">
            <span class="input-icon">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            </span>
            <input type="password" id="password" name="password" placeholder="请输入安全密码" required autocomplete="current-password">
          </div>
          <div id="error_text" class="error-message"></div>
        </div>
        <button type="submit" class="login-btn" id="submit_btn">
          <span>登录</span>
        </button>
      </form>
    </div>
  </div>

  <script>
    const THEME_KEY = 'aimili_theme';
    var themeLabels = { light: '明亮模式', dark: '暗黑模式', system: '跟随系统' };
    var themeIcons = {
      light: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />',
      dark: '<path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" />',
      system: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />'
    };
    function getThemeIcon(theme) { return themeIcons[theme] || themeIcons.light; }
    function setLoginTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme);
      var btn = document.getElementById('login_theme_btn');
      if (btn) btn.innerHTML = getThemeIcon(theme);
      localStorage.setItem(THEME_KEY, theme);
    }
    function toggleLoginTheme() {
      var saved = localStorage.getItem(THEME_KEY) || 'light';
      var next = saved === 'light' ? 'dark' : (saved === 'dark' ? 'system' : 'light');
      setLoginTheme(next);
    }
    
    // 应用保存的主题
    (function() {
      var saved = localStorage.getItem(THEME_KEY) || 'light';
      setLoginTheme(saved);
    })();

    async function handleLogin(e) {
      e.preventDefault();
      var uname = document.getElementById("username").value.trim();
      var pwd = document.getElementById("password").value.trim();
      var errorText = document.getElementById("error_text");
      var submitBtn = document.getElementById("submit_btn");

      errorText.classList.remove("show");
      submitBtn.disabled = true;
      submitBtn.querySelector("span").textContent = "正在验证...";

      try {
        var response = await fetch("./api/login", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username: uname, password: pwd })
        });
        var data = await response.json();
        if (response.ok && data.ok) {
          window.location.reload();
        } else {
          errorText.textContent = data.error || "账号或密码不正确";
          errorText.classList.add("show");
          submitBtn.disabled = false;
          submitBtn.querySelector("span").textContent = "登录";
        }
      } catch (err) {
        errorText.textContent = "连接服务器失败，请稍后重试";
        errorText.classList.add("show");
        submitBtn.disabled = false;
        submitBtn.querySelector("span").textContent = "登录";
      }
    }
  </script>
</body>
</html>
"""

INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>AimiliVPN 节点池管理系统</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    * { margin: 0; padding: 0; box-sizing: border-box; }

    :root {
      --bg: #e6e8ec;
      --surface: #ffffff;
      --surface-2: #f8fafc;
      --border: #e2e8f0;
      --border-light: #cbd5e1;
      --border-color: #e2e8f0;
      --text: #1e293b;
      --text-primary: #1e293b;
      --text-secondary: #64748b;
      --text-muted: #94a3b8;
      --primary: #6366f1;
      --primary-hover: #4f46e5;
      --success: #10b981;
      --success-bg: rgba(16,185,129,0.08);
      --danger: #ef4444;
      --danger-bg: rgba(239,68,68,0.08);
      --warning: #f59e0b;
      --warning-bg: rgba(245,158,11,0.08);
      --success-gradient: linear-gradient(135deg, #059669, #10b981);
      --shadow-sm: 0 1px 3px rgba(0,0,0,0.04);
      --shadow: 0 1px 4px rgba(0,0,0,0.06), 0 2px 12px rgba(0,0,0,0.04);
    }

    [data-theme="dark"] {
      --bg: #0a0e17;
      --surface: #111827;
      --surface-2: #1a2236;
      --border: #1e293b;
      --border-light: #273548;
      --border-color: #1e293b;
      --text: #f1f5f9;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --text-muted: #64748b;
      --success-bg: rgba(16,185,129,0.12);
      --danger-bg: rgba(239,68,68,0.12);
      --warning-bg: rgba(245,158,11,0.12);
      --shadow-sm: none;
      --shadow: none;
    }

    [data-theme="dark"] .active-card-icon { background: #1a2236; }
    [data-theme="dark"] .stat-icon { background: #1a2236; }
    [data-theme="dark"] th { background: rgba(10,14,23,0.4); }
    [data-theme="dark"] .log-container { background: #05080f; border-color: var(--border); }
    [data-theme="dark"] .badge-info { background: rgba(99,102,241,0.15); color: #a5b4fc; }
    [data-theme="dark"] .tag-green { background: rgba(16,185,129,0.12); color: #10b981; }
    [data-theme="dark"] .tag-blue { background: rgba(99,102,241,0.15); color: #a5b4fc; }
    [data-theme="dark"] .vps-card { background: var(--bg); }
    [data-theme="dark"] .vps-item { background: var(--bg); }
    [data-theme="dark"] .option-card { background: var(--bg); }
    [data-theme="dark"] .form-input { background: var(--bg); }
    [data-theme="dark"] .form-select { background: var(--bg); }
    [data-theme="dark"] .input-field { background: var(--bg); }
    [data-theme="dark"] [style*="background: #f8fafc"] { background: var(--surface) !important; }
    [data-theme="dark"] tr:hover td { background: rgba(255,255,255,0.015); }
    [data-theme="dark"] .row-active td { background: rgba(16,185,129,0.06) !important; }
    [data-theme="dark"] .modal-close:hover { background: var(--surface-2); }
    [data-theme="dark"] #log_terminal_container { background: #05080f !important; border-color: var(--border) !important; color: #a5b4fc !important; box-shadow: inset 0 4px 20px rgba(0,0,0,0.8) !important; }
    [data-theme="dark"] [style*="background: #f8fafc"] { background: var(--surface) !important; }
    [data-theme="dark"] .active-card-icon, 
    [data-theme="dark"] .stat-icon { background: #1a2236; }
    [data-theme="dark"] .card { background: var(--bg); }

    /* === 动态背景 Blob === */
    .main-blob {
      position: fixed;
      border-radius: 50%;
      filter: blur(80px);
      opacity: 0.5;
      pointer-events: none;
      z-index: 0;
    }
    [data-theme="dark"] .main-blob { opacity: 0.3; }
    .main-blob:nth-child(1) { width: 400px; height: 400px; background: rgba(99,102,241,0.35); top: -120px; left: -80px; animation: blobFloat1 12s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(1) { background: rgba(99,102,241,0.25); }
    .main-blob:nth-child(2) { width: 320px; height: 320px; background: rgba(236,72,153,0.30); top: 60%; right: -60px; animation: blobFloat2 10s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(2) { background: rgba(236,72,153,0.20); }
    .main-blob:nth-child(3) { width: 280px; height: 280px; background: rgba(20,184,166,0.25); bottom: -80px; left: 30%; animation: blobFloat3 14s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(3) { background: rgba(20,184,166,0.18); }
    .main-blob:nth-child(4) { width: 200px; height: 200px; background: rgba(251,191,36,0.20); top: 30%; left: 15%; animation: blobFloat4 9s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(4) { background: rgba(251,191,36,0.15); }
    .main-blob:nth-child(5) { width: 240px; height: 240px; background: rgba(56,189,248,0.25); top: 10%; right: 20%; animation: blobFloat5 11s ease-in-out infinite; }
    [data-theme="dark"] .main-blob:nth-child(5) { background: rgba(56,189,248,0.18); }

    .main-grid {
      position: fixed; inset: 0; z-index: 0; pointer-events: none;
      background-image: radial-gradient(circle, rgba(99,102,241,0.04) 1px, transparent 1px);
      background-size: 32px 32px;
      -webkit-mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
      mask-image: radial-gradient(ellipse at center, black 30%, transparent 70%);
    }

    /* 毛玻璃卡片 */
    .active-card {
      background: rgba(255,255,255,0.75);
      -webkit-backdrop-filter: blur(16px) saturate(180%);
      backdrop-filter: blur(16px) saturate(180%);
    }
    [data-theme="dark"] .active-card {
      background: rgba(17,24,39,0.75);
    }
    .table-wrapper {
      background: rgba(255,255,255,0.75);
      -webkit-backdrop-filter: blur(16px) saturate(180%);
      backdrop-filter: blur(16px) saturate(180%);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      overflow-x: auto;
    }
    [data-theme="dark"] .table-wrapper {
      background: rgba(17,24,39,0.75);
    }
    .stats-row .stat-card {
      background: rgba(255,255,255,0.75);
      -webkit-backdrop-filter: blur(16px) saturate(180%);
      backdrop-filter: blur(16px) saturate(180%);
    }
    [data-theme="dark"] .stats-row .stat-card {
      background: rgba(17,24,39,0.75);
    }
    .option-card {
      background: rgba(255,255,255,0.75);
      -webkit-backdrop-filter: blur(16px) saturate(180%);
      backdrop-filter: blur(16px) saturate(180%);
      border: 1px solid rgba(0,0,0,0.04);
    }
    [data-theme="dark"] .option-card {
      background: rgba(17,24,39,0.75);
      border: 1px solid rgba(255,255,255,0.08);
    }

    /* === 3x-UI 侧边栏布局 === */
    .app-layout { display: flex; min-height: 100vh; }

    .sidebar {
      width: 220px; min-width: 220px;
      background: #ffffff;
      border-right: 1px solid #e2e8f0;
      display: flex; flex-direction: column;
      position: fixed; top: 0; left: 0; bottom: 0;
      z-index: 200;
    }
    [data-theme="dark"] .sidebar { background: #15161a; border-right-color: #1e293b; }

    .sidebar-brand {
      padding: 18px 20px;
      border-bottom: 1px solid #e2e8f0;
      display: flex; align-items: center; gap: 10px;
    }
    [data-theme="dark"] .sidebar-brand { border-bottom-color: rgba(255,255,255,0.06); }
    .sidebar-brand-name {
      font-size: 20px; font-weight: 800;
      background: linear-gradient(135deg, #6366f1, #ec4899);
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    [data-theme="dark"] .sidebar-brand-name {
      background: linear-gradient(135deg, #60a5fa, #818cf8);
      -webkit-background-clip: text;
      background-clip: text;
    }
    .sidebar-brand-dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: #10b981;
      animation: online-blink 1.1s ease-in-out infinite;
    }
    @keyframes online-blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

    .sidebar-nav {
      flex: 1;
      min-height: 0;
      padding: 12px 10px;
      display: flex; flex-direction: column; gap: 2px;
      overflow-y: auto;
    }
    .nav-item {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 14px;
      border-radius: 8px;
      color: #64748b;
      font-size: 13px; font-weight: 500;
      text-decoration: none;
      transition: all .15s;
      cursor: pointer;
    }
    .nav-item:hover { background: #f1f5f9; color: #1e293b; }
    .nav-item.active {
      background: #eef2ff;
      color: #6366f1;
    }
    [data-theme="dark"] .nav-item { color: rgba(255,255,255,0.6); }
    [data-theme="dark"] .nav-item:hover { background: rgba(255,255,255,0.06); color: #fff; }
    [data-theme="dark"] .nav-item.active { background: rgba(99,102,241,0.2); color: #818cf8; }
    .nav-item svg { width: 18px; height: 18px; flex-shrink: 0; }

    .sidebar-divider {
      height: 1px; margin: 8px 12px;
      background: #e2e8f0;
    }
    [data-theme="dark"] .sidebar-divider { background: rgba(255,255,255,0.08); }
    .nav-item-danger { color: #ef4444 !important; }
    .nav-item-danger:hover { background: #fef2f2 !important; color: #dc2626 !important; }
    [data-theme="dark"] .nav-item-danger { color: #f87171 !important; }
    [data-theme="dark"] .nav-item-danger:hover { background: rgba(239,68,68,0.15) !important; color: #fca5a5 !important; }

    .submenu-toggle { position: relative; justify-content: flex-start; }
    .submenu-arrow { width: 16px; height: 16px; margin-left: auto; transition: transform .2s; }
    .submenu-toggle.open .submenu-arrow { transform: rotate(180deg); }
    .sub-item { padding-left: 40px !important; font-size: 13px; }

    .sidebar-footer {
      padding: 12px 10px 16px;
      border-top: 1px solid #e2e8f0;
      flex-shrink: 0;
    }
    [data-theme="dark"] .sidebar-footer { border-top-color: rgba(255,255,255,0.06); }
    .sidebar-theme-btn {
      display: flex; align-items: center; gap: 10px;
      padding: 10px 14px; border-radius: 8px;
      color: #475569; font-size: 13px; font-weight: 500;
      cursor: pointer; border: 1px solid #e2e8f0; background: #f8fafc;
      width: 100%; font-family: inherit;
      transition: all .15s;
    }
    .sidebar-theme-btn:hover { background: #eef2ff; color: #6366f1; border-color: #c7d2fe; }
    [data-theme="dark"] .sidebar-theme-btn { color: #cbd5e1; border-color: #334155; background: #1e293b; }
    [data-theme="dark"] .sidebar-theme-btn:hover { background: #334155; color: #fff; border-color: #475569; }

    .content {
      flex: 1;
      margin-left: 220px;
      background: transparent;
      min-height: 100vh;
      position: relative;
      z-index: 1;
    }

    /* 移动端侧边栏 */
    .mobile-menu-btn {
      position: fixed; top: 12px; left: 12px; z-index: 300;
      width: 38px; height: 38px; border-radius: 10px;
      background: var(--surface); border: 1px solid var(--border);
      color: var(--text); cursor: pointer;
      display: none; align-items: center; justify-content: center;
      box-shadow: var(--shadow);
    }
    .sidebar-overlay {
      display: none;
      position: fixed; inset: 0; background: rgba(0,0,0,0.4); z-index: 199;
    }

    @media (max-width: 768px) {
      .sidebar { transform: translateX(-100%); transition: transform .25s ease; }
      .sidebar.open { transform: translateX(0); }
      .sidebar-overlay.open { display: block; }
      .content { margin-left: 0; }
      .mobile-menu-btn { display: flex; }
    }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }

    header {
      padding: 20px 28px;
      background: transparent;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 16px;
    }

.brand h1 {
      font-size: 18px;
      font-weight: 700;
      color: var(--text);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .brand h1 svg { color: var(--primary); }

    .status-bar {
      font-size: 13px;
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      gap: 8px;
      margin-top: 4px;
    }

    .status-dot {
      width: 7px; height: 7px;
      border-radius: 50%;
      background: var(--success);
      display: inline-block;
    }

    .header-actions {
      display: flex;
      gap: 8px;
      align-items: center;
    }

    button, .btn {
      height: 34px;
      padding: 0 14px;
      border: 1px solid var(--border);
      border-radius: 8px;
      font-family: inherit;
      font-size: 13px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.15s ease;
      display: inline-flex;
      align-items: center;
      gap: 6px;
      background: var(--surface);
      color: var(--text-secondary);
      white-space: nowrap;
      text-decoration: none;
      box-shadow: var(--shadow-sm);
    }

    button:hover { border-color: var(--border-light); color: var(--text); }

    .btn-primary {
      background: var(--primary);
      color: #fff;
      border: none;
    }

    .btn-primary:hover { background: var(--primary-hover); }

    .btn-success {
      background: var(--success);
      color: #fff;
      border: none;
    }

    .btn-success:hover { opacity: 0.9; }

    .btn-danger {
      background: var(--danger);
      color: #fff;
      border: none;
    }

    .btn-danger:hover { opacity: 0.9; }

    .btn-ghost {
      background: transparent;
      border: 1px solid var(--border);
      color: var(--text-secondary);
      box-shadow: none;
    }

    .btn-ghost:hover { background: var(--surface-2); }

    button:disabled { opacity: 0.35; cursor: not-allowed; }

    .content-body {
      padding: 28px 36px;
      max-width: 1300px;
      margin: 0 auto;
    }

    .page-content { display: block; }

    .active-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 20px;
      margin-bottom: 20px;
      box-shadow: var(--shadow-sm);
    }

    .active-card-left {
      display: flex;
      align-items: center;
      gap: 16px;
    }

    .active-card-icon {
      width: 42px; height: 42px;
      background: #eef2ff;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .active-card-icon svg { width: 20px; height: 20px; color: var(--primary); }

    .active-card-details {
      display: flex;
      flex-direction: column;
      gap: 4px;
    }

    .active-card-row1 {
      display: flex;
      align-items: center;
      gap: 10px;
    }

    .active-card-row2 {
      display: flex;
      gap: 16px;
      font-size: 13px;
      color: var(--text-muted);
      flex-wrap: wrap;
    }

    .active-card-row2 strong { color: var(--text); font-weight: 600; }

    .badge {
      display: inline-flex;
      align-items: center;
      gap: 5px;
      padding: 3px 10px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      border: 1px solid transparent;
    }

    .badge-ok { background: var(--success-bg); color: var(--success); border-color: rgba(16,185,129,0.2); }
    .badge-err { background: var(--danger-bg); color: var(--danger); border-color: rgba(239,68,68,0.2); }
    .badge-warn { background: var(--warning-bg); color: var(--warning); border-color: rgba(245,158,11,0.2); }
    .badge-info { background: #eef2ff; color: #6366f1; border-color: rgba(99,102,241,0.2); }

    .pulse { width: 6px; height: 6px; border-radius: 50%; background: currentColor; animation: pulse 1.5s infinite; display: inline-block; }
    @keyframes pulse { 0%{opacity:1;transform:scale(.9)} 50%{opacity:.4;transform:scale(1.5)} 100%{opacity:1;transform:scale(.9)} }

    .stats-row {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }

    .stat-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-shadow: var(--shadow-sm);
    }

    .stat-card:hover { border-color: var(--border-light); }

    .stat-num {
      font-size: 28px;
      font-weight: 700;
      color: var(--text);
      line-height: 1;
      margin-bottom: 4px;
    }

    .stat-label {
      font-size: 13px;
      color: var(--text-muted);
    }

    .stat-icon {
      width: 36px; height: 36px;
      background: #eef2ff;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      flex-shrink: 0;
    }

    .stat-icon svg { width: 18px; height: 18px; color: var(--primary); }
    .stat-card:nth-child(2) .stat-icon { background: #fef3c7; }
    .stat-card:nth-child(2) .stat-icon svg { color: #f59e0b; }
    .stat-card:nth-child(3) .stat-icon { background: #d1fae5; }
    .stat-card:nth-child(3) .stat-icon svg { color: #10b981; }

    .toolbar {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 16px;
      margin-bottom: 16px;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      align-items: center;
      box-shadow: var(--shadow-sm);
    }

    .toolbar select, .toolbar input {
      height: 36px;
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 0 10px;
      color: var(--text);
      font-family: inherit;
      font-size: 13px;
      outline: none;
      cursor: pointer;
    }

    .toolbar select { width: 150px; }
    .toolbar select:focus, .toolbar input:focus { border-color: var(--primary); }

    .toolbar input { flex: 1; min-width: 200px; }

    .toolbar-spacer { margin-left: auto; }

    .table-wrap {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      overflow: hidden;
      box-shadow: var(--shadow-sm);
    }

    .table-scroll { overflow-x: auto; }

    table {
      width: 100%;
      border-collapse: collapse;
      font-size: 13px;
    }

    th {
      text-align: left;
      padding: 12px 16px;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: .6px;
      color: var(--text-muted);
      background: var(--surface-2);
      border-bottom: 1px solid var(--border);
      white-space: nowrap;
    }

    td {
      padding: 8px 12px;
      background: var(--danger-bg);
      border: 1px solid rgba(239,68,68,0.2);
      border-radius: 6px;
      color: #dc2626;
      font-size: 13px;
      margin-bottom: 16px;
      display: none;
    }

    .msg-success {
      padding: 8px 12px;
      background: var(--success-bg);
      border: 1px solid rgba(16,185,129,0.2);
      border-radius: 6px;
      color: #059669;
      font-size: 13px;
      margin-bottom: 16px;
      display: none;
    }

    .msg-error.show, .msg-success.show { display: block; }

    .option-group {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 8px;
      margin-top: 4px;
    }

    .option-card {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      cursor: pointer;
      transition: all .15s;
      user-select: none;
    }

    .option-card:hover { border-color: var(--border-light); }
    .option-card.active {
      border-color: var(--primary);
      background: #eef2ff;
    }

    .option-card-title { font-size: 13px; font-weight: 600; color: var(--text); margin-bottom: 2px; }
    .option-card-desc { font-size: 11px; color: var(--text-muted); }
    [data-theme="dark"] .option-card-desc { color: #cbd5e1; }

    .favorites-panel {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 16px;
      box-shadow: var(--shadow-sm);
    }

    .checkbox-row {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      cursor: pointer;
      user-select: none;
    }

    .checkbox-row input[type="checkbox"] { margin-top: 3px; }

    .checkbox-text {
      display: flex;
      flex-direction: column;
      gap: 2px;
    }

    .checkbox-text strong { font-size: 14px; font-weight: 600; color: var(--text); }
    .checkbox-text span { font-size: 12px; color: var(--text-muted); line-height: 1.4; }

    .vps-grid {
      display: grid;
      grid-template-columns: repeat(2, 1fr);
      gap: 14px;
    }

    @media (max-width: 576px) { .vps-grid { grid-template-columns: 1fr; } }

    .vps-card {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }

    .vps-tag {
      font-size: 11px;
      font-weight: 700;
      padding: 3px 8px;
      border-radius: 5px;
      width: fit-content;
      text-transform: uppercase;
      letter-spacing: .5px;
    }

    .tag-green { background: var(--success-bg); color: #059669; border: 1px solid rgba(16,185,129,0.2); }
    .tag-blue { background: #eef2ff; color: #6366f1; border: 1px solid rgba(99,102,241,0.2); }

    .vps-desc { font-size: 13px; color: var(--text-muted); line-height: 1.5; flex: 1; }

    .vps-link {
      display: block;
      text-align: center;
      padding: 8px;
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 6px;
      color: var(--text-secondary);
      text-decoration: none;
      font-size: 12px;
      font-weight: 600;
      transition: all .15s;
    }

    .vps-link:hover { border-color: var(--primary); color: var(--primary); }

    .log-container {
      background: var(--surface-2);
      border: 1px solid var(--border);
      border-radius: 10px;
      height: 380px;
      padding: 16px;
      overflow-y: auto;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      line-height: 1.6;
      white-space: pre-wrap;
      word-break: break-all;
      color: #6366f1;
      margin-bottom: 16px;
    }

    @media (max-width: 768px) {
      header { flex-direction: column; align-items: flex-start; padding: 12px 20px; }
      .header-actions { width: 100%; flex-wrap: wrap; }
      main { padding: 12px 12px; }
      .active-card { flex-direction: column; align-items: flex-start; }
      .option-group { grid-template-columns: 1fr; }
    }

    /* backward-compatible aliases for legacy template references */
    .stat-icon-wrapper { width: 42px; height: 42px; border-radius: 10px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
    .active-card-info { display: flex; align-items: center; gap: 16px; }
    .active-card-value { font-size: 24px; font-weight: 700; color: var(--text); }
    .badge-pulse { width: 6px; height: 6px; border-radius: 50%; background: currentColor; animation: pulse 1.5s infinite; display: inline-block; }
    .available { background: var(--success-bg); color: #059669; border-color: rgba(16,185,129,0.2); }
    .unavailable { background: var(--danger-bg); color: #dc2626; border-color: rgba(239,68,68,0.2); }
    .not_checked { background: var(--warning-bg); color: #d97706; border-color: rgba(245,158,11,0.2); }
    .connect-btn { height: 28px; padding: 0 10px; font-size: 12px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: all .15s; border: 1px solid var(--border); background: transparent; color: var(--text-secondary); display: inline-flex; align-items: center; gap: 4px; }
    .connect-btn:hover { border-color: var(--primary); color: var(--primary); }
    .test-btn { height: 28px; padding: 0 10px; font-size: 12px; border-radius: 6px; font-weight: 600; cursor: pointer; transition: all .15s; border: 1px solid var(--border); background: transparent; color: var(--success); display: inline-flex; align-items: center; gap: 4px; }
    .test-btn:hover { background: var(--success); color: #fff; border-color: transparent; }
    .connect-btn:disabled, .test-btn:disabled { opacity: 0.35; cursor: not-allowed; }
    .modal-content {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 14px;
      width: 90%;
      max-width: 480px;
      padding: 28px;
      box-shadow: 0 25px 60px rgba(0,0,0,0.25);
      animation: modalFadeIn .2s ease;
      max-height: 85vh;
      overflow-y: auto;
    }
    .modal {
      display: none;
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      z-index: 9999;
      align-items: center;
      justify-content: center;
      background: rgba(0, 0, 0, 0.5);
      backdrop-filter: blur(6px);
      -webkit-backdrop-filter: blur(6px);
      padding: 16px;
    }
    .modal-content .btn-primary { height: 38px; padding: 0 18px; }
    
    /* 代理设置弹窗暗黑模式文字颜色覆盖 */
    [data-theme="dark"] .modal-content .form-hint,
    [data-theme="dark"] .modal-content .option-card-desc {
      color: #cbd5e1 !important;
    }
    [data-theme="dark"] .modal-content .option-card.active {
      background: rgba(99,102,241,0.15) !important;
    }
    
    /* 所有弹窗暗黑模式通用覆盖 */
    [data-theme="dark"] .modal-content {
      background: rgba(17,24,39,0.95);
      border: 1px solid rgba(255,255,255,0.08);
    }
    [data-theme="dark"] .modal {
      background: rgba(0,0,0,0.6);
    }
    [data-theme="dark"] .modal-content button[onmouseover],
    [data-theme="dark"] .modal-content button[onmouseout] {
      color: var(--text-secondary) !important;
    }
    [data-theme="dark"] .modal-content button[onmouseover]:hover {
      background: rgba(255,255,255,0.08) !important;
      color: #60a5fa !important;
    }
    [data-theme="dark"] .modal-content .form-label {
      color: var(--text-primary) !important;
    }
    [data-theme="dark"] .modal-content .input-field {
      background: var(--bg) !important;
      border-color: var(--border) !important;
      color: var(--text) !important;
    }
    [data-theme="dark"] .modal-content select {
      background: var(--bg) !important;
      border-color: var(--border) !important;
      color: var(--text) !important;
    }
    [data-theme="dark"] .modal-content .btn-ghost,
    [data-theme="dark"] .modal-content button[style*="background: transparent"] {
      color: var(--text-secondary) !important;
      border-color: var(--border) !important;
    }
    [data-theme="dark"] .modal-content .btn-ghost:hover,
    [data-theme="dark"] .modal-content button[style*="background: transparent"]:hover {
      background: rgba(255,255,255,0.06) !important;
      color: var(--text) !important;
    }
    [data-theme="dark"] .modal-content .btn-primary {
      background: var(--primary) !important;
      color: #fff !important;
    }
    [data-theme="dark"] #log_terminal_container {
      background: #05080f !important;
      border-color: var(--border) !important;
      color: #a5b4fc !important;
      box-shadow: inset 0 4px 20px rgba(0,0,0,0.8) !important;
    }
    .input-field { width: 100%; height: 40px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px; padding: 0 12px; color: var(--text); font-family: inherit; font-size: 14px; outline: none; }
    .input-field:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(99,102,241,0.1); }
    .vps-links { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px; }
    .vps-item { background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; padding: 16px; display: flex; flex-direction: column; gap: 12px; }
    .vps-tag { font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 5px; width: fit-content; text-transform: uppercase; letter-spacing: .5px; }
    .tag-normal { background: #eef2ff; color: #6366f1; border: 1px solid rgba(99,102,241,0.2); }
    .tag-premium { background: var(--success-bg); color: #059669; border: 1px solid rgba(16,185,129,0.2); }
    .vps-desc { font-size: 13px; color: var(--text-muted); line-height: 1.5; flex: 1; }
    .vps-btn { display: block; text-align: center; padding: 8px; background: var(--surface); border: 1px solid var(--border); border-radius: 6px; color: var(--text-secondary); text-decoration: none; font-size: 12px; font-weight: 600; transition: all .15s; }
    .vps-btn:hover { border-color: var(--primary); color: var(--primary); }
    .vps-footer { padding-top: 12px; font-size: 13px; color: var(--text-muted); text-align: center; }
    .forum-link { color: var(--primary); font-weight: 600; text-decoration: none; }
    .forum-link:hover { color: #4f46e5; text-decoration: underline; }
    .latency-val { font-weight: 600; font-size: 12px; padding: 2px 6px; border-radius: 4px; }
    .latency-good { background: var(--success-bg); color: #059669; }
    .latency-medium { background: var(--warning-bg); color: #d97706; }
    .latency-poor { background: var(--danger-bg); color: #dc2626; }
    .health-badge { font-weight: 600; font-size: 12px; padding: 2px 6px; border-radius: 4px; display: inline-block; }
    .health-excellent { background: rgba(16, 185, 129, 0.15); color: #059669; }
    .health-good { background: rgba(59, 130, 246, 0.15); color: #2563eb; }
    .health-fair { background: rgba(245, 158, 11, 0.15); color: #d97706; }
    .health-poor { background: rgba(239, 68, 68, 0.15); color: #dc2626; }
    .health-critical { background: rgba(127, 29, 29, 0.15); color: #991b1b; }
    @media (max-width: 576px) { .vps-links { grid-template-columns: 1fr; } }
    @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
    @keyframes modalFadeIn { from { transform: scale(0.97); opacity: 0; } to { transform: scale(1); opacity: 1; } }
    
    /* 表格样式 - 覆盖login页面遗留的danger-bg */
    table { border-collapse: collapse; table-layout: fixed; }
    th { padding: 10px 14px; background: var(--surface-2); border-bottom: 1px solid var(--border); font-size: 12px; color: var(--text-secondary); font-weight: 600; }
    td { padding: 10px 14px; background: var(--surface); border-bottom: 1px solid var(--border); color: var(--text-primary); font-size: 13px; }
    tbody tr:hover td { background: var(--surface-2); }
    tbody tr:last-child td { border-bottom: none; }
    
    @media (max-width: 768px) {
      .modal { padding: 12px; align-items: flex-end; }
      .modal-content { width: 100%; max-width: none; border-radius: 16px 16px 0 0; max-height: 90vh; }
    }
  </style>
</head>
<body>
<div class="main-blob"></div>
<div class="main-blob"></div>
<div class="main-blob"></div>
<div class="main-blob"></div>
<div class="main-blob"></div>
<div class="main-grid"></div>

<div class="app-layout">

  <button class="mobile-menu-btn" id="mobile_menu_btn" onclick="toggleSidebar()">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h16"/></svg>
  </button>
  <div class="sidebar-overlay" id="sidebar_overlay" onclick="toggleSidebar()"></div>

  <aside class="sidebar" id="sidebar">
    <div class="sidebar-brand">
      <div class="sidebar-brand-name">AimiliVPN</div>
    </div>
    <nav class="sidebar-nav">
      <a class="nav-item active" id="nav_overview" href="javascript:void(0)" onclick="switchPage('overview')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/></svg>
        概览
      </a>
      <a class="nav-item" id="nav_nodes" href="javascript:void(0)" onclick="switchPage('nodes')">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4"/></svg>
        节点管理
      </a>
      <a class="nav-item" id="sidebar_refresh" href="javascript:void(0)" onclick="doRefreshNodes()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg>
        更新节点
      </a>

      <div class="sidebar-divider"></div>

      <div class="sidebar-submenu">
        <button class="nav-item submenu-toggle" id="settings_toggle" onclick="toggleSettingsSubmenu()">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
          设置
          <svg class="submenu-arrow" id="settings_arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M6 9l6 6 6-6"/></svg>
        </button>
        <div class="submenu-items" id="settings_submenu" style="display:none;">
          <a class="nav-item sub-item" href="javascript:void(0)" onclick="event.stopPropagation(); openCredentialsModal();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
            网页安全
          </a>
          <a class="nav-item sub-item" href="javascript:void(0)" onclick="event.stopPropagation(); openNetworkModal();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/></svg>
            代理设置
          </a>
          <a class="nav-item sub-item" href="javascript:void(0)" onclick="event.stopPropagation(); openGatewayModal();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10"/></svg>
            网关设置
          </a>
          <a class="nav-item sub-item" href="javascript:void(0)" onclick="event.stopPropagation(); openLogsModal();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"/></svg>
            日志
          </a>
          <a class="nav-item sub-item nav-item-danger" href="javascript:void(0)" onclick="event.stopPropagation(); logoutAdmin();">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"/></svg>
            退出
          </a>
        </div>
      </div>

      <div class="sidebar-divider"></div>

      <a class="nav-item" href="https://github.com/kadiswang/aimili-vpngate" target="_blank">
        <svg viewBox="0 0 16 16" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.012 8.012 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>
        GitHub
      </a>
      <a class="nav-item" href="https://t.me/arestemple" target="_blank">
        <svg viewBox="0 0 16 16" fill="currentColor"><path d="M16 8A8 8 0 1 1 0 8a8 8 0 0 1 16 0zM8.287 5.906c-.778.324-2.334.994-4.666 2.01-.378.15-.577.298-.595.442-.03.243.275.339.69.47l.175.055c.408.133.958.288 1.243.294.26.006.549-.1.868-.32 2.179-1.471 3.304-2.214 3.374-2.23.05-.012.12-.026.166.016.047.041.042.12.037.141-.03.129-1.227 1.241-1.846 1.817-.193.18-.33.307-.358.336-.063.065-.129.13-.19.193-.34.347-.597.609-.043.974.265.175.474.319.684.457.228.15.457.301.765.503.074.049.143.098.207.143.297.206.58.404.916.373.195-.018.398-.2.502-.754.25-1.332.74-4.22.842-5.281.01-.088.001-.22-.103-.312-.104-.092-.252-.09-.323-.087a1.52 1.52 0 0 0-.254.04z"/></svg>
        Telegram
      </a>
    </nav>
    <div class="sidebar-footer">
      <button class="sidebar-theme-btn" id="sidebar_theme_btn" onclick="toggleSidebarTheme()">
        <svg id="sidebar_theme_icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/></svg>
        <span id="sidebar_theme_label">明亮模式</span>
      </button>
    </div>
  </aside>

  <main class="content">
<header>
  <div class="brand">
    <h1>
      <svg xmlns="http://www.w3.org/2000/svg" style="width:24px; height:24px; color:#818cf8;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" /></svg>
      AimiliVPN 节点管理系统
    </h1>
    <div id="status" class="status" style="display: none;"><span class="status-dot"></span>服务加载中...</div>
  </div>
</header>
<div class="content-body">

    <div id="page_overview" class="page-content">
    <section class="active-node-section" id="active_node_card" style="margin-bottom: 24px;">
      <!-- Rendered dynamically by render() -->
    </section>

    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px; flex-wrap: wrap; gap: 8px;">
      <span style="font-size: 15px; font-weight: 600; color: var(--text-primary);">节点列表</span>
      <span id="overview_filter_label" style="font-size: 12px; color: var(--text-secondary);"></span>
    </div>

    <div class="table-wrapper" style="margin-top: 0;">
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th style="width: 100px; white-space: nowrap;">状态</th>
              <th style="width: 150px;">IP 地址 : 端口</th>
              <th style="width: 120px;">物理位置</th>
              <th style="width: 70px;">IP 类型</th>
              <th style="width: 70px;">延迟</th>
              <th style="width: 70px;">健康度</th>
              <th style="width: 140px;">操作</th>
            </tr>
          </thead>
          <tbody id="overview_rows"></tbody>
        </table>
      </div>
    </div>
    </div>

    <div id="page_nodes" class="page-content" style="display:none;">

  <section class="toolbar">
    <select id="status_filter">
      <option value="all">全部节点</option>
      <option value="available">可用节点</option>
      <option value="unavailable">失效节点</option>
    </select>
    <select id="country_filter">
      <option value="">所有国家</option>
    </select>
    <select id="ip_type_filter">
      <option value="">所有IP类型</option>
      <option value="residential">住宅IP</option>
      <option value="hosting">机房IP</option>
    </select>
    <select id="source_filter">
      <option value="all">所有来源</option>
      <option value="vpngate">VPNGate</option>
      <option value="publicvpnlist">PublicVPNList</option>
    </select>
    <select id="health_filter">
      <option value="all">全部健康度</option>
      <option value="excellent">优秀 (90+)</option>
      <option value="good">良好 (70+)</option>
      <option value="fair">一般 (50+)</option>
      <option value="poor">较差 (30+)</option>
      <option value="critical">极差 (0-29)</option>
    </select>
    <span id="node_count_label" style="font-size: 13px; color: var(--text-secondary); align-self: center; padding: 0 8px; white-space: nowrap;">
      共 <strong id="node_count_total" style="color: var(--text-primary); font-weight: 600;">0</strong> 个节点
    </span>
    <button id="btn_batch_test" class="toolbar-btn" type="button" onclick="batchTestFiltered()" style="height: 42px; gap: 6px; background: var(--primary); color: #fff; border: none;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
      </svg>
      一键检测
    </button>
    <button id="btn_favorites" class="toolbar-btn" type="button" onclick="toggleFavoritesView()" style="margin-left: auto; height: 42px; gap: 6px;">
      <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M11.049 2.927c.3-.921 1.603-.921 1.902 0l1.519 4.674a1 1 0 00.95.69h4.907c.961 0 1.371 1.24.588 1.81l-3.97 2.883a1 1 0 00-.364 1.118l1.518 4.674c.3.922-.755 1.688-1.538 1.118l-3.971-2.883a1 1 0 00-1.175 0l-3.97 2.883c-.783.57-1.838-.197-1.538-1.118l1.518-4.674a1 1 0 00-.364-1.118l-3.97-2.883c-.783-.57-.372-1.81.588-1.81h4.906a1 1 0 00.951-.69l1.519-4.674z" />
      </svg>
      收藏菜单
    </button>
  </section>
  <div id="favorites_panel" style="display: none; background: var(--surface); border: 1px solid var(--border-color); border-radius: 12px; padding: 20px; margin-bottom: 20px; box-shadow: var(--shadow-sm);">
    <div style="display: flex; flex-direction: column; gap: 16px;">
      <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px;">
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <span style="font-size: 15px; font-weight: 600; color: var(--text-primary); display: flex; align-items: center; gap: 6px;">
            ⭐ 收藏专属管理面板
          </span>
          <span style="font-size: 13px; color: var(--text-secondary);">
            在这里管理您的收藏节点过滤，以及设置出站连接漂移策略。
          </span>
        </div>
        <div style="display: flex; gap: 12px; align-items: center;">
          <button id="btn_toggle_fav_routing" type="button" class="toolbar-btn" style="height: 36px; padding: 0 14px; font-size: 13px; border-radius: 6px;" onclick="toggleFavRouting()">
            启用仅用收藏出站
          </button>
        </div>
      </div>
      
      <div style="border-top: 1px solid var(--border); padding-top: 16px;">
        <label style="display: flex; align-items: flex-start; gap: 10px; cursor: pointer; user-select: none;">
          <input type="checkbox" id="fav_fail_fallback_checkbox" style="margin-top: 3px; cursor: pointer;" onchange="handleFavFallbackChange(this.checked)" checked />
          <div style="display: flex; flex-direction: column; gap: 2px;">
            <span style="font-size: 14px; font-weight: 500; color: var(--text-primary);">收藏节点失效后自动切换其他（非收藏）可用节点</span>
            <span style="font-size: 12px; color: var(--text-secondary);">勾选此项，当所有收藏节点不可用时，系统将自动使用其他最快的非收藏可用节点，保障网络连接不中断。</span>
          </div>
        </label>
        <div id="fav_fallback_warning" style="display: none; margin-top: 12px; padding: 10px 14px; background: rgba(244, 63, 94, 0.1); border: 1px solid rgba(244, 63, 94, 0.25); border-radius: 8px; font-size: 12px; color: var(--danger); line-height: 1.4; animation: modalFadeIn 0.2s ease-out;">
          ⚠️ <strong>警告</strong>：您已取消勾选此项。如果当前收藏的节点均不可用，系统将<strong>无法切换</strong>到其他可用节点，可能导致网络<strong>彻底断开连接</strong>！
        </div>
      </div>
    </div>
  </div>

  <div class="table-wrapper">
    <div class="table-container">
      <table>
        <thead>
          <tr>
            <th style="width: 100px; white-space: nowrap;">状态</th>
            <th style="width: 150px;">IP 地址 : 端口</th>
            <th style="width: 120px;">物理位置</th>
            <th style="width: 120px;">运营主体 / ISP</th>
            <th style="width: 70px;">IP 类型</th>
            <th style="width: 70px;">延迟</th>
            <th style="width: 70px;">健康度</th>
            <th style="width: 140px;">操作</th>
          </tr>
        </thead>
        <tbody id="rows" style="display: table-row-group !important;"></tbody>
      </table>
    </div>
    
    <!-- 分页控制栏 -->
    <div class="pagination-container" style="padding: 16px; display: none; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); flex-wrap: wrap; gap: 12px;">
      <div style="font-size: 13px; color: var(--text-secondary);">
        显示第 <span id="page_start" style="color: var(--text-primary); font-weight:600;">0</span> - <span id="page_end" style="color: var(--text-primary); font-weight:600;">0</span> 条，共 <span id="filtered_count" style="color: var(--text-primary); font-weight:600;">0</span> 条备选节点
      </div>
      <div style="display: flex; gap: 8px; align-items: center;">
        <button id="btn_first_page" class="connect-btn" style="height: 32px; padding: 0 10px;">首页</button>
        <button id="btn_prev_page" class="connect-btn" style="height: 32px; padding: 0 10px;">上一页</button>
        <span style="font-size: 13px; color: var(--text-secondary); margin: 0 8px;">
          页码 <strong id="current_page_val" style="color: var(--primary);">1</strong> / <strong id="total_pages_val">1</strong>
        </span>
        <button id="btn_next_page" class="connect-btn" style="height: 32px; padding: 0 10px;">下一页</button>
        <button id="btn_last_page" class="connect-btn" style="height: 32px; padding: 0 10px;">尾页</button>
      </div>
    </div>
  </div> <!-- end table-wrapper -->

  </div> <!-- end page_nodes -->

  <!-- Credentials Modal (网页安全设置) -->
  <div id="credentials_modal" class="modal">
    <div class="modal-content">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          网页安全
        </h3>
        <button type="button" onclick="closeCredentialsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="credentials_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="credentials_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="credentials_form" onsubmit="saveCredentials(event)">
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_username">管理账号</label>
          <input type="text" id="cred_username" class="input-field" required placeholder="请输入管理账号">
        </div>
        
        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_password">安全密码</label>
          <input type="password" id="cred_password" class="input-field" placeholder="留空则保留当前密码">
        </div>

        <div class="form-group" style="margin-bottom: 12px;">
          <label class="form-label" for="cred_port">网页管理端口</label>
          <input type="number" id="cred_port" class="input-field" required min="1" max="65535" placeholder="8790">
        </div>
        
        <div class="form-group" style="margin-bottom: 20px;">
          <label class="form-label" for="cred_suffix">登录安全后缀 (仅字母和数字)</label>
          <input type="text" id="cred_suffix" class="input-field" required pattern="[A-Za-z0-9]+" placeholder="EJsW2EeBo9lY">
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeCredentialsModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="credentials_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Network Modal (代理及网络设置，包括出站路由) -->
  <div id="network_modal" class="modal">
    <div class="modal-content" style="max-width: 480px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          代理设置
        </h3>
        <button type="button" onclick="closeNetworkModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>
      
      <div id="network_error" style="color: var(--danger); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(244,63,94,0.1); border: 1px solid rgba(244,63,94,0.2); border-radius: 6px; display: none;"></div>
      <div id="network_success" style="color: var(--success); font-size: 13px; margin-bottom: 16px; padding: 8px 12px; background: rgba(16,185,129,0.1); border: 1px solid rgba(16,185,129,0.2); border-radius: 6px; display: none;"></div>

      <form id="network_form" onsubmit="saveNetwork(event)">
        <div class="form-group" style="margin-bottom: 16px;">
          <label class="form-label" for="net_proxy_port">HTTP/SOCKS5 代理出站端口</label>
          <input type="number" id="net_proxy_port" class="input-field" required min="1024" max="65535" placeholder="7928">
        </div>

        <div style="border-top: 1px dashed var(--border); padding-top: 16px; margin-bottom: 4px;">
          <label style="font-size: 13px; font-weight: 600; color: var(--text-primary); margin-bottom: 8px; display: flex; align-items: center; gap: 6px;">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="width:16px;height:16px;color:var(--primary)"><path d="M16 7a4 4 0 11-8 0 4 4 0 018 0z"/><path d="M12 14v7m-3-3h6"/></svg>
            上游代理（拉取节点用）
          </label>
          <p class="form-hint" style="font-size: 11px; color: var(--text-muted); margin-bottom: 12px; line-height: 1.4;">配置后通过代理访问 vpngate.net 拉取节点列表。留空则不启用。</p>
          
          <div class="form-group" style="margin-bottom: 12px;">
            <label class="form-label" for="net_upstream_enabled">启用上游代理</label>
            <input type="checkbox" id="net_upstream_enabled" style="width:16px;height:16px;accent-color:var(--primary);" onchange="toggleUpstreamFields()">
          </div>
          
          <div id="upstream_proxy_fields" style="display:none;">
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label">代理类型</label>
              <input type="hidden" id="net_upstream_type" value="socks">
              <div class="option-group" id="upstream_type_group">
                <div class="option-card active" data-value="socks" onclick="setUpstreamType('socks')">
                  <div class="option-card-title">SOCKS5</div>
                  <div class="option-card-desc">通用代理</div>
                </div>
                <div class="option-card" data-value="http" onclick="setUpstreamType('http')">
                  <div class="option-card-title">HTTP</div>
                  <div class="option-card-desc">HTTP代理</div>
                </div>
              </div>
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label" for="net_upstream_host">代理地址</label>
              <input type="text" id="net_upstream_host" class="input-field" placeholder="127.0.0.1">
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label" for="net_upstream_port">代理端口</label>
              <input type="number" id="net_upstream_port" class="input-field" min="1" max="65535" placeholder="1080">
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label" for="net_upstream_user">用户名（可选）</label>
              <input type="text" id="net_upstream_user" class="input-field" placeholder="留空则不认证">
            </div>
            <div class="form-group" style="margin-bottom: 12px;">
              <label class="form-label" for="net_upstream_pass">密码（可选）</label>
              <input type="password" id="net_upstream_pass" class="input-field" placeholder="留空则不认证">
            </div>
          </div>
        </div>

        <div style="border-top: 1px dashed var(--border); padding-top: 16px; margin-bottom: 16px;">
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站路由模式</label>
            <input type="hidden" id="net_routing_mode" value="auto">
            <div class="option-group" id="routing_mode_group">
              <div class="option-card active" data-value="auto" onclick="setRoutingMode('auto')">
                <div class="option-card-title">自动配置</div>
                <div class="option-card-desc">智能切换，最稳定</div>
              </div>
              <div class="option-card" data-value="fixed_ip" onclick="setRoutingMode('fixed_ip')">
                <div class="option-card-title">固定 IP</div>
                <div class="option-card-desc">锁定IP，不自动切换</div>
              </div>
              <div class="option-card" data-value="fixed_region" onclick="setRoutingMode('fixed_region')">
                <div class="option-card-title">固定地区</div>
                <div class="option-card-desc">锁定特定国家地区</div>
              </div>
            </div>
          </div>
          
          <div id="net_force_country_group" class="form-group" style="margin-bottom: 16px; display: none;">
            <label class="form-label" for="net_force_country">锁定国家地区</label>
            <select id="net_force_country" class="input-field" style="background: var(--surface-2); border: 1px solid var(--border-color); color: var(--text-primary); outline: none; cursor: pointer; width: 100%; height: 40px; border-radius: 8px; padding: 0 12px;">
              <option value="">正在加载节点国家...</option>
            </select>
          </div>
          
          <div class="form-group" style="margin-bottom: 16px;">
            <label class="form-label">IP 出站类型过滤</label>
            <input type="hidden" id="net_routing_ip_type" value="all">
            <div class="option-group" id="routing_ip_type_group">
              <div class="option-card active" data-value="all" onclick="setRoutingIpType('all')">
                <div class="option-card-title">所有IP</div>
                <div class="option-card-desc">机房 + 住宅</div>
              </div>
              <div class="option-card" data-value="residential" onclick="setRoutingIpType('residential')">
                <div class="option-card-title">住宅IP</div>
                <div class="option-card-desc">静态家宽</div>
              </div>
              <div class="option-card" data-value="hosting" onclick="setRoutingIpType('hosting')">
                <div class="option-card-title">机房IP</div>
                <div class="option-card-desc">普通机房</div>
              </div>
            </div>
          </div>
          
          <div id="net_routing_warning" class="form-hint" style="font-size: 12px; color: var(--text-secondary); line-height: 1.4; padding: 8px 12px; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px; margin-top: 8px;">
            ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。
          </div>
        </div>
        
        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button type="button" onclick="closeNetworkModal()" style="height: 40px; padding: 0 16px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">取消</button>
          <button type="submit" id="network_submit_btn" class="btn-primary" style="height: 40px; padding: 0 20px; font-weight: 600; border-radius: 8px;">保存修改</button>
        </div>
      </form>
    </div>
  </div>


  <!-- Gateway Modal (网关自检与代理测试) -->
  <div id="gateway_modal" class="modal">
    <div class="modal-content" style="max-width: 600px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" /></svg>
          网关设置与自检
        </h3>
        <button type="button" onclick="closeGatewayModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- 服务列表 -->
      <div id="gateway_services_list" style="display: flex; flex-direction: column; gap: 12px; margin-bottom: 24px;">
        <div style="text-align: center; color: var(--text-secondary); padding: 20px 0;">
          <svg style="animation: spin 1s linear infinite; width: 20px; height: 20px; display: inline-block; margin-bottom: 8px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>
          <div>正在加载系统网关状态...</div>
        </div>
      </div>

      <!-- 分割线 -->
      <div style="border-top: 1px dashed var(--border); margin: 20px 0;"></div>

      <!-- 本地代理出口检测 -->
      <div style="background: var(--surface-2); border: 1px solid var(--border-color); border-radius: 12px; padding: 16px;">
        <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
          <div class="stat-icon-wrapper" style="background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.2); width: 36px; height: 36px; border-radius: 8px; flex-shrink: 0;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2" style="color: var(--primary); width: 18px; height: 18px;"><path stroke-linecap="round" stroke-linejoin="round" d="M8.111 16.404a5.5 5.5 0 017.778 0M12 20h.01m-7.08-7.071a10.5 10.5 0 0114.14 0M1.414 8.05a16 16 0 0121.172 0" /></svg>
          </div>
          <div>
            <h4 style="margin: 0; font-size: 14px; font-weight: 600; color: var(--text-primary);">本地代理出口检测</h4>
            <p style="margin: 2px 0 0 0; font-size: 12px; color: var(--text-secondary);">检测 HTTP/SOCKS5 代理出站连通性与 IP</p>
          </div>
        </div>
        
        <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(0, 0, 0, 0.2); border-radius: 8px; padding: 12px; margin-bottom: 12px; flex-wrap: wrap; gap: 10px;">
          <div style="font-size: 13px; color: var(--text-secondary);">
            测试状态: <span id="proxy_status_badge" class="badge not_checked" style="margin-left: 4px;">未检测</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary); text-align: right;">
            出口 IP: <span id="proxy_ip_val" class="mono" style="font-weight: 600; color: var(--text-primary);">-</span> 
            <span id="proxy_latency_val" style="margin-left: 6px;"></span>
          </div>
        </div>

        <div style="display: flex; gap: 12px; justify-content: flex-end;">
          <button id="btn_test_proxy" class="btn-primary" style="height: 36px; padding: 0 16px; font-size: 13px;">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
            开始检测
          </button>
        </div>
      </div>
      
      <div style="display: flex; justify-content: flex-end; margin-top: 20px;">
        <button type="button" onclick="closeGatewayModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>

  <!-- Logs Modal (日志监控与分类筛选) -->
  <div id="logs_modal" class="modal">
    <div class="modal-content" style="max-width: 800px; width: 95%;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
        <h3 style="margin: 0; font-size: 18px; font-weight: 700; color: var(--text-primary); display: flex; align-items: center; gap: 8px;">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:20px; height:20px; color: var(--primary);" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" /></svg>
          今日运行日志
        </h3>
        
        <div style="display: flex; align-items: center; gap: 10px; margin-left: auto;">
          <label class="form-label" for="log_filter_select" style="margin: 0; font-size: 13px; color: var(--text-secondary);">日志筛选:</label>
          <select id="log_filter_select" class="input-field" style="width: 140px; height: 32px; font-size: 12px; border-radius: 6px; padding: 0 8px; background: var(--surface-2);" onchange="filterAndRenderLogs()">
            <option value="all">全部日志</option>
            <option value="proxy">代理相关 (Proxy)</option>
            <option value="vpn">VPN 连接 (VPN)</option>
            <option value="system">系统运行 (Main/Route)</option>
          </select>
        </div>
        
        <button type="button" onclick="closeLogsModal()" style="background: transparent; border: none; padding: 4px; cursor: pointer; color: var(--text-secondary); width: 28px; height: 28px; display: flex; align-items: center; justify-content: center; border-radius: 50%;" onmouseover="this.style.background='#f1f5f9'" onmouseout="this.style.background='transparent'">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:18px; height:18px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5"><path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" /></svg>
        </button>
      </div>

      <!-- Terminal Log Container -->
      <div id="log_terminal_container" style="background: var(--surface-2); border: 1px solid var(--border); border-radius: 10px; height: 400px; padding: 16px; overflow-y: auto; font-family: 'JetBrains Mono', Consolas, Courier, monospace; font-size: 12px; line-height: 1.5; text-align: left; white-space: pre-wrap; word-break: break-all; color: #6366f1; box-shadow: inset 0 2px 8px rgba(0,0,0,0.04); position: relative; margin-bottom: 20px;">
        <div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">
          暂无今日运行日志记录。
        </div>
      </div>

      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="display: flex; gap: 8px;">
<button type="button" onclick="copyLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: var(--surface-2); color: var(--text-primary); border: 1px solid var(--border-color);">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
          复制日志
        </button>
        <button type="button" onclick="exportLogContent()" class="btn-primary" style="height: 38px; padding: 0 16px; background: var(--surface-2); color: var(--text-primary); border: 1px solid var(--border-color);">
            <svg xmlns="http://www.w3.org/2000/svg" style="width:14px; height:14px; margin-right: 4px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" /></svg>
            导出日志
          </button>
        </div>
        <button type="button" onclick="closeLogsModal()" style="height: 38px; padding: 0 20px; font-weight: 600; border-radius: 8px; border: 1px solid var(--border-color); background: transparent; color: var(--text-secondary); cursor: pointer;">关闭</button>
      </div>
    </div>
  </div>
</div>
<script>
let nodes=[], state={}, testingNodeIds = new Set(), batchTesting = false;
let currentPage = 1;
const pageSize = 99999;
let currentPageNodes = [];
let countryDict = {};
let csrfToken = "";

async function fetchWithCsrf(url, options = {}) {
  if (!options.method || options.method === "GET") {
    options.method = options.method || "GET";
  }
  // Ensure headers object exists
  if (!options.headers || typeof options.headers !== "object") {
    options.headers = {};
  }
  options.headers = { ...options.headers };
  options.credentials = options.credentials || "same-origin";
  // Auto-fetch CSRF token if missing for write operations
  if (!csrfToken && (!options.method || options.method !== "GET")) {
    try {
      const csrfResp = await fetch("./api/csrf_token", { credentials: "same-origin" });
      if (csrfResp.ok) {
        const csrfData = await csrfResp.json();
        if (csrfData.csrf_token) {
          csrfToken = csrfData.csrf_token;
        }
      }
    } catch(e) {}
  }
  if (csrfToken) {
    options.headers["X-CSRF-Token"] = csrfToken;
  }
  const resp = await fetch(url, options);
  if (resp.ok) {
    try {
      const data = await resp.json();
      if (data.csrf_token) {
        csrfToken = data.csrf_token;
      }
      return data;
    } catch {
      return {};
    }
  }
  let errMsg = resp.statusText;
  try {
    const errBody = await resp.clone().json();
    errMsg = errBody.error || resp.statusText;
  } catch(e) {}
  throw new Error(errMsg);
}

const $=id=>document.getElementById(id);

// IP Health Score: 0-100 based on fraud score, availability, IP type, latency, quality
function getHealthScore(n) {
  if (!n) return 0;
  let score = 0;
  // Fraud score: 50 pts (lower is better)
  const fraud = parseInt(n.fraud_score) || 0;
  if (fraud <= 5) score += 50;
  else if (fraud <= 20) score += 40;
  else if (fraud <= 40) score += 30;
  else if (fraud <= 60) score += 20;
  else if (fraud <= 80) score += 10;
  // Availability: 5 pts
  if (n.probe_status === "available" || n.active) score += 5;
  else if (n.probe_status === "not_checked" || n.probe_status === "testing") score += 3;
  // IP type: 20 pts
  if (n.ip_type === "residential") score += 20;
  else if (n.ip_type === "mobile") score += 15;
  else if (n.ip_type === "hosting") score += 5;
  // Latency: 5 pts
  const lat = parseInt(n.latency_ms) || 0;
  if (lat > 0) {
    if (lat < 200) score += 5;
    else if (lat < 400) score += 4;
    else if (lat < 800) score += 2;
    else score += 1;
  }
  // Quality from vpngate: 20 pts
  const q = (n.quality || "").toLowerCase();
  if (q.includes("excellent") || q.includes("极好")) score += 20;
  else if (q.includes("good") || q.includes("好")) score += 15;
  else if (q.includes("average") || q.includes("一般")) score += 8;
  else if (q.includes("normal") || q.includes("一般")) score += 3;
  return Math.min(score, 100);
}

function getHealthClass(score) {
  if (score >= 90) return "health-excellent";
  if (score >= 70) return "health-good";
  if (score >= 50) return "health-fair";
  if (score >= 30) return "health-poor";
  return "health-critical";
}

function getHealthLabel(score) {
  if (score >= 90) return "优秀";
  if (score >= 70) return "良好";
  if (score >= 50) return "一般";
  if (score >= 30) return "较差";
  return "极差";
}
const esc=s=>String(s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
const base=p=>(p||"").split(/[\\/]/).pop();
function time(ts){return ts?new Date(ts*1000).toLocaleString():"从未"}
function speed(v){return v?`${(v*8/1000/1000).toFixed(1)} Mbps`:"-"}

const translateQuality = q => {
  const dict = {"normal": "普通", "proxy": "代理", "datacenter": "数据中心", "mobile": "移动端"};
  return dict[q] || q || "-";
};

const translateIpType = t => {
  const dict = {"residential": "住宅 IP", "hosting": "机房 IP", "mobile": "移动网", "proxy": "代理 IP"};
  return dict[t] || t || "-";
};

const translateCountry = c => {
  if (countryDict[c]) return countryDict[c];
  return c || "-";
};

const translateStatus = s => {
  const dict = {"available": "可用", "unavailable": "不可用", "not_checked": "待检测"};
  return dict[s] || s || "待检测";
};

function getLatencyClass(ms) {
  if (!ms) return '';
  if (ms < 50) return 'latency-good';
  if (ms < 150) return 'latency-medium';
  return 'latency-poor';
}

function updateCountryFilter() {
  const select = $("country_filter");
  const selectedValue = select.value;
  const countries = Array.from(new Set(nodes.map(n => n ? translateCountry(n.country) : "").filter(Boolean))).sort();
  
  const currentOptions = Array.from(select.options).map(o => o.value).filter(Boolean);
  if (JSON.stringify(countries) === JSON.stringify(currentOptions)) {
    return;
  }
  
  select.innerHTML = '<option value="">所有国家</option>' + 
    countries.map(c => `<option value="${esc(c)}">${esc(c)}</option>`).join("");
  
  if (countries.includes(selectedValue)) {
    select.value = selectedValue;
  } else {
    select.value = "";
  }
}

function updateSourceFilter() {
  const select = $("source_filter");
  if (!select) return;
  const hasPublicVPNList = nodes.some(n => n && n.source === "publicvpnlist");
  if (hasPublicVPNList) {
    select.style.display = "";
  } else {
    select.style.display = "none";
  }
}

function getFilteredNodes() {
  const selectedCountry = $("country_filter").value;
  const selectedIpType = $("ip_type_filter").value;
  const selectedStatus = $("status_filter").value;
  const selectedSource = $("source_filter").value;
  const selectedHealth = $("health_filter").value;
  return nodes.filter(n => {
    if (!n) return false;
    if (selectedCountry && translateCountry(n.country) !== selectedCountry) {
      return false;
    }
    if (selectedIpType) {
      if (selectedIpType === "residential" && !["residential", "mobile"].includes(n.ip_type)) {
        return false;
      }
      if (selectedIpType === "hosting" && n.ip_type !== "hosting") {
        return false;
      }
    }
    if (selectedStatus === "available" && n.probe_status !== "available" && !n.active) {
      return false;
    }
    if (selectedStatus === "unavailable" && (n.probe_status !== "unavailable" || n.active)) {
      return false;
    }
    if (selectedSource && selectedSource !== "all") {
      const nodeSource = n.source === "publicvpnlist" ? "publicvpnlist" : "vpngate";
      if (nodeSource !== selectedSource) {
        return false;
      }
    }
    if (selectedHealth && selectedHealth !== "all") {
      const score = getHealthScore(n);
      const minScores = { excellent: 90, good: 70, fair: 50, poor: 30, critical: 0 };
      const maxScores = { excellent: 100, good: 89, fair: 49, poor: 29, critical: 29 };
      if (score < minScores[selectedHealth] || score > maxScores[selectedHealth]) {
        return false;
      }
    }
    const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
    if (showFavoritesOnly && !favoriteIds.includes(n.id)) {
      return false;
    }
    return true;
  });
}

function stableSortNodes() {
  nodes.sort((a, b) => {
    if (!a || !b) return 0;
    const aScore = a.score || 0;
    const bScore = b.score || 0;
    if (bScore !== aScore) {
      return bScore - aScore;
    }
    const aId = a.id || "";
    const bId = b.id || "";
    return aId.localeCompare(bId);
  });
}

function render(){
  const activeNodeId = state.active_openvpn_node_id;
  const activeNode = nodes.find(n => n && (n.active || n.id === activeNodeId));
  
  // Render separated Active Node Card
  const activeCardContainer = $("active_node_card");
  if (state.is_connecting && !activeNode) {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--warning); box-shadow: 0 0 15px rgba(245, 158, 11, 0.15);">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #f59e0b; width: 24px; height: 24px; animation: spin 2s linear infinite;"><path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 1121.21 8H18" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-primary);">
              <span class="badge" style="background: rgba(245, 158, 11, 0.15); color: #f59e0b; border-color: rgba(245, 158, 11, 0.3);"><span class="badge-pulse" style="background: #f59e0b;"></span>正在连接</span>
              <strong>${esc(state.active_node_latency || '正在连接...')}</strong>
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              ${esc(state.last_check_message || '正在与 VPN 节点建立加密隧道，请稍候...')}
            </div>
          </div>
        </div>
      </div>
    `;
  } else if (activeNode) {
    const latencyClass = getLatencyClass(activeNode.latency_ms);
    const latencyText = activeNode.latency_ms ? `<span class="latency-val ${latencyClass}">${activeNode.latency_ms} ms</span>` : "-";
    const displayLocation = activeNode.location || translateCountry(activeNode.country) || "-";
    activeCardContainer.innerHTML = `
      <div class="active-card">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(16, 185, 129, 0.15); border-color: rgba(16, 185, 129, 0.3); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: #34d399; width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title">
              <span class="badge available"><span class="badge-pulse"></span>已连接</span>
              <strong>${esc(translateCountry(activeNode.country))} 节点</strong>
            </div>
            <div class="active-card-value mono" style="font-size: 20px; margin-top: 2px;">
              ${esc(activeNode.ip || activeNode.remote_host)}:${activeNode.remote_port || ""}
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              <span>物理位置: <strong>${esc(displayLocation)}</strong></span>
              <span style="margin-left: 12px;">延时: <strong>${latencyText}</strong></span>
              <span style="margin-left: 12px;">运营主体: <strong>${esc(activeNode.owner || activeNode.as_name || "-")}</strong></span>
              <span style="margin-left: 12px;">IP 类型: <strong>${esc(translateIpType(activeNode.ip_type))}</strong></span>
            </div>
          </div>
        </div>
        <button class="btn-danger" style="height: 38px; padding: 0 16px; border-radius: 8px;" onclick="disconnectNode()">
          <svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg>
          断开连接
        </button>
      </div>
    `;
  } else {
    activeCardContainer.innerHTML = `
      <div class="active-card" style="background: var(--bg-surface); border-color: var(--border-color); box-shadow: none;">
        <div class="active-card-info">
          <div class="stat-icon-wrapper" style="background: rgba(244, 63, 94, 0.1); border-color: rgba(244, 63, 94, 0.2); width: 48px; height: 48px; border-radius: 12px;">
            <svg xmlns="http://www.w3.org/2000/svg" class="stat-icon" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5" style="color: var(--danger); width: 24px; height: 24px;"><path stroke-linecap="round" stroke-linejoin="round" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" /></svg>
          </div>
          <div class="active-card-details">
            <div class="active-card-title" style="color: var(--text-secondary);">
              <span class="badge unavailable" style="padding: 2px 8px;">未连接</span> 当前未连接 VPN 节点
            </div>
            <div class="active-card-meta" style="margin-top: 4px;">
              在下方列表中选择一个可用备用节点并点击 “切换” 按钮开始连接。
            </div>
          </div>
        </div>
      </div>
    `;
  }

  renderOverviewNodes(activeNode);

  const shown = getFilteredNodes();
  console.log("[render] shown count:", shown.length, "currentPageNodes:", currentPageNodes.length);
  
  if ($("total")) $("total").textContent = nodes.length; 
  if ($("target")) $("target").textContent = state.target_valid_nodes || 3;
  if ($("active")) $("active").textContent = activeNode ? 1 : 0; 
  
  const statusMessage = state.last_check_message || "";
  const activeNodeInfo = activeNode ? `<span class="badge available" style="margin-left:8px; padding:2px 8px;">${esc(translateCountry(activeNode.country))} (${activeNode.id})</span>` : `<span class="badge unavailable" style="margin-left:8px; padding:2px 8px;">无</span>`;
  const localProxy = state.local_proxy || `http://127.0.0.1:${state.proxy_port || 7928}`;
  if ($("status")) { $("status").innerHTML=`<span class="status-dot"></span>HTTP 代理本地接口：${localProxy} | 活动节点：${activeNodeInfo} | 状态：${statusMessage}`; }
  
  // Update proxy test status card based on background checks
  const pBadge = $("proxy_status_badge");
  const pIpVal = $("proxy_ip_val");
  const pLatVal = $("proxy_latency_val");
  const pBtn = $("btn_test_proxy");
  
  if (state.is_connecting) {
    pBadge.className = "badge";
    pBadge.style.background = "rgba(245, 158, 11, 0.15)";
    pBadge.style.color = "#f59e0b";
    pBadge.style.borderColor = "rgba(245, 158, 11, 0.3)";
    pBadge.innerHTML = `<span class="badge-pulse" style="background: #f59e0b;"></span>正在连接`;
    pIpVal.textContent = state.active_node_latency || "正在连接...";
    pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message || "正在与 VPN 节点建立加密隧道，请稍候...")}</span>`;
    pBtn.disabled = true;
    pBtn.style.opacity = "0.5";
    pBtn.style.cursor = "not-allowed";
  } else {
    pBtn.disabled = false;
    pBtn.style.opacity = "";
    pBtn.style.cursor = "";
    pBadge.style.background = "";
    pBadge.style.color = "";
    pBadge.style.borderColor = "";
    if (state.proxy_ok !== undefined) {
      if (state.proxy_ok) {
        pBadge.className = "badge available";
        pBadge.textContent = "可用";
        pIpVal.textContent = state.proxy_ip || "-";
        const latencyClass = getLatencyClass(state.proxy_latency_ms);
        pLatVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${state.proxy_latency_ms} ms</span>`;
      } else {
        pBadge.className = "badge unavailable";
        pBadge.textContent = "不可用";
        pIpVal.textContent = "-";
        pLatVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px; max-width: 450px; display: inline-block; white-space: normal; line-height: 1.4; text-align: left;" title="${esc(state.proxy_error)}">${esc(state.proxy_error || "连接失败")}</span>`;
      }
    } else {
      pBadge.className = "badge not_checked";
      pBadge.textContent = "未检测";
      pIpVal.textContent = "-";
      if (state.last_check_message) {
        pLatVal.innerHTML = `<span style="color: var(--text-secondary); font-size: 12px;">${esc(state.last_check_message)}</span>`;
      } else {
        pLatVal.innerHTML = "";
      }
    }
  }

  updateFavPanelUI();

  // Pagination calculation
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage > totalPages) currentPage = totalPages;
  if (currentPage < 1) currentPage = 1;
  
  const startIndex = (currentPage - 1) * pageSize;
  const endIndex = Math.min(startIndex + pageSize, shown.length);
  currentPageNodes = shown.slice(startIndex, endIndex);

  // Render table rows
  if (currentPageNodes.length === 0) {
    $("rows").innerHTML = `<tr style="display: table-row !important;"><td colspan="7" style="display: table-cell !important; text-align: center; color: var(--text-secondary); padding: 40px 0;">未找到符合过滤条件的备选节点。</td></tr>`;
  } else {
    $("rows").innerHTML=currentPageNodes.map(n=>{
      if (!n) return '';
      const isCurrentlyActive = activeNode && n.id === activeNode.id;
      const rowClass = isCurrentlyActive ? 'class="active-row"' : '';
      
      const badgeClass = isCurrentlyActive ? 'available' : (n.probe_status || 'not_checked');
      const badgeText = isCurrentlyActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
      const latencyClass = getLatencyClass(n.latency_ms);
      const latencyText = n.latency_ms ? `<span class="latency-val ${latencyClass}">${n.latency_ms} ms</span>` : "-";
      const displayLocation = n.location || translateCountry(n.country) || "-";
      
      const isTesting = testingNodeIds.has(n.id) || batchTesting;
      const testSpinner = `<svg style="animation: spin 1s linear infinite; width: 12px; height: 12px; display: inline-block; margin-right: 4px; vertical-align: middle;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>`;
      const testBtnText = isTesting ? `${testSpinner}检测中` : '检测';
      const testBtn = `<button class="test-btn" data-node-id="${esc(n.id)}" ${isTesting ? 'disabled' : ''} onclick="testNode(this, '${esc(n.id)}', event)">${testBtnText}</button>`;
      
      // Connect button: publicvpnlist nodes without config still show switch (triggers lazy download)
      const isUnavailable = n.probe_status === "unavailable";
      const needsLazyDownload = !n.has_config && n.source === "publicvpnlist";
      const connectDisabled = isUnavailable || state.is_connecting;
      const connectBtn = isCurrentlyActive 
        ? `<button class="connect-btn" disabled style="background: var(--success-gradient); color: white; cursor: default; opacity: 1;">已连接</button>`
        : `<button class="connect-btn" ${connectDisabled ? 'disabled style="opacity:0.3; cursor:not-allowed;"' : ''} onclick="connectNode('${esc(n.id)}')" title="${needsLazyDownload ? '将先下载配置文件再切换' : ''}">${needsLazyDownload ? '下载并切换' : '切换'}</button>`;
      
      const favoriteIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];
      const isFav = favoriteIds.includes(n.id);
      const favBtn = isFav 
        ? `<button class="test-btn" style="color: var(--warning); border-color: rgba(245, 158, 11, 0.4); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">★ 已收藏</button>`
        : `<button class="test-btn" style="color: var(--text-secondary); border-color: var(--border-color); padding: 0 8px; height: 30px;" onclick="toggleFavorite('${esc(n.id)}', event)">☆ 收藏</button>`;

      return `<tr ${rowClass} style="display: table-row !important;">
        <td style="display: table-cell !important; white-space: nowrap;"><span class="badge ${badgeClass}">${badgeText}</span></td>
        <td class="mono" style="white-space: nowrap; max-width: 220px; overflow: hidden; text-overflow: ellipsis; display: table-cell !important;" title="${esc(n.ip||n.remote_host)}:${n.remote_port||""}">${esc(n.ip||n.remote_host)}:${n.remote_port||""}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: table-cell !important;" title="${esc(displayLocation)}">${esc(displayLocation)}</td>
        <td style="white-space: nowrap; overflow: hidden; text-overflow: ellipsis; display: table-cell !important;" title="${esc(n.owner||n.as_name||"-")}">${esc(n.owner||n.as_name||"-")}</td>
        <td style="white-space: nowrap; max-width: 110px; overflow: hidden; text-overflow: ellipsis; display: table-cell !important;" title="${esc(translateIpType(n.ip_type))}">${esc(translateIpType(n.ip_type))}</td>
        <td style="white-space: nowrap; display: table-cell !important;">${latencyText}</td>
        <td style="white-space: nowrap; display: table-cell !important;">
          <span class="health-badge ${getHealthClass(getHealthScore(n))}">${getHealthScore(n)}</span>
        </td>
        <td style="display: table-cell !important;">
          <div class="table-actions">
            ${favBtn}
            ${connectBtn}
          </div>
        </td>
      </tr>`;
    }).join("");
  }

  // Render pagination controls
  $("page_start").textContent = shown.length > 0 ? startIndex + 1 : 0;
  $("page_end").textContent = endIndex;
  $("filtered_count").textContent = shown.length;
  $("node_count_total").textContent = shown.length;
  $("current_page_val").textContent = currentPage;
  $("total_pages_val").textContent = totalPages;
  
  $("btn_first_page").disabled = currentPage === 1;
  $("btn_prev_page").disabled = currentPage === 1;
  $("btn_next_page").disabled = currentPage === totalPages;
  $("btn_last_page").disabled = currentPage === totalPages;

  const batchBtn = $("btn_batch_test");
  if (batchBtn && batchTesting) {
    batchBtn.disabled = true;
  }
}

function renderOverviewNodes(activeNode) {
  const container = $("overview_rows");
  const label = $("overview_filter_label");
  if (!container) return;

  const routingMode = state.routing_mode || "auto";
  const routingIpType = state.routing_ip_type || "all";
  const forceCountry = state.force_country || "";
  const favIds = Array.isArray(state.favorite_node_ids) ? state.favorite_node_ids : [];

  let filtered = nodes.filter(function(n) { return n && n.id; });

  if (routingMode === "fixed_region" && forceCountry) {
    filtered = filtered.filter(function(n) {
      return n.country === forceCountry || (countryDict[n.country] || n.country) === forceCountry;
    });
  } else if (routingMode === "favorites") {
    filtered = filtered.filter(function(n) { return favIds.includes(n.id); });
  }

  if (routingIpType === "residential") {
    filtered = filtered.filter(function(n) { return n.ip_type === "residential" || n.ip_type === "mobile"; });
  } else if (routingIpType === "hosting") {
    filtered = filtered.filter(function(n) { return n.ip_type === "hosting"; });
  }

  // Sort: available first (by latency), then by status
  filtered.sort(function(a, b) {
    if (a.probe_status === "available" && b.probe_status !== "available") return -1;
    if (b.probe_status === "available" && a.probe_status !== "available") return 1;
    if (a.probe_status === "available" && b.probe_status === "available") {
      return (parseInt(a.latency_ms) || 999999) - (parseInt(b.latency_ms) || 999999);
    }
    return 0;
  });

  // Build filter label
  var parts = [];
  if (routingMode === "fixed_region" && forceCountry) parts.push(forceCountry);
  else if (routingMode === "favorites") parts.push("收藏节点");
  else parts.push("自动配置");
  if (routingIpType === "residential") parts.push("住宅IP");
  else if (routingIpType === "hosting") parts.push("机房IP");
  else parts.push("所有IP");
  label.textContent = parts.join(" + ") + " (" + filtered.length + " 个节点)";

  if (filtered.length === 0) {
    container.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-secondary);padding:30px 0;">暂无符合条件的节点</td></tr>';
    return;
  }

  container.innerHTML = filtered.map(function(n) {
    var isActive = activeNode && n.id === activeNode.id;
    var badgeClass = isActive ? "available" : (n.probe_status || "not_checked");
    var badgeText = isActive ? '<span class="badge-pulse"></span>已连接' : translateStatus(n.probe_status);
    var latencyClass = getLatencyClass(n.latency_ms);
    var latencyText = n.latency_ms ? '<span class="latency-val ' + latencyClass + '">' + n.latency_ms + ' ms</span>' : "-";
    var displayLocation = n.location || translateCountry(n.country) || "-";
    var isUnavailable = n.probe_status === "unavailable";
    var connectBtn = isActive
      ? '<button class="connect-btn" disabled style="background:var(--success-gradient);color:white;cursor:default;opacity:1;">已连接</button>'
      : '<button class="connect-btn" ' + ((isUnavailable || state.is_connecting) ? 'disabled style="opacity:0.3;cursor:not-allowed;"' : '') + ' onclick="connectNode(\'' + esc(n.id) + '\')">切换</button>';

    return '<tr' + (isActive ? ' class="active-row"' : '') + ' style="display:table-row!important;">' +
      '<td style="display:table-cell!important;white-space:nowrap;"><span class="badge ' + badgeClass + '">' + badgeText + '</span></td>' +
      '<td class="mono" style="white-space:nowrap;max-width:220px;overflow:hidden;text-overflow:ellipsis;display:table-cell!important;" title="' + esc(n.ip||n.remote_host) + ':' + (n.remote_port||"") + '">' + esc(n.ip||n.remote_host) + ':' + (n.remote_port||"") + '</td>' +
      '<td style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;display:table-cell!important;" title="' + esc(displayLocation) + '">' + esc(displayLocation) + '</td>' +
      '<td style="white-space:nowrap;display:table-cell!important;">' + esc(translateIpType(n.ip_type)) + '</td>' +
      '<td style="white-space:nowrap;display:table-cell!important;">' + latencyText + '</td>' +
      '<td style="white-space:nowrap;display:table-cell!important;"><span class="health-badge ' + getHealthClass(getHealthScore(n)) + '">' + getHealthScore(n) + '</span></td>' +
      '<td style="display:table-cell!important;">' + connectBtn + '</td>' +
      '</tr>';
  }).join("");
}

// Hook up page buttons events
$("btn_first_page").onclick = () => { currentPage = 1; render(); };
$("btn_prev_page").onclick = () => { if (currentPage > 1) { currentPage--; render(); } };
$("btn_next_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  if (currentPage < totalPages) { currentPage++; render(); }
};
$("btn_last_page").onclick = () => {
  const shown = getFilteredNodes();
  const totalPages = Math.ceil(shown.length / pageSize) || 1;
  currentPage = totalPages;
  render();
};

async function testNode(btn, id, event){
  if (event) event.stopPropagation();
  testingNodeIds.add(id);
  render();
  
  try {
    const response = await fetchWithCsrf("./api/test_node", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = response;
    if (result.ok && result.node) {
      const idx = nodes.findIndex(n => n && n.id === id);
      if (idx !== -1) {
        nodes[idx] = result.node;
      }
    }
  } catch (e) {
  } finally {
    testingNodeIds.delete(id);
    render();
  }
}

async function batchTestFiltered() {
  const filtered = getFilteredNodes();
  if (filtered.length === 0) {
    return;
  }
  batchTesting = true;
  const btn = $("btn_batch_test");
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = '<svg style="animation: spin 1s linear infinite; width:16px; height:16px; display:inline-block; margin-right:4px;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-opacity="0.2" fill="none"></circle><path d="M4 12a8 8 0 018-8" stroke="currentColor" fill="none"></path></svg>检测中...';
  }
  render();
  try {
    const ids = filtered.map(n => n.id);
    const response = await fetchWithCsrf("./api/test_nodes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids })
    });
    if (response.ok && Array.isArray(response.nodes)) {
      const resultsMap = {};
      for (const r of response.nodes) {
        if (r && r.id) {
          resultsMap[r.id] = r;
        }
      }
      for (let i = 0; i < nodes.length; i++) {
        const updated = resultsMap[nodes[i] && nodes[i].id];
        if (updated) {
          nodes[i] = updated;
        }
      }
    }
  } catch (e) {
  } finally {
    batchTesting = false;
    if (btn) {
      btn.disabled = false;
      btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" /></svg>一键检测';
    }
    render();
  }
}

async function toggleFavorite(id, event) {
  if (event) event.stopPropagation();
  try {
    const response = await fetchWithCsrf("./api/toggle_favorite", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id })
    });
    const result = response;
    if (result.ok) {
      state.favorite_node_ids = Array.isArray(result.favorite_node_ids) ? result.favorite_node_ids : [];
      render();
    }
  } catch (e) {
    console.error("切换收藏失败", e);
  }
}

let pollInterval = null;

function startConnectionPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(async () => {
    try {
      const data = await fetchWithCsrf("./api/nodes");
      nodes = Array.isArray(data.nodes) ? data.nodes : [];
      state = data.state || {};
      stableSortNodes();
      updateCountryFilter();
      updateSourceFilter();
      render();
      
      if (!state.is_connecting) {
        clearInterval(pollInterval);
        pollInterval = null;
        try {
          const result = await fetchWithCsrf("./api/test_proxy", { method: "POST" });
        } catch(pe){}
        load();
      }
    } catch(pe) {
      clearInterval(pollInterval);
      pollInterval = null;
      load();
    }
  }, 1000);
}

async function connectNode(id){
  state.is_connecting = true;
  state.active_openvpn_node_id = id;
  state.active_node_latency = "正在连接";
  state.last_check_message = "正在发送连接请求...";
  render();
  
  startConnectionPolling();
  
  try {
    const r = await fetchWithCsrf("./api/connect",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({id})
    });
    const result = r;
    if (!result.ok) {
      alert("连接失败: " + (result.error || "未知错误"));
      if (pollInterval) {
        clearInterval(pollInterval);
        pollInterval = null;
      }
      state.is_connecting = false;
      render();
      return;
    }
  } catch(e) {
    alert("连接请求错误: " + (e.message || "未知错误"));
    if (pollInterval) {
      clearInterval(pollInterval);
      pollInterval = null;
    }
    state.is_connecting = false;
    render();
  }
}

async function disconnectNode(){
  if (!confirm("确定要断开当前的 VPN 连接吗？")) return;
  try {
    const response = await fetchWithCsrf("./api/disconnect", { method: "POST" });
    const result = response;
    if (result.ok) {
      try {
        await fetchWithCsrf("./api/test_proxy", { method: "POST" });
      } catch(pe){}
      load();
    } else {
      alert("断开连接失败: " + (result.error || "未知错误"));
    }
  } catch (e) {
    alert("请求断开连接失败");
  }
}





const THEME_KEY = 'aimili_theme';
var themeLabels = { light: '明亮模式', dark: '暗黑模式', system: '跟随系统' };
var themeIcons = {
  light: '<path stroke-linecap="round" stroke-linejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />',
  dark: '<path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.718 9.718 0 0118 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 003 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 009.002-5.998z" />',
  system: '<path stroke-linecap="round" stroke-linejoin="round" d="M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25" />'
};
function getThemeIcon(theme) { return themeIcons[theme] || themeIcons.light; }
function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme === 'system' ? (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme);
  var si = document.getElementById('sidebar_theme_icon');
  if (si) si.innerHTML = getThemeIcon(theme);
  var sl = document.getElementById('sidebar_theme_label');
  if (sl) sl.textContent = themeLabels[theme] || themeLabels.light;
  localStorage.setItem(THEME_KEY, theme);
}
function toggleTheme() {
  var saved = localStorage.getItem(THEME_KEY) || 'light';
  var next = saved === 'light' ? 'dark' : (saved === 'dark' ? 'system' : 'light');
  setTheme(next);
}
function toggleSidebar() {
  document.getElementById('sidebar').classList.toggle('open');
  document.getElementById('sidebar_overlay').classList.toggle('open');
}
function toggleSidebarTheme() {
  toggleTheme();
}

async function load(){
  const r=await fetchWithCsrf("./api/nodes"); 
  const d=r;
  nodes=Array.isArray(d.nodes) ? d.nodes : []; 
  console.log("[load] nodes count:", nodes.length, "first node:", nodes[0] ? nodes[0].id : "none");
  state=d.state||{}; 
  console.log("[load] state.last_fetch_status:", state.last_fetch_status);
  
  if (state.country_translations) {
    countryDict = state.country_translations;
  }
  
  // Fetch CSRF token on load
  try {
    const csrfResp = await fetchWithCsrf("./api/csrf_token");
    if (csrfResp.csrf_token) {
      csrfToken = csrfResp.csrf_token;
    }
  } catch(e) {}
  
  stableSortNodes();
  updateCountryFilter();
  populateRoutingCountries();
  render();

  if (state.is_connecting) {
    startConnectionPolling();
  }
}
$("country_filter").onchange=()=>{ currentPage = 1; render(); };
$("ip_type_filter").onchange=()=>{ currentPage = 1; render(); };
$("status_filter").onchange=()=>{ currentPage = 1; render(); };
$("source_filter").onchange=()=>{ currentPage = 1; render(); };
$("health_filter").onchange=()=>{ currentPage = 1; render(); };

function toggleSettingsSubmenu() {
  const sub = $("settings_submenu");
  const toggle = $("settings_toggle");
  if (sub) {
    const isOpen = sub.style.display === "block";
    sub.style.display = isOpen ? "none" : "block";
    if (toggle) toggle.classList.toggle("open", !isOpen);
  }
}

function switchPage(name) {
  document.querySelectorAll(".page-content").forEach(function(p) { p.style.display = "none"; });
  document.querySelectorAll(".nav-item").forEach(function(n) { n.classList.remove("active"); });
  var page = document.getElementById("page_" + name);
  if (page) page.style.display = "";
  var nav = document.getElementById("nav_" + name);
  if (nav) nav.classList.add("active");
  localStorage.setItem("vpngate_page", name);
}

async function doRefreshNodes(){ 
  const el=$("sidebar_refresh");
  el.style.pointerEvents="none"; 
  el.style.opacity="0.6"; 
  try{await fetchWithCsrf("./api/refresh_nodes",{method:"POST"}); await load();} 
  catch(e){}
  setTimeout(()=>{
    el.style.pointerEvents=""; 
    el.style.opacity="";
  }, 3000);
};
$("btn_test_proxy").onclick = async () => {
  const btn = $("btn_test_proxy");
  const badge = $("proxy_status_badge");
  const ipVal = $("proxy_ip_val");
  const latVal = $("proxy_latency_val");
  
  btn.disabled = true;
  btn.innerHTML = `<span class="badge-pulse"></span>测试中...`;
  badge.className = "badge not_checked";
  badge.textContent = "检测中...";
  ipVal.textContent = "-";
  latVal.textContent = "";
  
  try {
    const response = await fetchWithCsrf("./api/test_proxy", { method: "POST" });
    const result = response;
    if (result.ok) {
      badge.className = "badge available";
      badge.textContent = "可用";
      ipVal.textContent = result.ip || "-";
      
      const latencyClass = getLatencyClass(result.latency_ms);
      latVal.innerHTML = `<span class="latency-val ${latencyClass}" style="margin-left:8px;">${result.latency_ms} ms</span>`;
    } else {
      badge.className = "badge unavailable";
      badge.textContent = "不可用";
      ipVal.textContent = "-";
      latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;" title="${esc(result.error)}">连接失败</span>`;
    }
  } catch (e) {
    badge.className = "badge unavailable";
    badge.textContent = "网络错误";
    ipVal.textContent = "-";
    latVal.innerHTML = `<span class="latency-val latency-poor" style="margin-left:8px; font-size:11px;">请求出错</span>`;
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" style="width:16px; height:16px;" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"><path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" /></svg> 测试代理`;
  }
};

let showFavoritesOnly = false;

function toggleFavoritesView() {
  showFavoritesOnly = !showFavoritesOnly;
  currentPage = 1;
  render();
}

function updateFavPanelUI() {
  const panel = $("favorites_panel");
  if (!panel) return;
  panel.style.display = showFavoritesOnly ? "block" : "none";
  
  const btn = $("btn_favorites");
  if (btn) {
    if (showFavoritesOnly) {
      btn.classList.add("active");
    } else {
      btn.classList.remove("active");
    }
  }

  if (showFavoritesOnly && state) {
    const fallbackCheckbox = $("fav_fail_fallback_checkbox");
    if (fallbackCheckbox) {
      fallbackCheckbox.checked = !!state.fav_fail_fallback;
    }
    
    const warningDiv = $("fav_fallback_warning");
    if (warningDiv) {
      warningDiv.style.display = state.fav_fail_fallback ? "none" : "block";
    }

    const favRoutingBtn = $("btn_toggle_fav_routing");
    if (favRoutingBtn) {
      if (state.routing_mode === "favorites") {
        favRoutingBtn.textContent = "禁用仅用收藏出站";
        favRoutingBtn.style.background = "var(--danger-gradient)";
        favRoutingBtn.style.borderColor = "transparent";
        favRoutingBtn.style.color = "#ffffff";
        favRoutingBtn.style.boxShadow = "0 0 12px rgba(244, 63, 94, 0.3)";
      } else {
        favRoutingBtn.textContent = "启用仅用收藏出站";
        favRoutingBtn.style.background = "#f1f5f9";
        favRoutingBtn.style.borderColor = "var(--border-color)";
        favRoutingBtn.style.color = "var(--text-primary)";
        favRoutingBtn.style.boxShadow = "none";
      }
    }
  }
}

async function toggleFavRouting() {
  if (!state) return;
  const newMode = state.routing_mode === "favorites" ? "auto" : "favorites";
  
  state.routing_mode = newMode;
  updateFavPanelUI();
  
  try {
    const res = await fetchWithCsrf("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: newMode,
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all",
        fav_fail_fallback: state.fav_fail_fallback !== false
      })
    });
    if (res.ok) {
      load();
    } else {
      alert("更新出站路由设置失败: " + (res.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败: " + (err.message || "请稍后重试"));
    load();
  }
}

async function handleFavFallbackChange(checked) {
  if (!state) return;
  
  if (!checked) {
    alert("⚠️ 警告：不勾选此项可能在所有收藏节点失效时造成网络彻底断开连接，无法自动切换到其他非收藏的可用节点！");
  }
  
  state.fav_fail_fallback = checked;
  updateFavPanelUI();
  
  try {
    const res = await fetchWithCsrf("./api/update_routing", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        routing_mode: state.routing_mode || "auto",
        force_country: state.force_country || "",
        routing_ip_type: state.routing_ip_type || "all",
        fav_fail_fallback: checked
      })
    });
    if (res.ok) {
      load();
    } else {
      alert("更新失败: " + (res.error || "未知错误"));
      load();
    }
  } catch (err) {
    alert("连接服务器失败: " + (err.message || "请稍后重试"));
    load();
  }
}

function selectOptionCard(groupName, value) {
  if (groupName === 'routing_mode') {
    const input = $("net_routing_mode");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_mode_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
    
    handleRoutingModeChange(value);
  } else if (groupName === 'routing_ip_type') {
    const input = $("net_routing_ip_type");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#routing_ip_type_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  } else if (groupName === 'upstream_type') {
    const input = $("net_upstream_type");
    if (input) input.value = value;
    
    const cards = document.querySelectorAll("#upstream_type_group .option-card");
    cards.forEach(card => {
      if (card.getAttribute("data-value") === value) {
        card.classList.add("active");
      } else {
        card.classList.remove("active");
      }
    });
  }
}

function setRoutingMode(value) {
  selectOptionCard('routing_mode', value);
}

function setRoutingIpType(value) {
  selectOptionCard('routing_ip_type', value);
}

function handleRoutingModeChange(mode) {
  const countryGroup = $("net_force_country_group");
  const warningDiv = $("net_routing_warning");
  
  if (mode === "fixed_region") {
    countryGroup.style.display = "block";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定地区</strong>：限制仅连接选定国家的节点，且后台仅并发测速该国家的节点。如果该国的所有可用节点都失效，会造成代理中断且<strong>绝不自动切换到其他国家</strong>的节点。`;
  } else if (mode === "favorites") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>仅用收藏</strong>：只连接和切换您收藏的节点。如果所有收藏的节点均失效，系统不会自动切换到未收藏的节点。请确保收藏列表中有足够多且可用的节点。`;
  } else if (mode === "fixed_ip") {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--warning)";
    warningDiv.style.background = "rgba(245, 158, 11, 0.1)";
    warningDiv.style.border = "1px solid rgba(245, 158, 11, 0.2)";
    warningDiv.innerHTML = `⚠️ <strong>固定IP</strong>：锁定当前连接的节点。不管该节点是否失效，系统都绝不自动切换至其他IP；如果节点由于网络故障失效，会造成代理中断（但如果OpenVPN连接意外退出，脚本将尝试为您在后台重新拉起连接同一IP）。<br><strong>提示</strong>：您可以在主页 of 节点列表中直接点击“连接”按钮来选择并锁定不同的IP节点。`;
  } else {
    countryGroup.style.display = "none";
    warningDiv.style.color = "var(--text-secondary)";
    warningDiv.style.background = "var(--surface)";
    warningDiv.style.border = "1px solid var(--border)";
    warningDiv.innerHTML = `ℹ️ <strong>自动配置</strong>：全自动测试并选择最佳IP。在使用过程中，如果当前连接节点没有失效，将不再更换IP；如果当前节点失效，系统将立刻秒级自动漂移到其他最快的可用节点。`;
  }
}

function populateRoutingCountries() {
  const select = $("net_force_country");
  if (!select) return;
  const countMap = {};
  nodes.forEach(n => {
    const c = translateCountry(n.country);
    if (c) {
      countMap[c] = (countMap[c] || 0) + 1;
    }
  });
  
  const countries = Object.keys(countMap).sort();
  let html = '<option value="">请选择要锁定的国家...</option>';
  countries.forEach(c => {
    html += `<option value="${esc(c)}">${esc(c)} (${countMap[c]}个节点)</option>`;
  });
  select.innerHTML = html;
  
  if (state) {
    select.value = state.force_country ? translateCountry(state.force_country) : "";
  }
}

function openCredentialsModal() {
  $("credentials_error").style.display = "none";
  $("credentials_success").style.display = "none";
  $("credentials_form").reset();
  if (state) {
    $("cred_username").value = state.username || "";
    $("cred_password").value = "";
    $("cred_port").value = state.port || 8790;
    $("cred_suffix").value = state.secret_path || "";
  }
  $("credentials_modal").style.display = "flex";
}

function closeCredentialsModal() {
  $("credentials_modal").style.display = "none";
}

function openNetworkModal() {
  $("network_error").style.display = "none";
  $("network_success").style.display = "none";
  $("network_form").reset();
  if (state) {
    $("net_proxy_port").value = state.proxy_port || 7928;
    $("net_routing_mode").value = state.routing_mode || "auto";
    $("net_force_country").value = state.force_country || "";
    $("net_routing_ip_type").value = state.routing_ip_type || "all";
    
    const up = state.upstream_proxy || {};
    $("net_upstream_enabled").checked = !!up.enabled;
    if (up.enabled) {
      $("net_upstream_type").value = up.type || "socks";
      setUpstreamType(up.type || "socks");
      $("net_upstream_host").value = up.host || "";
      $("net_upstream_port").value = up.port || 0;
      $("net_upstream_user").value = up.user || "";
      $("net_upstream_pass").value = up.pass || "";
    }
    handleRoutingModeChange(state.routing_mode || "auto");
    setRoutingIpType(state.routing_ip_type || "all");
  }
  $("network_modal").style.display = "flex";
}

function closeNetworkModal() {
  $("network_modal").style.display = "none";
}

function toggleUpstreamFields() {
  const enabled = $("net_upstream_enabled").checked;
  $("upstream_proxy_fields").style.display = enabled ? "block" : "none";
}

async function saveCredentials(e) {
  e.preventDefault();
  const errorDivEl = $("credentials_error");
  const successDiv = $("credentials_success");
  const submitBtn = $("credentials_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const username = $("cred_username").value.trim();
  const password = $("cred_password").value.trim();
  const port = parseInt($("cred_port").value);
  const suffix = $("cred_suffix").value.trim();
  
  if (!username || (!password && !(state && state.password_set))) {
    errorDivEl.textContent = "用户名不能为空；首次设置时密码不能为空";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (isNaN(port) || port < 1 || port > 65535) {
    errorDivEl.textContent = "网页管理端口范围必须在 1 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (!/^[A-Za-z0-9]+$/.test(suffix)) {
    errorDivEl.textContent = "登录安全后缀仅能由英文字母和数字组成";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (state && port === state.proxy_port) {
    errorDivEl.textContent = "网页管理端口不能与代理出站端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetchWithCsrf("./api/update_credentials", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: username,
        password: password,
        port: port,
        secret_path: suffix
      })
    });
    
    if (res.ok) {
      if (res.restart_needed) {
        successDiv.textContent = "保存成功！网页管理端口或路径已变更，页面将在 4 秒内自动跳转...";
        successDiv.style.display = "block";
        
        const inputs = $("credentials_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          const protocol = window.location.protocol;
          const host = window.location.hostname;
          window.location.href = `${protocol}//${host}:${port}/${suffix}/`;
        }, 4000);
      } else {
        successDiv.textContent = res.reauth_required ? "账号密码保存成功，请重新登录..." : "账号密码保存成功，已即时生效！";
        successDiv.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.textContent = "保存修改";
        setTimeout(() => {
          if (res.reauth_required) {
            window.location.reload();
          } else {
            closeCredentialsModal();
            load();
          }
        }, 1500);
      }
    } else {
      errorDivEl.textContent = res.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = err.message || "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}

async function saveNetwork(e) {
  e.preventDefault();
  const errorDivEl = $("network_error");
  const successDiv = $("network_success");
  const submitBtn = $("network_submit_btn");
  
  errorDivEl.style.display = "none";
  successDiv.style.display = "none";
  
  const proxyPort = parseInt($("net_proxy_port").value);
  const routingMode = $("net_routing_mode").value;
  const forceCountry = $("net_force_country").value;
  const routingIpType = $("net_routing_ip_type").value;
  
  const upstreamEnabled = $("net_upstream_enabled").checked;
  const upstreamType = $("net_upstream_type").value;
  const upstreamHost = ($("net_upstream_host").value || "").trim();
  const upstreamPort = parseInt($("net_upstream_port").value) || 0;
  const upstreamUser = ($("net_upstream_user").value || "").trim();
  const upstreamPass = ($("net_upstream_pass").value || "").trim();
  
  if (upstreamEnabled) {
    if (!upstreamHost) {
      errorDivEl.textContent = "请输入上游代理地址";
      errorDivEl.style.display = "block";
      return;
    }
    if (!upstreamPort || upstreamPort < 1 || upstreamPort > 65535) {
      errorDivEl.textContent = "上游代理端口范围必须在 1 至 65535 之间";
      errorDivEl.style.display = "block";
      return;
    }
  }
  
  if (isNaN(proxyPort) || proxyPort < 1024 || proxyPort > 65535) {
    errorDivEl.textContent = "代理出站端口范围必须在 1024 至 65535 之间";
    errorDivEl.style.display = "block";
    return;
  }

  if (state && proxyPort === state.port) {
    errorDivEl.textContent = "代理出站端口不能与网页管理端口相同";
    errorDivEl.style.display = "block";
    return;
  }
  
  if (routingMode === "fixed_region" && !forceCountry) {
    errorDivEl.textContent = "请选择一个要锁定的目标国家";
    errorDivEl.style.display = "block";
    return;
  }
  
  submitBtn.disabled = true;
  submitBtn.textContent = "正在保存...";
  
  try {
    const res = await fetchWithCsrf("./api/update_settings", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        proxy_port: proxyPort,
        routing_mode: routingMode,
        force_country: forceCountry,
        routing_ip_type: routingIpType,
        upstream_proxy: upstreamEnabled ? {
          enabled: true,
          type: upstreamType,
          host: upstreamHost,
          port: upstreamPort,
          user: upstreamUser,
          pass: upstreamPass
        } : { enabled: false }
      })
    });
    
    if (res.ok) {
      if (res.restart_needed) {
        successDiv.textContent = "保存成功！代理出站端口已变更，页面将在 4 秒内自动刷新...";
        successDiv.style.display = "block";
        
        const inputs = $("network_form").querySelectorAll("input, button");
        inputs.forEach(el => el.disabled = true);
        
        setTimeout(() => {
          window.location.reload();
        }, 4000);
      } else {
        successDiv.textContent = "配置保存成功，已即时生效！";
        successDiv.style.display = "block";
        submitBtn.disabled = false;
        submitBtn.textContent = "保存修改";
        setTimeout(() => {
          closeNetworkModal();
          load();
        }, 1500);
      }
    } else {
      errorDivEl.textContent = res.error || "保存失败，请检查输入";
      errorDivEl.style.display = "block";
      submitBtn.disabled = false;
      submitBtn.textContent = "保存修改";
    }
  } catch (err) {
    errorDivEl.textContent = err.message || "连接服务器失败，请稍后重试";
    errorDivEl.style.display = "block";
    submitBtn.disabled = false;
    submitBtn.textContent = "保存修改";
  }
}


async function logoutAdmin() {
  try {
    const res = await fetchWithCsrf("./api/logout", { method: "POST" });
    if (res.ok) {
      window.location.reload();
    }
  } catch (err) {
    console.error("退出登录失败", err);
    window.location.reload();
  }
}

// 页面加载时自动初始化数据
load();

// 每 10 秒在前台空闲时自动更新节点与状态，无需手动刷新页面
setInterval(async () => {
  if (typeof state !== "undefined" && !state.is_connecting && (!testingNodeIds || !testingNodeIds.size) && document.visibilityState === "visible") {
    try {
      const d = await fetchWithCsrf("./api/nodes");
      nodes = d.nodes || [];
      state = d.state || {};
      stableSortNodes();
      updateCountryFilter();
      updateSourceFilter();
      render();
    } catch(e) {}
  }
}, 10000);
let gatewayPollInterval = null;

function openGatewayModal() {
  $("gateway_modal").style.display = "flex";
  loadGatewayStatus();
  if (gatewayPollInterval) clearInterval(gatewayPollInterval);
  gatewayPollInterval = setInterval(loadGatewayStatus, 3000);
}

function closeGatewayModal() {
  $("gateway_modal").style.display = "none";
  if (gatewayPollInterval) {
    clearInterval(gatewayPollInterval);
    gatewayPollInterval = null;
  }
}

async function loadGatewayStatus() {
  try {
    const res = await fetchWithCsrf("./api/gateway_status");
    if (res.ok && res.services) {
      renderGatewayServices(res.services);
    }
  } catch (e) {
    console.error("加载网关状态失败", e);
  }
}

function renderGatewayServices(services) {
  const container = $("gateway_services_list");
  if (!container) return;
  
  let html = "";
  services.forEach(s => {
    const statusText = s.status === "running" ? "正在运行" : "已停止";
    const badgeClass = s.status === "running" ? "available" : "unavailable";
    const statusPulse = s.status === "running" ? '<span class="badge-pulse"></span>' : '';
    
    html += `
      <div style="background: var(--surface-2); border: 1px solid var(--border-color); border-radius: 10px; padding: 12px 16px; display: flex; flex-direction: column; gap: 6px;">
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <strong style="font-size: 14px; color: var(--text-primary);">${esc(s.name)}</strong>
          <span class="badge ${badgeClass}">${statusPulse}${statusText}</span>
        </div>
        <div style="font-size: 12px; color: var(--text-secondary);">${esc(s.details || "-")}</div>
        ${s.error ? `
          <div style="font-size: 12px; color: var(--danger); background: rgba(244,63,94,0.08); border: 1px solid rgba(244,63,94,0.15); border-radius: 6px; padding: 6px 10px; margin-top: 4px; line-height: 1.4;">
            ⚠️ 诊断原因: ${esc(s.error)}
          </div>
        ` : ''}
      </div>
    `;
  });
  container.innerHTML = html;
}

let logsPollInterval = null;
let rawLogsCache = [];

function openLogsModal() {
  $("logs_modal").style.display = "flex";
  loadLogs();
  if (logsPollInterval) clearInterval(logsPollInterval);
  logsPollInterval = setInterval(loadLogs, 5000);
}

function closeLogsModal() {
  $("logs_modal").style.display = "none";
  if (logsPollInterval) {
    clearInterval(logsPollInterval);
    logsPollInterval = null;
  }
}

async function loadLogs() {
  try {
    const res = await fetchWithCsrf("./api/logs");
    if (res.logs) {
      rawLogsCache = res.logs;
      filterAndRenderLogs();
    }
  } catch (e) {
    console.error("加载日志失败", e);
  }
}

let lastRenderedLogKey = "";
function filterAndRenderLogs() {
  const filterVal = $("log_filter_select").value;
  const term = $("log_terminal_container");
  if (!term) return;
  
  let filtered = rawLogsCache;
  if (filterVal === "proxy") {
    filtered = rawLogsCache.filter(l => l.module === "Proxy");
  } else if (filterVal === "vpn") {
    filtered = rawLogsCache.filter(l => l.module === "VPN");
  } else if (filterVal === "system") {
    filtered = rawLogsCache.filter(l => !["Proxy", "VPN"].includes(l.module));
  }
  
  const renderKey = filterVal + "|" + (filtered.length > 0 ? filtered[filtered.length - 1].timestamp + filtered[filtered.length - 1].message : "");
  if (renderKey === lastRenderedLogKey) return;
  lastRenderedLogKey = renderKey;
  
  if (filtered.length === 0) {
    term.innerHTML = `<div style="color: var(--text-secondary); text-align: center; margin-top: 150px;">暂无该类型日志。</div>`;
    return;
  }
  
  const linesHtml = filtered.map(l => {
    let color = "#a5b4fc";
    if (l.module === "Proxy") color = "#38bdf8";
    if (l.module === "VPN") color = "#34d399";
    if (l.level === "WARNING") color = "#fbbf24";
    if (l.level === "ERROR") color = "#f43f5e";
    
    return `<div style="color: ${color}; margin-bottom: 4px;">[${esc(l.timestamp)}] [${esc(l.level)}] [${esc(l.module)}] ${esc(l.message)}</div>`;
  }).join("");
  
  const isAtBottom = term.scrollHeight - term.clientHeight <= term.scrollTop + 50;
  
  term.innerHTML = linesHtml;
  
  if (isAtBottom) {
    term.scrollTop = term.scrollHeight;
  }
}

function copyLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供复制的日志。");
    return;
  }
  
  navigator.clipboard.writeText(text).then(() => {
    alert("日志内容已成功复制到剪贴板！");
  }).catch(err => {
    console.error("复制失败", err);
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    alert("日志内容已复制到剪贴板！");
  });
}

function exportLogContent() {
  const term = $("log_terminal_container");
  if (!term) return;
  
  const text = term.innerText || term.textContent;
  if (!text || text.includes("暂无今日") || text.includes("暂无该类型")) {
    alert("当前没有可供导出的日志。");
    return;
  }
  
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  const dateStr = new Date().toISOString().slice(0, 10);
  const filterVal = $("log_filter_select").value;
  a.download = `vpngate_log_${filterVal}_${dateStr}.txt`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
URL.revokeObjectURL(url);
}

// 页面初始化
(function(){
  var saved = localStorage.getItem("vpngate_page") || "overview";
  switchPage(saved);
})();

// 主题初始化
(function(){
  var saved = localStorage.getItem(THEME_KEY) || 'light';
  setTheme(saved);
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', function(){
    if (localStorage.getItem(THEME_KEY) === 'system') {
      setTheme('system');
    }
  });
})();

</script>
</main>
</div>
</body></html>"""

def check_proxy_health() -> dict[str, Any]:
    # 1. 检测代理服务端口是否在监听
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    s = None
    try:
        s = socket.socket(af, socket.SOCK_STREAM)
        s.settimeout(1.5)
        connect_host = LOCAL_PROXY_HOST
        if connect_host in ("::", "0.0.0.0", ""):
            connect_host = "::1" if is_ipv6 else "127.0.0.1"
        try:
            s.connect((connect_host, LOCAL_PROXY_PORT))
        except Exception as e:
            if connect_host == "::1":
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.5)
                s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
            else:
                raise e
    except Exception as e:
        diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
        diag_msg = diag[1] if diag else f"端口 {LOCAL_PROXY_PORT} 连接失败，原因: {e}"
        return {
            "ok": False,
            "error": f"代理服务未运行 ({diag_msg})"
        }
    finally:
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # 2. 检测虚拟网卡 tun0 是否存在 (Linux 下)
    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    # 3. 使用 curl 通过本地 SOCKS5 代理接口测试 IP 与实际延迟
    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        proxy_hosts = []
        if LOCAL_PROXY_HOST == "::":
            proxy_hosts = ["[::1]", "127.0.0.1"]
        elif LOCAL_PROXY_HOST == "0.0.0.0":
            proxy_hosts = ["127.0.0.1"]
        elif ":" in LOCAL_PROXY_HOST:
            proxy_hosts = [f"[{LOCAL_PROXY_HOST}]", "127.0.0.1"]
        else:
            proxy_hosts = [LOCAL_PROXY_HOST]

        for p_host in proxy_hosts:
            proxy_url = f"socks5h://{p_host}:{LOCAL_PROXY_PORT}"
            proxy_user, proxy_pass = proxy_server.get_proxy_credentials()
            cmd = [
                "curl", "-s",
                "-w", "\n%{time_total} %{http_code}",
                "-x", proxy_url,
                url,
                "--max-time", "5"
            ]
            if proxy_user is not None and proxy_pass is not None:
                cmd.extend(["--proxy-user", f"{proxy_user}:{proxy_pass}"])
            try:
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if res.returncode == 0:
                    lines = res.stdout.strip().splitlines()
                    if len(lines) >= 2:
                        ip = lines[0].strip()
                        time_info = lines[1].strip().split()
                        if len(time_info) == 2:
                            total_time_str, http_code = time_info
                            if http_code == "200" and ip:
                                latency_ms = int(float(total_time_str) * 1000)
                                return {"ok": True, "ip": ip, "latency_ms": latency_ms}
            except Exception:
                pass
        return None

    try:
        result = _curl_check_ip("http://ip.sb")
        if result:
            return result
        result = _curl_check_ip("http://api.ipify.org")
        if result:
            return result
            
        # 此时外网测试失败，检测本地代理端口是否依然能连通。若仍能连通，直接抛出出口测试失败，不调用占用诊断
        port_still_listening = False
        test_sock = None
        try:
            test_sock = socket.socket(af, socket.SOCK_STREAM)
            test_sock.settimeout(1.0)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                test_sock.connect((connect_host, LOCAL_PROXY_PORT))
                port_still_listening = True
            except Exception:
                if connect_host == "::1":
                    test_sock.close()
                    test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_sock.settimeout(1.0)
                    test_sock.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                    port_still_listening = True
        except Exception:
            pass
        finally:
            if test_sock is not None:
                try:
                    test_sock.close()
                except Exception:
                    pass

        if not port_still_listening:
            diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
            if diag:
                return {"ok": False, "error": f"出口连接测试失败 | 本机诊断结果: {diag[1]}"}
            
        return {"ok": False, "error": "出口连接测试失败 (ip.sb 和 api.ipify.org 均无法连通，可能是节点已失效或 VPS 防火墙限制了 UDP/TCP 出站端口)"}
    except Exception as e:
        return {"ok": False, "error": f"出口连接测试异常: {e}"}

def background_proxy_checker() -> None:
    global last_checker_heartbeat, is_connecting
    time.sleep(30)
    while True:
        last_checker_heartbeat = time.time()
        try:
            if is_connecting:
                time.sleep(5)
                continue

            res = check_proxy_health()
            if res["ok"]:
                set_state(
                    proxy_ok=True,
                    proxy_ip=res["ip"],
                    proxy_latency_ms=res["latency_ms"],
                    proxy_error=""
                )
                log_to_json("INFO", "Proxy", f"代理可用，IP: {res['ip']}, 延迟: {res['latency_ms']} ms")
            else:
                error_msg = res.get("error", "未知错误")
                if active_openvpn_node_id:
                    print(f"[警告] {LOCAL_PROXY_PORT} 端口本地代理当前不可用！原因: {error_msg}", flush=True)
                    log_to_json("WARNING", "Proxy", f"代理不可用: {error_msg}")
                set_state(
                    proxy_ok=False,
                    proxy_ip="-",
                    proxy_latency_ms=0,
                    proxy_error=error_msg
                )

                # If we intended to have an active VPN node but proxy failed, trigger auto-switch
                if active_openvpn_node_id:
                    ui_cfg = _cached_load_ui_config()
                    routing_mode = ui_cfg.get("routing_mode", "auto")
                    if routing_mode != "fixed_ip":
                        with lock:
                            nodes = read_nodes()
                            active_node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                            if active_node:
                                mark_blacklisted(active_node, f"代理连通性检测失败: {error_msg}")
                                active_node["probe_status"] = "unavailable"
                                write_json(NODES_FILE, nodes)
                        auto_switch_node()
                    else:
                        print(f"[代理守护线程] 固定 IP 模式下代理不可用，正在尝试重启连接同一节点: {active_openvpn_node_id}", flush=True)
                        is_connecting = False
                        try:
                            connect_node(active_openvpn_node_id)
                        except Exception as e:
                            print(f"[代理守护线程] 重启固定节点失败: {e}", flush=True)
        except Exception as e:
            print(f"[错误] 代理后台检测发生异常: {e}", flush=True)
            log_to_json("ERROR", "Proxy", f"检测守护线程发生异常: {e}")
        time.sleep(30)

def active_node_pinger() -> None:
    global last_pinger_heartbeat, last_active_ping_time, last_active_latency
    while True:
        last_pinger_heartbeat = time.time()
        try:
            if active_openvpn_running() and active_openvpn_node_id:
                nodes = read_nodes()
                node = next((n for n in nodes if n.get("id") == active_openvpn_node_id), None)
                if node:
                    ip = node.get("ip") or node.get("remote_host")
                    port = parse_int(node.get("remote_port"))
                    fallback = parse_int(node.get("ping"))
                    if ip:
                        latency = vpn_utils.ping_latency_ms(ip, port, fallback)
                        if latency > 0:
                            last_active_latency = latency
                            last_active_ping_time = time.time()
                            set_state(active_node_latency=f"{latency} ms")
                        else:
                            set_state(active_node_latency="检测超时")
                    else:
                        set_state(active_node_latency="检测超时")
                else:
                    set_state(active_node_latency="检测超时")
            elif is_connecting:
                set_state(active_node_latency="测试中...")
            else:
                if active_openvpn_node_id:
                    set_state(active_node_latency="无活动连接")
        except Exception as e:
            print(f"[ERROR] active_node_pinger error: {e}", flush=True)
        time.sleep(10)


class Handler(BaseHTTPRequestHandler):
    def get_secret_path(self) -> str:
        ui_cfg = _cached_load_ui_config()
        return ui_cfg.get("secret_path", "EJsW2EeBo9lY")

    def is_authorized(self) -> bool:
        ui_cfg = _cached_load_ui_config()
        pwd = ui_cfg.get("password")
        if not pwd:
            print("[Auth] 管理后台密码为空，已拒绝访问。请检查 ui_auth.json。", flush=True)
            return False
        
        cookie_header = self.headers.get("Cookie", "")
        cookies = {}
        if cookie_header:
            for item in cookie_header.split(";"):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    cookies[k.strip()] = v.strip()
        
        session_token = cookies.get("session")
        if not session_token:
            return False
            
        with lock:
            exp_time = active_sessions.get(session_token)
            if exp_time is not None and exp_time > time.time():
                return True
        return False

    def validate_path(self) -> str:
        secret_path = self.get_secret_path()
        request_path = urllib.parse.urlsplit(self.path).path
        if not secret_path:
            return request_path
        if request_path == f"/{secret_path}":
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", f"/{secret_path}/")
            self.end_headers()
            return ""
        prefix = f"/{secret_path}/"
        if request_path.startswith(prefix):
            return "/" + request_path[len(prefix):]
        self.send_response(HTTPStatus.NOT_FOUND)
        self.end_headers()
        return ""

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[{self.log_date_time_string()}] {format % args}", flush=True)

    def send_bytes(self, body: bytes, content_type: str, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, data: Any, status: HTTPStatus = HTTPStatus.OK) -> None:
        self.send_bytes(json.dumps(data, ensure_ascii=False).encode("utf-8"), "application/json; charset=utf-8", status)

    def read_request_body(self, max_bytes: int = 65536) -> bytes:
        length = parse_int(self.headers.get("Content-Length"))
        if length < 0:
            raise ValueError("Content-Length 无效")
        if length > max_bytes:
            raise ValueError(f"请求体过大，最大允许 {max_bytes} 字节")
        return self.rfile.read(length) if length > 0 else b""

    def read_json_body(self, max_bytes: int = 65536) -> dict[str, Any]:
        body = self.read_request_body(max_bytes)
        if not body:
            return {}
        data = json.loads(body.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求 JSON 必须是对象")
        return data

    def do_GET(self) -> None:
        print(f"[DEBUG] do_GET called with path: {self.path}", flush=True)
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if not self.is_authorized():
            if effective_path in ("/", "/index.html"):
                self.send_bytes(LOGIN_HTML.encode("utf-8"), "text/html; charset=utf-8")
                return
            else:
                self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
                
        if effective_path in ("/", "/index.html"):
            self.send_bytes(INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
        elif effective_path == "/api/nodes":
            print("[DEBUG] /api/nodes handler called", flush=True)
            global last_active_ping_time, last_active_latency, active_openvpn_node_id
            nodes = read_nodes()
            print(f"[DEBUG] /api/nodes read_nodes returned {len(nodes)} nodes", flush=True)
            active_node = next((n for n in nodes if active_openvpn_node_id and n.get("id") == active_openvpn_node_id), None)
            for n in nodes:
                n["active"] = (active_openvpn_node_id and n.get("id") == active_openvpn_node_id)
            if active_node:
                ip = active_node.get("ip") or active_node.get("remote_host")
                if ip:
                    now = time.time()
                    if now - last_active_ping_time > 15.0:
                        last_active_ping_time = now
                        def bg_ping(ip_addr: str, port: int, fallback: int) -> None:
                            global last_active_latency
                            try:
                                latency = vpn_utils.ping_latency_ms(ip_addr, port, fallback)
                                if latency > 0:
                                    last_active_latency = latency
                            except Exception:
                                pass
                        threading.Thread(
                            target=bg_ping, 
                            args=(ip, parse_int(active_node.get("remote_port")), parse_int(active_node.get("ping"))),
                            daemon=True
                        ).start()
                    if last_active_latency > 0:
                        active_node["latency_ms"] = last_active_latency
            stripped_nodes = []
            for n in nodes:
                stripped = n.copy()
                ct = stripped.get("config_text", "")
                if len(ct) > MAX_CONFIG_TEXT_LENGTH:
                    stripped["config_text_truncated"] = True
                stripped["has_config"] = bool(ct.strip())
                if "config_text" in stripped:
                    del stripped["config_text"]
                stripped_nodes.append(stripped)
            print(f"[DEBUG] /api/nodes returning {len(stripped_nodes)} nodes, sources: { {n.get('source', 'vpngate') for n in stripped_nodes} }", flush=True)
            self.send_json({"nodes": stripped_nodes, "state": get_state()})
        elif effective_path.startswith("/configs/"):
            filename = urllib.parse.unquote(effective_path.removeprefix("/configs/"))
            with lock:
                nodes = read_nodes()
                node = next((n for n in nodes if Path(n.get("config_file", "")).name == filename), None)
            if node and node.get("config_text"):
                self.send_bytes(node["config_text"].encode("utf-8"), "application/x-openvpn-profile")
            else:
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        elif effective_path == "/api/gateway_status":
            web_ui_status = {
                "name": "Web 管理服务",
                "status": "running",
                "details": f"监听地址: {_cached_load_ui_config().get('host', UI_HOST)}:{_cached_load_ui_config().get('port', UI_PORT)}",
                "error": ""
            }
            proxy_ok = False
            proxy_err = ""
            is_ipv6 = ":" in LOCAL_PROXY_HOST
            af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
            s = None
            try:
                s = socket.socket(af, socket.SOCK_STREAM)
                s.settimeout(0.5)
                connect_host = LOCAL_PROXY_HOST
                if connect_host in ("::", "0.0.0.0", ""):
                    connect_host = "::1" if is_ipv6 else "127.0.0.1"
                try:
                    s.connect((connect_host, LOCAL_PROXY_PORT))
                    proxy_ok = True
                except Exception:
                    if connect_host == "::1":
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        proxy_ok = True
                    else:
                        raise
            except Exception as e:
                diag = vpn_utils.diagnose_local_obstructions(LOCAL_PROXY_PORT, host=LOCAL_PROXY_HOST)
                proxy_err = diag[1] if diag else f"本地代理网关无法连通: {e}"
            finally:
                if s is not None:
                    try:
                        s.close()
                    except Exception:
                        pass
            proxy_gateway_status = {
                "name": "本地代理网关",
                "status": "running" if proxy_ok else "stopped",
                "details": f"监听地址: {LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
                "error": proxy_err
            }
            ovpn_ok = active_openvpn_running()
            ovpn_err = ""
            ovpn_details = "未连接"
            if ovpn_ok:
                ovpn_details = f"已连接节点: {active_openvpn_node_id}"
                if sys.platform.startswith("linux"):
                    if not Path("/sys/class/net/tun0").exists():
                        ovpn_err = "[警告] 虚拟网卡 (tun0) 未启用，可能存在策略路由配置问题。"
            else:
                if active_openvpn_node_id:
                    ovpn_err = "连接已中断或 OpenVPN 核心程序异常退出。"
                    ovpn_details = f"尝试连接节点 {active_openvpn_node_id} 失败"
            openvpn_status = {
                "name": "OpenVPN 核心连接",
                "status": "running" if ovpn_ok else "stopped",
                "details": ovpn_details,
                "error": ovpn_err
            }
            now = time.time()
            server_uptime = now - server_start_time
            collector_ok = (last_collector_heartbeat > 0.0 and now - last_collector_heartbeat < (CHECK_INTERVAL_SECONDS * 1.5)) or (server_uptime < 15.0)
            collector_status = {
                "name": "节点同步守护线程",
                "status": "running" if collector_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_collector_heartbeat)) if last_collector_heartbeat > 0 else '等待启动'}",
                "error": "" if collector_ok else "线程可能已异常终止，导致无法在后台拉取和测速新节点。"
            }
            checker_ok = (last_checker_heartbeat > 0.0 and now - last_checker_heartbeat < 90.0) or (server_uptime < 35.0)
            checker_status = {
                "name": "出口检测守护线程",
                "status": "running" if checker_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_checker_heartbeat)) if last_checker_heartbeat > 0 else '等待启动'}",
                "error": "" if checker_ok else "线程可能已挂起或终止，导致无法实时获取代理出口状态。"
            }
            pinger_ok = (last_pinger_heartbeat > 0.0 and now - last_pinger_heartbeat < 30.0) or (server_uptime < 15.0)
            pinger_status = {
                "name": "延迟测速守护线程",
                "status": "running" if pinger_ok else "stopped",
                "details": f"上次心跳: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(last_pinger_heartbeat)) if last_pinger_heartbeat > 0 else '等待启动'}",
                "error": "" if pinger_ok else "线程可能已中止，无法实时刷新活动节点的 Ping 延迟。"
            }
            self.send_json({
                "ok": True,
                "services": [
                    web_ui_status,
                    proxy_gateway_status,
                    openvpn_status,
                    collector_status,
                    checker_status,
                    pinger_status
                ]
            })
        elif effective_path == "/api/csrf_token":
            self.send_json({"ok": True, "csrf_token": _generate_csrf_token()})
        elif effective_path == "/api/logs":
            logs_dir = DATA_DIR / "logs"
            date_str = time.strftime("%Y-%m-%d", time.localtime())
            log_file = logs_dir / f"{date_str}.json"
            entries = deque(maxlen=200)
            if log_file.exists():
                try:
                    with lock:
                        with open(log_file, "r", encoding="utf-8") as f:
                            for line in f:
                                line = line.strip()
                                if line:
                                    try:
                                        entries.append(json.loads(line))
                                    except Exception:
                                        pass
                except Exception as e:
                    print(f"[API Logs] Error reading log file: {e}", flush=True)
            self.send_json({"logs": list(entries), "total": len(entries), "tail": len(entries)})
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        effective_path = self.validate_path()
        if effective_path == "": return
        
        if effective_path == "/api/login":
            client_ip = self.client_address[0] if not self.client_address[0].startswith("::ffff:") else self.client_address[0][7:]
            if not _check_login_rate_limit(client_ip):
                log_to_json("WARNING", "Auth", f"登录频率限制触发，IP: {client_ip}")
                self.send_json({"ok": False, "error": f"登录尝试过于频繁，请在 {LOGIN_RATE_LIMIT_WINDOW // 60} 分钟后重试"}, HTTPStatus.FORBIDDEN)
                return
            try:
                payload = self.read_json_body()
                input_pwd = str(payload.get("password") or "")
                input_uname = str(payload.get("username") or "")
                
                ui_cfg = load_ui_config()
                expected_pwd = ui_cfg.get("password", "")
                expected_uname = ui_cfg.get("username", "admin")
                
                if expected_pwd and input_pwd == expected_pwd and input_uname == expected_uname:
                    _record_login_attempt(client_ip)
                    log_audit("LOGIN_SUCCESS", "Auth", f"用户 {expected_uname} 登录成功", expected_uname)
                    token = uuid.uuid4().hex
                    with lock:
                        active_sessions[token] = time.time() + SESSION_TIMEOUT
                    body = json.dumps({"ok": True, "csrf_token": _generate_csrf_token()}).encode("utf-8")
                    self.send_response(HTTPStatus.OK)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.send_header("Cache-Control", "no-store")
                    secret_path = self.get_secret_path()
                    cookie_path = f"/{secret_path}/" if secret_path else "/"
                    self.send_header("Set-Cookie", f"session={token}; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=2592000")
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    _record_login_attempt(client_ip)
                    log_audit("LOGIN_FAILED", "Auth", f"登录失败，IP: {client_ip}", input_uname)
                    self.send_json({"ok": False, "error": "用户名或密码不正确，请重新输入"}, HTTPStatus.FORBIDDEN)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/logout":
            try:
                cookie_header = self.headers.get("Cookie", "")
                cookies = {}
                if cookie_header:
                    for item in cookie_header.split(";"):
                        item = item.strip()
                        if "=" in item:
                            k, v = item.split("=", 1)
                            cookies[k.strip()] = v.strip()
                session_token = cookies.get("session")
                if session_token:
                    with lock:
                        active_sessions.pop(session_token, None)
                secret_path = self.get_secret_path()
                cookie_path = f"/{secret_path}/" if secret_path else "/"
                body = json.dumps({"ok": True}).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"session=; Path={cookie_path}; HttpOnly; SameSite=Lax; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT")
                self.end_headers()
                self.wfile.write(body)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if not self.is_authorized():
            self.send_json({"error": "Unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        # CSRF validation for write operations (skip for login/logout)
        csrf_skip_paths = {"/api/login", "/api/logout"}
        if effective_path not in csrf_skip_paths:
            csrf_header = self.headers.get("X-CSRF-Token", "")
            cookie_csrf = ""
            cookie_header = self.headers.get("Cookie", "")
            if cookie_header:
                for item in cookie_header.split(";"):
                    item = item.strip()
                    if item.startswith("csrf_token="):
                        cookie_csrf = item.split("=", 1)[1].strip()
            submitted_token = csrf_header or cookie_csrf
            if not _validate_csrf_token(submitted_token):
                log_to_json("WARNING", "Auth", "CSRF 令牌验证失败")
                self.send_json({"ok": False, "error": "CSRF 令牌无效或已过期"}, HTTPStatus.FORBIDDEN)
                return

        if effective_path == "/api/update_credentials":
            try:
                payload = self.read_json_body()
                new_username = str(payload.get("username") or "").strip()
                new_password = str(payload.get("password") or "").strip()
                new_port = payload.get("port")
                new_suffix = str(payload.get("secret_path") or "").strip()
                
                ui_cfg = _cached_load_ui_config()
                if not new_username or (not new_password and not ui_cfg.get("password")):
                    self.send_json({"ok": False, "error": "用户名不能为空；首次设置时密码不能为空"}, HTTPStatus.BAD_REQUEST)
                    return
                
                try:
                    new_port_int = int(new_port)
                    if not (1 <= new_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "网页管理端口范围必须是 1 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return

                if not new_suffix or not re.match(r"^[A-Za-z0-9]+$", new_suffix):
                    self.send_json({"ok": False, "error": "安全后缀仅能由英文字母和数字组成"}, HTTPStatus.BAD_REQUEST)
                    return

                expected_username = ui_cfg.get("username", "")
                expected_password = ui_cfg.get("password", "")
                expected_port = ui_cfg.get("port", 8790)
                expected_suffix = ui_cfg.get("secret_path", "EJsW2EeBo9lY")

                ui_cfg["username"] = new_username
                if new_password:
                    ui_cfg["password"] = new_password
                ui_cfg["port"] = new_port_int
                ui_cfg["secret_path"] = new_suffix
                
                auth_file = DATA_DIR / "ui_auth.json"
                reauth_required = new_username != expected_username or (new_password and new_password != expected_password)
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                    if reauth_required:
                        active_sessions.clear()
                
                restart_needed = (new_port_int != expected_port or new_suffix != expected_suffix)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "reauth_required": reauth_required, "message": "配置更新成功，网页管理端口或路径已变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 管理后台安全配置更新，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    log_audit("UPDATE_CREDENTIALS", "Auth", f"账号/端口/路径已更新")
                    self.send_json({"ok": True, "restart_needed": False, "reauth_required": reauth_required, "message": "账号密码配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_settings":
            try:
                payload = self.read_json_body()
                
                new_proxy_port = payload.get("proxy_port")
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                
                try:
                    new_proxy_port_int = int(new_proxy_port)
                    if not (1024 <= new_proxy_port_int <= 65535):
                        raise ValueError()
                except (TypeError, ValueError):
                    self.send_json({"ok": False, "error": "代理出站端口范围必须是 1024 至 65535"}, HTTPStatus.BAD_REQUEST)
                    return
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = _cached_load_ui_config()
                expected_proxy_port = ui_cfg.get("proxy_port", 7928)
                
                if new_proxy_port_int == ui_cfg.get("port", 8790):
                    self.send_json({"ok": False, "error": "代理出站端口不能与网页管理端口相同"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg["proxy_port"] = new_proxy_port_int
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                
                upstream_data = payload.get("upstream_proxy")
                if upstream_data and isinstance(upstream_data, dict):
                    if upstream_data.get("enabled"):
                        ui_cfg["upstream_proxy"] = {
                            "enabled": True,
                            "type": str(upstream_data.get("type", "socks")).strip() or "socks",
                            "host": str(upstream_data.get("host", "")).strip(),
                            "port": int(upstream_data.get("port", 0)),
                            "user": str(upstream_data.get("user", "")).strip(),
                            "pass": str(upstream_data.get("pass", "")).strip()
                        }
                    else:
                        ui_cfg["upstream_proxy"] = { "enabled": False }
                elif "upstream_proxy" not in ui_cfg:
                    ui_cfg["upstream_proxy"] = { "enabled": False }
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                
                policy_message = enforce_active_node_allowed_by_routing(ui_cfg, "路由设置已更新")
                
                restart_needed = (new_proxy_port_int != expected_proxy_port)
                if restart_needed:
                    self.send_json({"ok": True, "restart_needed": True, "message": "配置更新成功，代理出站端口变更，将在 2 秒内重启..."})
                    
                    def restart_server():
                        time.sleep(2)
                        print("[系统] 代理出站端口变更，进程即将退出以触发自动重启...", flush=True)
                        os._exit(0)
                    
                    threading.Thread(target=restart_server, daemon=True).start()
                else:
                    log_audit("UPDATE_SETTINGS", "Settings", f"代理端口: {new_proxy_port_int}, 路由模式: {routing_mode}")
                    self.send_json({"ok": True, "restart_needed": False, "message": "配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/update_routing":
            try:
                payload = self.read_json_body()
                routing_mode = str(payload.get("routing_mode") or "auto").strip()
                force_country = str(payload.get("force_country") or "").strip()
                routing_ip_type = str(payload.get("routing_ip_type") or "all").strip()
                fav_fail_fallback = bool(payload.get("fav_fail_fallback", True))
                
                if routing_mode not in ("auto", "fixed_ip", "fixed_region", "favorites"):
                    self.send_json({"ok": False, "error": "无效的路由配置模式"}, HTTPStatus.BAD_REQUEST)
                    return
                if routing_ip_type not in ("all", "residential", "hosting"):
                    self.send_json({"ok": False, "error": "无效的IP出站类型过滤"}, HTTPStatus.BAD_REQUEST)
                    return
                
                ui_cfg = _cached_load_ui_config()
                ui_cfg["routing_mode"] = routing_mode
                ui_cfg["force_country"] = force_country
                ui_cfg["routing_ip_type"] = routing_ip_type
                ui_cfg["fav_fail_fallback"] = fav_fail_fallback
                ui_cfg.pop("enable_force_country", None)
                
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                
                enforce_active_node_allowed_by_routing(ui_cfg, "出站路由配置已更新")
                
                self.send_json({"ok": True, "message": "出站路由配置更新成功，已即时生效！"})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/audit_logs":
            with _audit_log_lock:
                self.send_json({"logs": list(_audit_logs)})
            return

        elif effective_path == "/api/events":
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(f"data: {json.dumps({'type': 'ping', 'data': {'timestamp': time.time()}})}\n\n".encode("utf-8"))
            self.wfile.flush()
            return

        elif effective_path == "/api/export_config":
            try:
                export_data = {
                    "version": "1.0",
                    "exported_at": time.time(),
                    "ui_config": load_ui_config(),
                    "state": get_state(),
                }
                body = json.dumps(export_data, ensure_ascii=False, indent=2).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="vpngate_config_backup.json"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                log_audit("EXPORT_CONFIG", "Config", "配置备份导出成功")
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/import_config":
            try:
                body_bytes = self.read_request_body(65536)
                if not body_bytes:
                    self.send_json({"ok": False, "error": "请求体为空"}, HTTPStatus.BAD_REQUEST)
                    return
                import_data = json.loads(body_bytes.decode("utf-8"))
                if not isinstance(import_data, dict):
                    self.send_json({"ok": False, "error": "无效的备份文件格式"}, HTTPStatus.BAD_REQUEST)
                    return
                ui_cfg = import_data.get("ui_config")
                if ui_cfg and isinstance(ui_cfg, dict):
                    auth_file = DATA_DIR / "ui_auth.json"
                    with lock:
                        DATA_DIR.mkdir(exist_ok=True, parents=True)
                        write_json(auth_file, ui_cfg)
                log_audit("IMPORT_CONFIG", "Config", "配置备份导入成功")
                self.send_json({"ok": True, "message": "配置导入成功，已即时生效！"})
            except json.JSONDecodeError:
                self.send_json({"ok": False, "error": "备份文件格式错误，不是有效的JSON"}, HTTPStatus.BAD_REQUEST)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        elif effective_path == "/api/toggle_favorite":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "").strip()
                
                ui_cfg = _cached_load_ui_config()
                fav_ids = ui_cfg.get("favorite_node_ids", [])
                if not isinstance(fav_ids, list):
                    fav_ids = []
                
                if node_id in fav_ids:
                    fav_ids.remove(node_id)
                else:
                    fav_ids.append(node_id)
                
                ui_cfg["favorite_node_ids"] = fav_ids
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                
                if ui_cfg.get("routing_mode") == "favorites":
                    enforce_active_node_allowed_by_routing(ui_cfg, "收藏列表已更新")
                
                self.send_json({"ok": True, "favorite_node_ids": fav_ids})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
            return

        if effective_path == "/api/check":
            try:
                self.send_json({"ok": True, "message": maintain_valid_nodes(force=True)})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/refresh_nodes":
            try:
                if maintenance_lock.locked():
                    self.send_json({"ok": True, "message": "节点维护任务正在运行，请稍后再试", "running": True})
                else:
                    threading.Thread(target=maintain_valid_nodes, args=(False,), daemon=True).start()
                    self.send_json({"ok": True, "message": "已在后台启动节点更新流程", "running": False})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_nodes":
            try:
                payload = self.read_json_body(max_bytes=262144)
                node_ids = payload.get("ids", [])
                tested_nodes = test_multiple_nodes(node_ids)
                self.send_json({"ok": True, "nodes": tested_nodes})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/disconnect":
            try:
                ui_cfg = _cached_load_ui_config()
                ui_cfg["connection_enabled"] = False
                auth_file = DATA_DIR / "ui_auth.json"
                with lock:
                    DATA_DIR.mkdir(exist_ok=True, parents=True)
                    write_json(auth_file, ui_cfg)
                
                stop_active_openvpn()
                with lock:
                    nodes = read_nodes()
                    for item in nodes:
                        item["active"] = False
                    write_json(NODES_FILE, nodes)
                global last_active_ping_time, last_active_latency
                last_active_ping_time = 0.0
                last_active_latency = 0
                set_state(active_openvpn_node_id="", last_check_message="手动断开连接", active_node_latency="无活动连接")
                broadcast_event("node_disconnected", {})
                self.send_json({"ok": True})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/connect":
            try:
                payload = self.read_json_body()
                self.send_json({"ok": True, "message": connect_node(str(payload.get("id") or ""))})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_node":
            try:
                payload = self.read_json_body()
                node_id = str(payload.get("id") or "")
                updated_node = test_node_by_id(node_id)
                self.send_json({"ok": True, "node": updated_node})
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        elif effective_path == "/api/test_proxy":
            try:
                self.read_request_body()
                result = check_proxy_health()
                if result["ok"]:
                    set_state(
                        proxy_ok=True,
                        proxy_ip=result["ip"],
                        proxy_latency_ms=result["latency_ms"],
                        proxy_error=""
                    )
                else:
                    set_state(
                        proxy_ok=False,
                        proxy_ip="-",
                        proxy_latency_ms=0,
                        proxy_error=result.get("error", "未知错误")
                    )
                self.send_json(result)
            except Exception as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)
        else:
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

class Tee:
    def __init__(self, file_path: str):
        Path(file_path).parent.mkdir(exist_ok=True, parents=True)
        self.file = open(file_path, "a", encoding="utf-8")
        self.stdout = sys.stdout

    def write(self, data: str) -> None:
        self.stdout.write(data)
        self.file.write(data)
        self.file.flush()

    def flush(self) -> None:
        self.stdout.flush()
        self.file.flush()

    def isatty(self) -> bool:
        return self.stdout.isatty()

    def __getattr__(self, attr: str) -> Any:
        return getattr(self.stdout, attr)

def session_cleanup_loop() -> None:
    while True:
        time.sleep(SESSION_CLEANUP_INTERVAL)
        _cleanup_expired_sessions()


def main() -> None:
    ensure_dirs()
    log_to_json("INFO", "Main", "服务已启动，正在初始化...")
    kill_existing_openvpn_processes()
    
    log_file = DATA_DIR / "vpngate.log"
    tee = Tee(str(log_file))
    sys.stdout = tee
    sys.stderr = tee

    write_json(
        STATE_FILE,
        {
            "api_url": API_URL,
            "target_valid_nodes": TARGET_VALID_NODES,
            "fetch_interval_seconds": FETCH_INTERVAL_SECONDS,
            "check_interval_seconds": CHECK_INTERVAL_SECONDS,
            "local_proxy": f"http://{'[' + LOCAL_PROXY_HOST + ']' if ':' in LOCAL_PROXY_HOST else LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}",
            "active_openvpn_node_id": "",
            "last_fetch_status": "starting",
            "last_check_message": "服务已启动，正在初始化网络并获取候选 VPN 节点...",
            "is_connecting": False,
            "active_node_latency": "正在准备",
            "blacklisted_nodes": 0,
        },
    )
    threading.Thread(target=proxy_server.start_proxy_server, args=(LOCAL_PROXY_HOST, LOCAL_PROXY_PORT), daemon=True).start()
    
    # Wait for the gateway to officially start
    print("[网关] 正在启动代理网关...", flush=True)
    gateway_ready = False
    is_ipv6 = ":" in LOCAL_PROXY_HOST
    af = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    for _ in range(30):
        s = None
        try:
            s = socket.socket(af, socket.SOCK_STREAM)
            s.settimeout(0.5)
            connect_host = LOCAL_PROXY_HOST
            if connect_host in ("::", "0.0.0.0", ""):
                connect_host = "::1" if is_ipv6 else "127.0.0.1"
            try:
                s.connect((connect_host, LOCAL_PROXY_PORT))
                gateway_ready = True
                break
            except Exception:
                if connect_host == "::1":
                    try:
                        s.close()
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.5)
                        s.connect(("127.0.0.1", LOCAL_PROXY_PORT))
                        gateway_ready = True
                        break
                    except Exception:
                        pass
                raise
        except Exception:
            time.sleep(0.5)
        finally:
            if s is not None:
                try:
                    s.close()
                except Exception:
                    pass
            
    if gateway_ready:
        print("[网关] 代理网关已成功启动监听，启动同步与检测脚本...", flush=True)
        log_to_json("INFO", "Main", "代理网关启动成功")
    else:
        print("[警告] 代理网关启动超时，继续执行脚本...", flush=True)
        log_to_json("WARNING", "Main", "代理网关启动超时")

    threading.Thread(target=collector_loop, daemon=True).start()
    log_to_json("INFO", "Main", "节点采集线程已启动")
    threading.Thread(target=background_proxy_checker, daemon=True).start()
    log_to_json("INFO", "Main", "代理检测线程已启动")
    threading.Thread(target=active_node_pinger, daemon=True).start()
    log_to_json("INFO", "Main", "节点ping检测线程已启动")
    threading.Thread(target=session_cleanup_loop, daemon=True).start()
    log_to_json("INFO", "Main", "会话清理线程已启动")
    
    ui_cfg = _cached_load_ui_config()
    ui_host = ui_cfg.get("host", UI_HOST)
    ui_port = bounded_int(ui_cfg.get("port"), UI_PORT, 1, 65535)
    
    print(f"UI: http://{ui_host}:{ui_port}/", flush=True)
    print(f"Proxy: http://{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}", flush=True)
    log_to_json("INFO", "Main", f"UI服务已启动: http://{ui_host}:{ui_port}/")
    DualStackHTTPServer((ui_host, ui_port), Handler).serve_forever()

if __name__ == "__main__":
    main()
