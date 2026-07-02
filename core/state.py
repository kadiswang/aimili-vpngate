#!/usr/bin/env python3
from __future__ import annotations
import json
import subprocess
import threading
import time
import traceback
import uuid
import socket
import os
import sys
from pathlib import Path
from typing import Any

from .constants import (
    DATA_DIR, NODES_FILE, STATE_FILE, AUTH_FILE, CONFIG_DIR,
    OPENVPN_AUTH_USER, OPENVPN_AUTH_PASS,
    LOG_CLEANUP_INTERVAL, LOG_RETENTION_DAYS,
    CONFIG_CACHE_TTL, NODE_CACHE_TTL,
    LOCAL_PROXY_HOST, LOCAL_PROXY_PORT,
)

state_lock = threading.RLock()
config_lock = threading.RLock()
log_file_lock = threading.Lock()
maintenance_lock = threading.Lock()
ws_clients_lock = threading.Lock()

active_sessions: dict[str, float] = {}
active_ws_clients: list = []
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

_config_cache: dict[str, Any] | None = None
_config_cache_time = 0.0
_last_cleanup_time = 0.0

_login_attempts: dict[str, list[float]] = {}
_login_attempts_lock = threading.Lock()

_csrf_tokens: dict[str, tuple[float, str]] = {}
_csrf_lock = threading.Lock()

_audit_log_lock = threading.Lock()
_audit_logs: list[dict[str, Any]] = []
_MAX_AUDIT_LOGS = 1000

_event_stream_lock = threading.Lock()
_event_callbacks: list[callable] = []

_log_write_counter = 0
_LOG_CLEANUP_CHECK_EVERY = 100


def write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)
    if path == NODES_FILE:
        global _nodes_cache
        _nodes_cache = None


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def cleanup_old_logs(logs_dir: Path) -> None:
    global _last_cleanup_time
    now = time.time()
    if now - _last_cleanup_time < LOG_CLEANUP_INTERVAL:
        return
    _last_cleanup_time = now
    try:
        retention_sec = LOG_RETENTION_DAYS * 24 * 60 * 60
        for path in logs_dir.glob("*.json"):
            match = __import__("re").match(r"^(\d{4}-\d{2}-\d{2})\.json$", path.name)
            if match:
                date_str = match.group(1)
                try:
                    file_time = time.mktime(time.strptime(date_str, "%Y-%m-%d"))
                    today_str = time.strftime("%Y-%m-%d", time.localtime())
                    today_time = time.mktime(time.strptime(today_str, "%Y-%m-%d"))
                    if today_time - file_time >= retention_sec:
                        path.unlink()
                        print(f"[清理] 已删除{LOG_RETENTION_DAYS}天前的旧日志文件: {path.name}", flush=True)
                except Exception:
                    if now - path.stat().st_mtime > retention_sec:
                        path.unlink()
    except Exception as e:
        print(f"[清理错误] 清理旧日志失败: {e}", flush=True)
        print(traceback.format_exc(), flush=True)


def log_to_json(level: str, module: str, message: str) -> None:
    global _log_write_counter
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
        with log_file_lock:
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _log_write_counter += 1
        if _log_write_counter >= _LOG_CLEANUP_CHECK_EVERY:
            _log_write_counter = 0
            cleanup_old_logs(logs_dir)
    except Exception as e:
        print(f"[Log Error] Failed to write JSON log: {e}", flush=True)


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


def register_event_callback(cb: callable) -> None:
    with _event_stream_lock:
        _event_callbacks.append(cb)


def unregister_event_callback(cb: callable) -> None:
    with _event_stream_lock:
        try:
            _event_callbacks.remove(cb)
        except ValueError:
            pass


def broadcast_event(event_type: str, data: dict[str, Any] | None = None) -> None:
    with _event_stream_lock:
        for cb in _event_callbacks:
            try:
                cb(event_type, data)
            except Exception as e:
                print(f"[事件] 事件回调执行异常: {e}", flush=True)


def _cleanup_expired_sessions() -> None:
    now = time.time()
    expired = [t for t, exp in active_sessions.items() if exp <= now]
    for t in expired:
        active_sessions.pop(t, None)


def _get_or_cleanup_sessions() -> dict[str, float]:
    _cleanup_expired_sessions()
    return active_sessions


def read_nodes() -> list[dict[str, Any]]:
    global _nodes_cache, _nodes_cache_time
    now = time.time()
    with state_lock:
        if _nodes_cache is not None and now - _nodes_cache_time < NODE_CACHE_TTL:
            return _nodes_cache
        raw = read_json(NODES_FILE, [])
        if not isinstance(raw, list):
            _nodes_cache = []
            return []
        _nodes_cache = [item for item in raw if isinstance(item, dict)]
        _nodes_cache_time = now
        return _nodes_cache


def cached_nodes() -> list[dict[str, Any]]:
    return read_nodes()


def set_state(**updates: Any) -> None:
    state = get_state()
    state.update(updates)
    write_json(STATE_FILE, state)


def get_state() -> dict[str, Any]:
    global active_openvpn_node_id, is_connecting
    state = read_json(STATE_FILE, {})
    state.pop("password", None)
    state["active_openvpn_node_id"] = active_openvpn_node_id
    state["is_connecting"] = is_connecting
    return state


def ensure_dirs() -> None:
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text(f"{OPENVPN_AUTH_USER}\n{OPENVPN_AUTH_PASS}\n", encoding="utf-8")
        try:
            AUTH_FILE.chmod(0o600)
        except OSError:
            pass


def _check_login_rate_limit(ip: str) -> bool:
    from .constants import LOGIN_RATE_LIMIT_WINDOW, LOGIN_RATE_LIMIT_MAX_ATTEMPTS
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
    from .constants import CSRF_TOKEN_EXPIRY
    token = uuid.uuid4().hex + uuid.uuid4().hex
    with _csrf_lock:
        _csrf_tokens[token] = (time.time() + CSRF_TOKEN_EXPIRY, token)
    return token


def _validate_csrf_token(token: str | None) -> bool:
    from .constants import CSRF_TOKEN_EXPIRY
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


def _parse_session_cookie(cookie_header: str | None) -> str:
    """从 Cookie 头解析 session_id。"""
    if not cookie_header:
        return ""
    for part in cookie_header.split(";"):
        part = part.strip()
        if part.startswith("session_id="):
            return part[len("session_id="):]
    return ""


def get_session_id_from_headers(headers) -> str:
    """从请求头获取 session_id（优先 Cookie，其次 X-Session-Token）。"""
    token = _parse_session_cookie(headers.get("Cookie"))
    if token:
        return token
    return headers.get("X-Session-Token", "") or ""


def check_request_session(headers) -> bool:
    """校验请求是否携带有效且未过期的 session。"""
    from .constants import SESSION_TIMEOUT
    sid = get_session_id_from_headers(headers)
    if not sid:
        return False
    with state_lock:
        _cleanup_expired_sessions()
        exp = active_sessions.get(sid)
        if exp is None:
            return False
        if exp <= time.time():
            active_sessions.pop(sid, None)
            return False
        # sliding renewal: 续期以保持活跃用户不掉线
        active_sessions[sid] = time.time() + SESSION_TIMEOUT
        return True


def delete_session(headers) -> bool:
    """注销当前请求对应的 session。"""
    sid = get_session_id_from_headers(headers)
    if not sid:
        return False
    with state_lock:
        return active_sessions.pop(sid, None) is not None


def _check_and_record_login_attempt(ip: str) -> bool:
    """原子化登录限流：检查通过即预占一个槽位，避免并发下突破阈值。"""
    from .constants import LOGIN_RATE_LIMIT_WINDOW, LOGIN_RATE_LIMIT_MAX_ATTEMPTS
    now = time.time()
    with _login_attempts_lock:
        timestamps = [t for t in _login_attempts.get(ip, []) if now - t < LOGIN_RATE_LIMIT_WINDOW]
        if len(timestamps) >= LOGIN_RATE_LIMIT_MAX_ATTEMPTS:
            _login_attempts[ip] = timestamps
            return False
        timestamps.append(now)
        _login_attempts[ip] = timestamps
        return True


def clear_login_attempts(ip: str) -> None:
    """登录成功后清除该 IP 的失败/尝试记录。"""
    with _login_attempts_lock:
        _login_attempts.pop(ip, None)


def _cached_load_ui_config() -> dict[str, Any]:
    global _config_cache, _config_cache_time
    now = time.time()
    if _config_cache is not None and now - _config_cache_time < CONFIG_CACHE_TTL:
        return _config_cache
    from .config import load_ui_config
    result = load_ui_config()
    with config_lock:
        _config_cache = result
        _config_cache_time = now
    return result


def save_ui_config(config: dict[str, Any]) -> None:
    global _config_cache, _config_cache_time
    auth_file = DATA_DIR / "ui_auth.json"
    DATA_DIR.mkdir(exist_ok=True, parents=True)
    write_json(auth_file, config)
    with config_lock:
        _config_cache = dict(config)
        _config_cache_time = time.time()


def stop_process(process: subprocess.Popen[str] | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()


def clear_active_connection_state(message: str) -> None:
    global active_openvpn_process, active_openvpn_node_id
    stop_process(active_openvpn_process)
    active_openvpn_process = None
    active_openvpn_node_id = ""
    with state_lock:
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


def graceful_shutdown() -> None:
    """清理所有活动连接、关闭 OpenVPN 进程、清理策略路由，安全退出。"""
    global active_openvpn_process, active_openvpn_node_id, is_connecting
    print("[Shutdown] 正在执行优雅关闭...", flush=True)
    try:
        is_connecting = False
        if active_openvpn_process is not None:
            stop_process(active_openvpn_process)
            active_openvpn_process = None
        active_openvpn_node_id = ""
        try:
            from vpn.routing import cleanup_policy_routing
            cleanup_policy_routing()
        except Exception as e:
            print(f"[Shutdown] 清理策略路由失败: {e}", flush=True)
        try:
            from vpn.openvpn import kill_existing_openvpn_processes
            kill_existing_openvpn_processes()
        except Exception as e:
            print(f"[Shutdown] 清理残留 OpenVPN 进程失败: {e}", flush=True)
        set_state(
            active_openvpn_node_id="",
            is_connecting=False,
            active_node_latency="无活动连接",
            last_check_message="服务已关闭",
        )
        log_to_json("INFO", "Main", "服务已优雅关闭")
    except Exception as e:
        print(f"[Shutdown] 优雅关闭时发生异常: {e}", flush=True)
        print(traceback.format_exc(), flush=True)


def check_proxy_health() -> dict[str, Any]:
    import vpn_utils
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

    tun_path = Path("/sys/class/net/tun0")
    if sys.platform.startswith("linux") and not tun_path.exists():
        return {
            "ok": False,
            "error": "[错误代码 3004] [ERR_ROUTE_DEV_NOT_FOUND] VPN 虚拟网卡 (tun0) 未启用，请确保当前已成功连接 VPN 节点"
        }

    def _curl_check_ip(url: str) -> dict[str, Any] | None:
        import proxy_server
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