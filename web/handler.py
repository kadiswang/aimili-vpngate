#!/usr/bin/env python3
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import socket
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from core.constants import (
    DATA_DIR, UI_HOST, UI_PORT, NODE_EXPORT_FIELDS, LOG_TAIL_LINES,
    MAX_CONFIG_TEXT_LENGTH, SESSION_TIMEOUT, LOCAL_PROXY_HOST, LOCAL_PROXY_PORT,
)
import core.state
from core.state import (
    state_lock, active_sessions, ws_clients_lock, active_ws_clients,
    read_nodes, write_json, log_audit,
    _cached_load_ui_config, save_ui_config,
    _generate_csrf_token, _validate_csrf_token,
    get_state, _audit_logs, _audit_log_lock,
    check_request_session, delete_session, get_session_id_from_headers,
    _check_and_record_login_attempt, clear_login_attempts,
)

import urllib.parse


_orig_getaddrinfo = socket.getaddrinfo


def _ipv4_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    if family == 0:
        if isinstance(host, str) and ":" in host:
            return _orig_getaddrinfo(host, port, socket.AF_INET6, type, proto, flags)
        try:
            results = _orig_getaddrinfo(host, port, socket.AF_INET, type, proto, flags)
            if results:
                return results
        except socket.gaierror:
            pass
        return _orig_getaddrinfo(host, port, 0, type, proto, flags)
    return _orig_getaddrinfo(host, port, family, type, proto, flags)


# 优先 IPv4 解析，保证 VPN 节点探测在双栈环境下行为可预期
socket.getaddrinfo = _ipv4_getaddrinfo


_TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
_MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024  # 1 MB 上限，防止 OOM DoS


def _path_matches_secret(path: str, secret_path: str) -> bool:
    """secret_path 必须非空且作为完整 URL 段匹配（前缀 + '/' 或完全相等）。"""
    if not secret_path:
        return False
    return path == secret_path or path.startswith(secret_path + "/")


def _is_safe_static_path(stripped_path: str) -> bool:
    """防止路径穿越：仅允许不含 .. 的纯文件名，且解析后仍在 templates 目录内。"""
    if not stripped_path or ".." in stripped_path.split("/"):
        return False
    candidate = (_TEMPLATES_DIR / stripped_path).resolve()
    try:
        candidate.relative_to(_TEMPLATES_DIR)
    except ValueError:
        return False
    return candidate.is_file()


class DualStackHTTPServer(ThreadingHTTPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        host, port = server_address
        if host == "":
            host = "::"
        if ":" in host:
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET

        try:
            super().__init__((host, port), RequestHandlerClass, bind_and_activate)
        except OSError as e:
            if self.address_family == socket.AF_INET6:
                fallback_host = "0.0.0.0" if host == "::" else "127.0.0.1"
                print(f"[警告] 绑定 Web 管理后台 IPv6 {host}:{port} 失败 ({e})，正在尝试回退至 IPv4 {fallback_host} ...", flush=True)
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
            except OSError as e:
                print(f"[警告] 设置 IPV6_V6ONLY=0 失败，IPv4 客户端可能无法通过 IPv6 socket 访问: {e}", flush=True)
        super().server_bind()


class VPNRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, status: int, data: Any, extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(json.dumps(data, ensure_ascii=False).encode("utf-8"))

    def send_html(self, content: str) -> None:
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(content.encode("utf-8"))

    def send_file(self, path: Path) -> None:
        if not path.exists():
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "File not found"})
            return
        self.send_response(HTTPStatus.OK)
        ext = path.suffix.lower()
        if ext == ".css":
            self.send_header("Content-Type", "text/css; charset=utf-8")
        elif ext == ".js":
            self.send_header("Content-Type", "application/javascript; charset=utf-8")
        elif ext == ".png":
            self.send_header("Content-Type", "image/png")
        elif ext == ".svg":
            self.send_header("Content-Type", "image/svg+xml")
        else:
            self.send_header("Content-Type", "application/octet-stream")
        self.end_headers()
        self.wfile.write(path.read_bytes())

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.lstrip("/")

        ui_cfg = _cached_load_ui_config()
        secret_path = ui_cfg.get("secret_path", "")

        # secret_path 必须非空且作为完整 URL 段匹配，否则一律返回登录页
        if not _path_matches_secret(path, secret_path):
            self.send_html(get_login_page(ui_cfg, ""))
            return

        stripped_path = path[len(secret_path):].lstrip("/")

        # 首页 HTML 与公开静态资源放行（CSS/JS 等），由前端处理登录态
        if stripped_path == "":
            self.send_html(get_index_page())
            return

        # 公开端点：登录前可访问
        if stripped_path == "api/csrf_token":
            self.handle_api_csrf_token()
            return

        # 其余 API 端点需要 session 鉴权
        if stripped_path.startswith("api/"):
            if not check_request_session(self.headers):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "未登录或会话已过期", "need_login": True})
                return

            if stripped_path == "api/status":
                self.handle_api_status()
                return
            if stripped_path == "api/nodes":
                self.handle_api_nodes()
                return
            if stripped_path.startswith("api/node/"):
                node_id = stripped_path[9:]
                self.handle_api_node(node_id)
                return
            if stripped_path == "api/logs":
                self.handle_api_logs()
                return
            if stripped_path == "api/audit":
                self.handle_api_audit()
                return
            if stripped_path == "api/gateway_status":
                self.handle_api_gateway_status()
                return
            if stripped_path == "api/settings":
                self.handle_api_settings_get()
                return
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})
            return

        # WebSocket 升级（带 session 校验）
        if stripped_path == "ws":
            if not check_request_session(self.headers):
                self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "未登录"})
                return
            self.handle_websocket()
            return

        # 静态资源（防路径穿越）
        if _is_safe_static_path(stripped_path):
            self.send_file(_TEMPLATES_DIR / stripped_path)
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.lstrip("/")

        ui_cfg = _cached_load_ui_config()
        secret_path = ui_cfg.get("secret_path", "")

        # 根路径 api/login 放行：登录页在 / 下，无需知道 secret_path 即可提交
        if path == "api/login":
            self.handle_api_login()
            return

        if not _path_matches_secret(path, secret_path):
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
            return

        stripped_path = path[len(secret_path):].lstrip("/")

        # 登录端点豁免 session/CSRF
        if stripped_path == "api/login":
            self.handle_api_login()
            return

        # 其余 POST 端点：必须同时满足 session 鉴权 + CSRF 校验
        if not check_request_session(self.headers):
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "未登录或会话已过期", "need_login": True})
            return
        if not _validate_csrf_token(self.headers.get("X-CSRF-Token")):
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "CSRF 校验失败，请刷新页面后重试"})
            return

        if stripped_path == "api/logout":
            self.handle_api_logout()
            return
        if stripped_path == "api/test_node":
            self.handle_api_test_node()
            return
        if stripped_path == "api/test_nodes":
            self.handle_api_test_nodes()
            return
        if stripped_path == "api/toggle_favorite":
            self.handle_api_toggle_favorite()
            return
        if stripped_path == "api/connect":
            self.handle_api_connect()
            return
        if stripped_path == "api/disconnect":
            self.handle_api_disconnect()
            return
        if stripped_path == "api/test_proxy":
            self.handle_api_test_proxy()
            return
        if stripped_path == "api/refresh_nodes":
            self.handle_api_refresh_nodes()
            return
        if stripped_path == "api/update_routing":
            self.handle_api_update_routing()
            return
        if stripped_path == "api/update_credentials":
            self.handle_api_update_credentials()
            return
        if stripped_path == "api/update_settings":
            self.handle_api_update_settings()
            return
        if stripped_path == "api/auto_switch":
            self.handle_api_auto_switch()
            return
        if stripped_path == "api/maintain":
            self.handle_api_maintain()
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def read_body(self) -> dict[str, Any]:
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except (TypeError, ValueError):
            return {}
        if content_length <= 0:
            return {}
        if content_length > _MAX_REQUEST_BODY_BYTES:
            return {}
        try:
            body = self.rfile.read(content_length).decode("utf-8")
            return json.loads(body)
        except Exception:
            return {}

    def handle_api_login(self) -> None:
        body = self.read_body()
        username = body.get("username", "")
        password = body.get("password", "")
        ui_cfg = _cached_load_ui_config()
        client_ip = self.client_address[0] if self.client_address else "unknown"

        # 原子化登录限流（检查通过即预占槽位，防并发突破阈值）
        if not _check_and_record_login_attempt(client_ip):
            self.send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "登录尝试过于频繁，请稍后再试"})
            return

        expected_user = ui_cfg.get("username", "")
        expected_pwd = ui_cfg.get("password", "")
        secret_path = ui_cfg.get("secret_path", "")
        # 常量时间比较，防时序侧信道
        user_ok = isinstance(username, str) and hmac.compare_digest(username, expected_user)
        pwd_ok = isinstance(password, str) and hmac.compare_digest(password, expected_pwd)
        if user_ok and pwd_ok:
            clear_login_attempts(client_ip)
            session_id = os.urandom(32).hex()
            with state_lock:
                active_sessions[session_id] = time.time() + SESSION_TIMEOUT
                core.state._cleanup_expired_sessions()
            cookie = (
                f"session_id={session_id}; HttpOnly; SameSite=Strict; "
                f"Max-Age={SESSION_TIMEOUT}; Path=/"
            )
            log_audit("login", "Web", f"Successful login from {client_ip}")
            self.send_json(
                HTTPStatus.OK,
                {"ok": True, "session_id": session_id, "secret_path": secret_path},
                extra_headers={"Set-Cookie": cookie},
            )
        else:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "账号或密码不正确"})

    def handle_api_status(self) -> None:
        from vpn.openvpn import active_openvpn_running
        state = get_state()
        state["active_openvpn_running"] = active_openvpn_running()
        state["last_collector_heartbeat"] = core.state.last_collector_heartbeat
        state["last_checker_heartbeat"] = core.state.last_checker_heartbeat
        state["server_start_time"] = core.state.server_start_time
        state["uptime_seconds"] = int(time.time() - core.state.server_start_time)
        self.send_json(HTTPStatus.OK, state)

    def handle_api_nodes(self) -> None:
        nodes = read_nodes()
        export_nodes = []
        for node in nodes:
            export_node = {}
            for field in NODE_EXPORT_FIELDS:
                export_node[field] = node.get(field, "")
            if "config_text" in node and len(node["config_text"]) > MAX_CONFIG_TEXT_LENGTH:
                export_node["config_text"] = node["config_text"][:MAX_CONFIG_TEXT_LENGTH] + "\n... (truncated)"
            else:
                export_node["config_text"] = node.get("config_text", "")
            export_nodes.append(export_node)
        state = get_state()
        self.send_json(HTTPStatus.OK, {"nodes": export_nodes, "state": state})

    def handle_api_node(self, node_id: str) -> None:
        nodes = read_nodes()
        node = next((n for n in nodes if n.get("id") == node_id), None)
        if not node:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Node not found"})
            return
        result = {k: v for k, v in node.items() if k != "config_text"}
        if node.get("config_text"):
            if len(node["config_text"]) > MAX_CONFIG_TEXT_LENGTH:
                result["config_text"] = node["config_text"][:MAX_CONFIG_TEXT_LENGTH] + "\n... (truncated)"
            else:
                result["config_text"] = node["config_text"]
        self.send_json(HTTPStatus.OK, result)

    def handle_api_logs(self) -> None:
        logs_dir = DATA_DIR / "logs"
        if not logs_dir.exists():
            self.send_json(HTTPStatus.OK, {"logs": []})
            return
        log_lines = []
        for log_file in sorted(logs_dir.glob("*.json"), reverse=True):
            try:
                with open(log_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()[-LOG_TAIL_LINES:]
                    for line in lines:
                        try:
                            entry = json.loads(line)
                            log_lines.append(entry)
                        except json.JSONDecodeError:
                            pass
            except Exception:
                pass
            if len(log_lines) >= LOG_TAIL_LINES:
                break
        log_lines = log_lines[-LOG_TAIL_LINES:]
        self.send_json(HTTPStatus.OK, {"logs": log_lines})

    def handle_api_audit(self) -> None:
        with _audit_log_lock:
            logs = list(_audit_logs)
        self.send_json(HTTPStatus.OK, {"logs": logs})

    def handle_api_test_node(self) -> None:
        body = self.read_body()
        node_id = body.get("id", "")
        if not node_id:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "id is required"})
            return
        from vpn.nodes import test_node_by_id
        try:
            result = test_node_by_id(str(node_id))
            log_audit("test_node", "Web", f"Test node: {node_id}")
            if isinstance(result, dict) and result.get("ok"):
                self.send_json(HTTPStatus.OK, result)
            else:
                self.send_json(HTTPStatus.OK, {"ok": False, "error": result.get("error", "测试失败") if isinstance(result, dict) else str(result)})
        except Exception as e:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})

    def handle_api_test_nodes(self) -> None:
        body = self.read_body()
        node_ids = body.get("ids", [])
        if not node_ids:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "ids is required"})
            return
        from vpn.nodes import test_multiple_nodes
        try:
            threading.Thread(target=test_multiple_nodes, args=(node_ids,), daemon=True).start()
            log_audit("test_nodes", "Web", f"Test {len(node_ids)} nodes")
            self.send_json(HTTPStatus.OK, {"ok": True})
        except Exception as e:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})

    def handle_api_toggle_favorite(self) -> None:
        body = self.read_body()
        node_id = str(body.get("id", ""))
        if not node_id:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "id is required"})
            return
        ui_cfg = _cached_load_ui_config()
        fav_ids = list(ui_cfg.get("favorite_node_ids", []))
        if node_id in fav_ids:
            fav_ids.remove(node_id)
        else:
            fav_ids.append(node_id)
        ui_cfg["favorite_node_ids"] = fav_ids
        save_ui_config(ui_cfg)
        log_audit("toggle_favorite", "Web", f"Toggle favorite: {node_id}")
        self.send_json(HTTPStatus.OK, {"ok": True, "favorite_node_ids": fav_ids})

    def handle_api_connect(self) -> None:
        body = self.read_body()
        node_id = str(body.get("id", ""))
        from vpn.nodes import connect_node
        try:
            connect_node(node_id)
            log_audit("connect", "Web", f"Connected to node: {node_id}")
            self.send_json(HTTPStatus.OK, {"ok": True})
        except Exception as e:
            self.send_json(HTTPStatus.OK, {"ok": False, "error": str(e)})

    def handle_api_disconnect(self) -> None:
        from vpn.openvpn import stop_active_openvpn
        stop_active_openvpn()
        log_audit("disconnect", "Web", "Manual disconnect")
        self.send_json(HTTPStatus.OK, {"ok": True})

    def handle_api_test_proxy(self) -> None:
        from core.state import check_proxy_health
        try:
            result = check_proxy_health()
            if result.get("ok"):
                self.send_json(HTTPStatus.OK, {"ok": True, "ip": result.get("ip", "-"), "latency_ms": result.get("latency_ms", 0)})
            else:
                self.send_json(HTTPStatus.OK, {"ok": False, "error": result.get("error", "代理不可用")})
        except Exception as e:
            self.send_json(HTTPStatus.OK, {"ok": False, "error": str(e)})

    def handle_api_refresh_nodes(self) -> None:
        from vpn.nodes import maintain_valid_nodes
        threading.Thread(target=maintain_valid_nodes, kwargs={"force": True}, daemon=True).start()
        log_audit("refresh_nodes", "Web", "Manual refresh triggered")
        self.send_json(HTTPStatus.OK, {"ok": True})

    def handle_api_update_routing(self) -> None:
        body = self.read_body()
        ui_cfg = _cached_load_ui_config()
        for key in ("routing_mode", "force_country", "routing_ip_type", "fav_fail_fallback"):
            if key in body:
                ui_cfg[key] = body[key]
        save_ui_config(ui_cfg)
        log_audit("update_routing", "Web", "Routing updated")
        self.send_json(HTTPStatus.OK, {"ok": True})

    def handle_api_update_credentials(self) -> None:
        from core.constants import UI_PORT as _DEFAULT_UI_PORT
        body = self.read_body()
        ui_cfg = _cached_load_ui_config()
        restart_needed = False
        old_port = ui_cfg.get("port", _DEFAULT_UI_PORT)
        old_suffix = ui_cfg.get("secret_path", "")
        # 类型校验：避免任意垃圾值写入配置
        if "username" in body and isinstance(body["username"], str) and body["username"]:
            ui_cfg["username"] = body["username"][:64]
        if "password" in body and isinstance(body["password"], str) and body["password"]:
            ui_cfg["password"] = body["password"][:128]
        if "port" in body:
            try:
                new_port = int(body["port"])
                if 1 <= new_port <= 65535 and new_port != ui_cfg.get("proxy_port"):
                    ui_cfg["port"] = new_port
            except (TypeError, ValueError):
                pass
        if "secret_path" in body and isinstance(body["secret_path"], str) and body["secret_path"]:
            # secret_path 仅允许字母数字，避免注入或路径穿越
            import re
            if re.fullmatch(r"[A-Za-z0-9_-]{4,64}", body["secret_path"]):
                ui_cfg["secret_path"] = body["secret_path"]
        if ui_cfg.get("port", old_port) != old_port or ui_cfg.get("secret_path", old_suffix) != old_suffix:
            restart_needed = True
        save_ui_config(ui_cfg)
        log_audit("update_credentials", "Web", "Credentials updated")
        self.send_json(HTTPStatus.OK, {"ok": True, "restart_needed": restart_needed})

    def handle_api_update_settings(self) -> None:
        from core.constants import LOCAL_PROXY_PORT as _DEFAULT_PROXY_PORT
        body = self.read_body()
        ui_cfg = _cached_load_ui_config()
        old_proxy_port = ui_cfg.get("proxy_port", _DEFAULT_PROXY_PORT)
        restart_needed = False
        if "proxy_port" in body:
            try:
                new_proxy_port = int(body["proxy_port"])
                if 1024 <= new_proxy_port <= 65535 and new_proxy_port != ui_cfg.get("port"):
                    ui_cfg["proxy_port"] = new_proxy_port
            except (TypeError, ValueError):
                pass
        if "routing_mode" in body and body["routing_mode"] in ("auto", "off", "force_country"):
            ui_cfg["routing_mode"] = body["routing_mode"]
        if "force_country" in body and isinstance(body["force_country"], str):
            ui_cfg["force_country"] = body["force_country"][:64]
        if "routing_ip_type" in body and body["routing_ip_type"] in ("all", "ipv4", "ipv6"):
            ui_cfg["routing_ip_type"] = body["routing_ip_type"]
        if "min_health_score" in body:
            try:
                ui_cfg["min_health_score"] = max(0, min(100, int(body["min_health_score"])))
            except (TypeError, ValueError):
                pass
        if "upstream_proxy" in body and isinstance(body["upstream_proxy"], dict):
            ui_cfg["upstream_proxy"] = body["upstream_proxy"]
        if ui_cfg.get("proxy_port", old_proxy_port) != old_proxy_port:
            restart_needed = True
        save_ui_config(ui_cfg)
        log_audit("update_settings", "Web", "Settings updated")
        self.send_json(HTTPStatus.OK, {"ok": True, "restart_needed": restart_needed})

    def handle_api_logout(self) -> None:
        deleted = delete_session(self.headers)
        log_audit("logout", "Web", f"User logged out (session_removed={deleted})")
        # 清除客户端 cookie
        self.send_json(
            HTTPStatus.OK,
            {"ok": True},
            extra_headers={"Set-Cookie": "session_id=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/"},
        )

    def handle_api_auto_switch(self) -> None:
        from vpn.nodes import auto_switch_node
        try:
            auto_switch_node()
            log_audit("auto_switch", "Web", "Auto switch triggered")
            self.send_json(HTTPStatus.OK, {"ok": True})
        except Exception as e:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})

    def handle_api_maintain(self) -> None:
        from vpn.nodes import maintain_valid_nodes
        threading.Thread(target=maintain_valid_nodes, daemon=True).start()
        log_audit("maintain", "Web", "Manual maintenance triggered")
        self.send_json(HTTPStatus.OK, {"ok": True, "message": "Maintenance started"})

    def handle_api_settings_get(self) -> None:
        ui_cfg = _cached_load_ui_config()
        # 仅返回前端需要的非敏感字段，secret_path/username 等敏感信息不外泄
        safe_fields = (
            "host", "port", "proxy_port", "routing_mode", "force_country",
            "routing_ip_type", "min_health_score", "connection_enabled",
            "fixed_node_id", "favorite_node_ids", "fav_fail_fallback",
            "upstream_proxy",
        )
        result = {k: v for k, v in ui_cfg.items() if k in safe_fields}
        self.send_json(HTTPStatus.OK, result)

    def _check_proxy_port_listening(self) -> bool:
        """检测代理端口是否在监听，对 ::/0.0.0.0 做归一化。"""
        import socket as _sock
        host = LOCAL_PROXY_HOST
        if host in ("::", "0.0.0.0", ""):
            # 先试 IPv6 本地，失败再试 IPv4 本地
            for h, af in (("[::1]", _sock.AF_INET6), ("127.0.0.1", _sock.AF_INET), ("0.0.0.0", _sock.AF_INET)):
                try:
                    s = _sock.socket(af, _sock.SOCK_STREAM)
                    s.settimeout(1)
                    s.connect((h, LOCAL_PROXY_PORT))
                    s.close()
                    return True
                except Exception:
                    continue
            return False
        try:
            af = _sock.AF_INET6 if ":" in host else _sock.AF_INET
            s = _sock.socket(af, _sock.SOCK_STREAM)
            s.settimeout(1)
            s.connect((host, LOCAL_PROXY_PORT))
            s.close()
            return True
        except Exception:
            return False

    def handle_api_gateway_status(self) -> None:
        from vpn.openvpn import active_openvpn_running
        services = []
        # Web 后端：进程在跑即说明本请求已到达，恒为 running
        services.append({"name": "Web 管理后台", "status": "running", "details": f"PID {os.getpid()}"})
        # OpenVPN
        ovpn_running = active_openvpn_running()
        services.append({"name": "OpenVPN 连接核心", "status": "running" if ovpn_running else "stopped", "details": "-"})
        # Proxy server（host 归一化，避免 connect(("::", port)) 误报）
        proxy_ok = self._check_proxy_port_listening()
        services.append({"name": "代理网关", "status": "running" if proxy_ok else "stopped", "details": f"{LOCAL_PROXY_HOST}:{LOCAL_PROXY_PORT}"})
        self.send_json(HTTPStatus.OK, {"ok": True, "services": services})

    def handle_api_csrf_token(self) -> None:
        token = _generate_csrf_token()
        self.send_json(HTTPStatus.OK, {"csrf_token": token})

    def handle_websocket(self) -> None:
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            return

        # RFC 6455: Sec-WebSocket-Accept = base64(sha1(key + GUID))
        accept_key = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()

        self.send_response(HTTPStatus.SWITCHING_PROTOCOLS)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_key)
        self.end_headers()

        client = self.connection
        client_lock = threading.Lock()
        with ws_clients_lock:
            active_ws_clients.append(client)

        from core.state import register_event_callback, unregister_event_callback

        def callback(event_type, data):
            try:
                payload = json.dumps({"type": event_type, "data": data}, ensure_ascii=False).encode("utf-8")
                length = len(payload)
                if length < 126:
                    header = bytes([0x81, length])
                elif length < 65536:
                    header = bytes([0x81, 0x7E]) + length.to_bytes(2, "big")
                else:
                    header = bytes([0x81, 0x7F]) + length.to_bytes(8, "big")
                with client_lock:
                    client.send(header + payload)
            except Exception:
                pass

        register_event_callback(callback)

        try:
            while True:
                try:
                    data = client.recv(1024)
                    if not data:
                        break
                except Exception:
                    break
        finally:
            unregister_event_callback(callback)
            with ws_clients_lock:
                try:
                    active_ws_clients.remove(client)
                except ValueError:
                    pass


def get_login_page(ui_cfg, error_message):
    templates_dir = Path(__file__).parent.parent / "templates"
    login_html = templates_dir / "login.html"
    if login_html.exists():
        return login_html.read_text(encoding="utf-8")
    return f"""
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>Login</title>
</head>
<body>
<h1>Login</h1>
{error_message}
<form method="post" action="/{ui_cfg.get('secret_path', '')}/api/login">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit">Login</button>
</form>
</body>
</html>
"""


def get_index_page():
    templates_dir = Path(__file__).parent.parent / "templates"
    index_html = templates_dir / "index.html"
    if index_html.exists():
        return index_html.read_text(encoding="utf-8")
    return "<html><body><h1>AimiliVPN</h1></body></html>"


def start_web_server(host: str = UI_HOST, port: int = UI_PORT) -> None:
    server = DualStackHTTPServer((host, port), VPNRequestHandler)
    display_host = f"[{host}]" if ":" in host else host
    print(f"[Web] 启动 Web 管理后台: http://{display_host}:{port}", flush=True)
    server.serve_forever()