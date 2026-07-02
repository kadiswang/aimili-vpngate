#!/usr/bin/env python3
from __future__ import annotations
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
    MAX_CONFIG_TEXT_LENGTH, SESSION_TIMEOUT,
)
from core.state import (
    state_lock, active_sessions, ws_clients_lock, active_ws_clients,
    read_nodes, write_json, log_to_json, log_audit,
    _cached_load_ui_config, save_ui_config, _check_login_rate_limit,
    _record_login_attempt, _generate_csrf_token, _validate_csrf_token,
    _cleanup_expired_sessions, get_state, last_collector_heartbeat,
    last_checker_heartbeat, server_start_time, _audit_logs, _audit_log_lock,
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


class VPNRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def send_json(self, status: int, data: Any) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
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
        query = urllib.parse.parse_qs(parsed.query)

        ui_cfg = _cached_load_ui_config()
        secret_path = ui_cfg.get("secret_path", "")

        if not path.startswith(secret_path):
            self.send_html(get_login_page(ui_cfg, ""))
            return

        stripped_path = path[len(secret_path):].lstrip("/")

        if stripped_path == "":
            self.send_html(get_index_page())
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

        if stripped_path == "api/test-node":
            self.handle_api_test_node(query)
            return

        if stripped_path == "api/test-multiple":
            self.handle_api_test_multiple(query)
            return

        if stripped_path == "api/connect":
            self.handle_api_connect(query)
            return

        if stripped_path == "api/disconnect":
            self.handle_api_disconnect()
            return

        if stripped_path == "api/auto-switch":
            self.handle_api_auto_switch()
            return

        if stripped_path == "api/maintain":
            self.handle_api_maintain()
            return

        if stripped_path == "api/settings":
            self.handle_api_settings(query)
            return

        if stripped_path == "api/favorites":
            self.handle_api_favorites(query)
            return

        if stripped_path == "api/csrf-token":
            self.handle_api_csrf_token()
            return

        if stripped_path == "ws":
            self.handle_websocket()
            return

        static_path = Path(__file__).parent.parent / "templates" / stripped_path
        if static_path.exists():
            self.send_file(static_path)
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def do_POST(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.lstrip("/")

        ui_cfg = _cached_load_ui_config()
        secret_path = ui_cfg.get("secret_path", "")

        if not path.startswith(secret_path):
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Unauthorized"})
            return

        stripped_path = path[len(secret_path):].lstrip("/")

        if stripped_path == "api/settings":
            self.handle_api_settings_post()
            return

        if stripped_path == "api/favorites":
            self.handle_api_favorites_post()
            return

        if stripped_path == "api/login":
            self.handle_api_login()
            return

        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found"})

    def read_body(self) -> dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
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

        if not _check_login_rate_limit(self.client_address[0]):
            self.send_json(HTTPStatus.TOO_MANY_REQUESTS, {"error": "Too many login attempts"})
            return

        if username == ui_cfg.get("username") and password == ui_cfg.get("password"):
            session_id = os.urandom(32).hex()
            with state_lock:
                active_sessions[session_id] = time.time() + SESSION_TIMEOUT
            self.send_json(HTTPStatus.OK, {"session_id": session_id, "success": True})
            log_audit("login", "Web", f"Successful login from {self.client_address[0]}")
        else:
            _record_login_attempt(self.client_address[0])
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid credentials"})

    def handle_api_status(self) -> None:
        from vpn.openvpn import active_openvpn_running
        state = get_state()
        state["active_openvpn_running"] = active_openvpn_running()
        state["last_collector_heartbeat"] = last_collector_heartbeat
        state["last_checker_heartbeat"] = last_checker_heartbeat
        state["server_start_time"] = server_start_time
        state["uptime_seconds"] = int(time.time() - server_start_time)
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
        self.send_json(HTTPStatus.OK, {"nodes": export_nodes})

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

    def handle_api_test_node(self, query) -> None:
        node_id = query.get("node_id", [None])[0]
        if not node_id:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "node_id is required"})
            return
        from vpn.nodes import test_node_by_id
        try:
            result = test_node_by_id(node_id)
            log_audit("test_node", "Web", f"Test node: {node_id}")
            self.send_json(HTTPStatus.OK, result)
        except Exception as e:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})

    def handle_api_test_multiple(self, query) -> None:
        node_ids = query.get("node_ids", [])
        if not node_ids:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "node_ids is required"})
            return
        from vpn.nodes import test_multiple_nodes
        try:
            results = test_multiple_nodes(node_ids)
            log_audit("test_multiple", "Web", f"Test {len(node_ids)} nodes")
            self.send_json(HTTPStatus.OK, {"results": results})
        except Exception as e:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})

    def handle_api_connect(self, query) -> None:
        node_id = query.get("node_id", [None])[0]
        from vpn.nodes import connect_node
        try:
            result = connect_node(node_id)
            log_audit("connect", "Web", f"Connected to node: {node_id}")
            self.send_json(HTTPStatus.OK, result)
        except Exception as e:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})

    def handle_api_disconnect(self) -> None:
        from vpn.openvpn import stop_active_openvpn
        stop_active_openvpn()
        log_audit("disconnect", "Web", "Manual disconnect")
        self.send_json(HTTPStatus.OK, {"success": True})

    def handle_api_auto_switch(self) -> None:
        from vpn.nodes import auto_switch_node
        try:
            auto_switch_node()
            log_audit("auto_switch", "Web", "Auto switch triggered")
            self.send_json(HTTPStatus.OK, {"success": True})
        except Exception as e:
            self.send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(e)})

    def handle_api_maintain(self) -> None:
        from vpn.nodes import maintain_valid_nodes
        threading.Thread(target=maintain_valid_nodes, daemon=True).start()
        log_audit("maintain", "Web", "Manual maintenance triggered")
        self.send_json(HTTPStatus.OK, {"success": True, "message": "Maintenance started"})

    def handle_api_settings(self, query) -> None:
        ui_cfg = _cached_load_ui_config()
        result = {k: v for k, v in ui_cfg.items() if k != "password"}
        self.send_json(HTTPStatus.OK, result)

    def handle_api_settings_post(self) -> None:
        body = self.read_body()
        if not _validate_csrf_token(body.get("csrf_token")):
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid CSRF token"})
            return

        ui_cfg = _cached_load_ui_config()
        updates = ["port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "min_health_score", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback", "upstream_proxy"]
        for key in updates:
            if key in body:
                ui_cfg[key] = body[key]

        save_ui_config(ui_cfg)
        log_audit("settings_update", "Web", "Settings updated")
        self.send_json(HTTPStatus.OK, {"success": True})

    def handle_api_favorites(self, query) -> None:
        ui_cfg = _cached_load_ui_config()
        self.send_json(HTTPStatus.OK, {"favorite_node_ids": ui_cfg.get("favorite_node_ids", [])})

    def handle_api_favorites_post(self) -> None:
        body = self.read_body()
        if not _validate_csrf_token(body.get("csrf_token")):
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Invalid CSRF token"})
            return

        ui_cfg = _cached_load_ui_config()
        ui_cfg["favorite_node_ids"] = body.get("favorite_node_ids", [])
        save_ui_config(ui_cfg)
        log_audit("favorites_update", "Web", f"Favorites updated: {len(ui_cfg['favorite_node_ids'])} nodes")
        self.send_json(HTTPStatus.OK, {"success": True})

    def handle_api_csrf_token(self) -> None:
        token = _generate_csrf_token()
        self.send_json(HTTPStatus.OK, {"csrf_token": token})

    def handle_websocket(self) -> None:
        import hashlib
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            self.send_response(HTTPStatus.BAD_REQUEST)
            self.end_headers()
            return

        accept_key = hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest().hex()

        self.send_response(HTTPStatus.SWITCHING_PROTOCOLS)
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept_key)
        self.end_headers()

        client = self.connection
        with ws_clients_lock:
            active_ws_clients.append(client)

        from core.state import register_event_callback, broadcast_event

        def callback(event_type, data):
            try:
                payload = json.dumps({"type": event_type, "data": data}, ensure_ascii=False).encode("utf-8")
                length = len(payload)
                if length < 126:
                    frame = bytes([0x81, length]) + payload
                else:
                    frame = bytes([0x81, 0x7E]) + length.to_bytes(2, "big") + payload
                client.send(frame)
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
            with ws_clients_lock:
                active_ws_clients.remove(client)


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