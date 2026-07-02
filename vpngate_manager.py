#!/usr/bin/env python3
from __future__ import annotations
import signal
import threading
import time
import os

from core.constants import UI_HOST, UI_PORT, FETCH_INTERVAL_SECONDS, CHECK_INTERVAL_SECONDS
from core.state import log_to_json, graceful_shutdown, ensure_dirs, last_collector_heartbeat, last_checker_heartbeat
import core.state
from core.config import init_config
from vpn.nodes import maintain_valid_nodes, auto_switch_node
from vpn.openvpn import kill_existing_openvpn_processes
from web.handler import DualStackHTTPServer, VPNRequestHandler


def main() -> None:
    ensure_dirs()
    log_to_json("INFO", "Main", "服务已启动，正在初始化...")
    kill_existing_openvpn_processes()
    config = init_config()
    ui_host = config.get("host", UI_HOST)
    ui_port = config.get("port", UI_PORT)

    def sigterm_handler(signum, frame):
        log_to_json("INFO", "Main", "接收到终止信号，正在优雅关闭...")
        graceful_shutdown()
        os._exit(0)

    signal.signal(signal.SIGTERM, sigterm_handler)
    signal.signal(signal.SIGINT, sigterm_handler)

    def run_maintain_loop():
        while True:
            try:
                maintain_valid_nodes()
            except Exception as e:
                log_to_json("ERROR", "Maintain", f"节点维护循环异常: {e}")
            core.state.last_collector_heartbeat = time.time()
            time.sleep(FETCH_INTERVAL_SECONDS)

    def run_check_loop():
        while True:
            try:
                auto_switch_node()
            except Exception as e:
                log_to_json("ERROR", "Checker", f"连接检查循环异常: {e}")
            core.state.last_checker_heartbeat = time.time()
            time.sleep(CHECK_INTERVAL_SECONDS)

    threading.Thread(target=run_maintain_loop, daemon=True).start()
    threading.Thread(target=run_check_loop, daemon=True).start()

    server = DualStackHTTPServer((ui_host, ui_port), VPNRequestHandler)
    display_host = f"[{ui_host}]" if ":" in ui_host else ui_host
    print(f"[Web] Web 管理后台已启动: http://{display_host}:{ui_port}", flush=True)
    log_to_json("INFO", "Main", f"Web 管理后台已启动，监听 {ui_host}:{ui_port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        graceful_shutdown()
        server.server_close()


if __name__ == "__main__":
    main()