#!/usr/bin/env python3
from __future__ import annotations
import os
import sys
from pathlib import Path

ROOT_DIR = Path(sys.executable).resolve().parent if globals().get("__compiled__") else Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
NODES_FILE = DATA_DIR / "nodes.json"
STATE_FILE = DATA_DIR / "state.json"
AUTH_FILE = DATA_DIR / "vpngate_auth.txt"
UPSTREAM_PROXY_AUTH_FILE = DATA_DIR / "upstream_proxy_auth.txt"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"

API_URL = "https://www.vpngate.net/api/iphone/"

OPENVPN_CMD = os.environ.get("OPENVPN_CMD", "openvpn")
OPENVPN_AUTH_USER = os.environ.get("OPENVPN_AUTH_USER", "vpn")
OPENVPN_AUTH_PASS = os.environ.get("OPENVPN_AUTH_PASS", "vpn")
LOCAL_PROXY_HOST = os.environ.get("LOCAL_PROXY_HOST", "127.0.0.1")
UI_HOST = os.environ.get("UI_HOST", "::")


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


FETCH_INTERVAL_SECONDS = env_int("FETCH_INTERVAL_SECONDS", 1260, 1)
CHECK_INTERVAL_SECONDS = env_int("CHECK_INTERVAL_SECONDS", 1260, 1)
TARGET_VALID_NODES = env_int("TARGET_VALID_NODES", 3, 1)
MAX_SCAN_ROWS = env_int("MAX_SCAN_ROWS", 300, 1)
OPENVPN_TEST_TIMEOUT_SECONDS = env_int("OPENVPN_TEST_TIMEOUT_SECONDS", 35, 1)
MANUAL_TEST_NODE_LIMIT = env_int("MANUAL_TEST_NODE_LIMIT", 5, 1, 20)
INITIAL_CONNECT_TEST_LIMIT = env_int("INITIAL_CONNECT_TEST_LIMIT", 10, 1, 50)
LOCAL_PROXY_PORT = env_int("LOCAL_PROXY_PORT", 7928, 1, 65535)
UI_PORT = env_int("UI_PORT", 8790, 1, 65535)
INVALID_BACKOFF_SECONDS = env_int("INVALID_BACKOFF_SECONDS", 30 * 60, 1)

MAX_BLACKLIST_SIZE = 1000

SESSION_CLEANUP_INTERVAL = 300
SESSION_TIMEOUT = 30 * 24 * 3600
LOGIN_RATE_LIMIT_WINDOW = 300
LOGIN_RATE_LIMIT_MAX_ATTEMPTS = 10
CSRF_TOKEN_EXPIRY = 30 * 60
CONFIG_CACHE_TTL = 5.0
LOG_TAIL_LINES = 500
NODE_CACHE_TTL = 2.0
MAX_CONFIG_TEXT_LENGTH = 8192
HTTP_REQUEST_TIMEOUT = 12
OPENVPN_PROBE_TIMEOUT = 12
NODE_TEST_MAX_WORKERS = 5
IP_INFO_MAX_CONCURRENT = 8
AUTO_SWITCH_MAX_ATTEMPTS = 3
LOG_CLEANUP_INTERVAL = 3600
LOG_RETENTION_DAYS = 3
MAX_LOG_SIZE_BYTES = 10 * 1024 * 1024
MAX_LOG_FILES = 5

NODE_EXPORT_FIELDS = [
    "id", "country", "country_short", "host_name", "ip",
    "score", "ping", "speed", "sessions", "owner", "asn",
    "as_name", "location", "ip_type", "quality", "latency_ms",
    "probe_status", "probe_message", "probed_at",
]

from typing import Any
