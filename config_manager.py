#!/usr/bin/env python3
from __future__ import annotations
import json
import os
import secrets
import string
import threading
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ["VPNGATE_DATA_DIR"]).resolve() if os.environ.get("VPNGATE_DATA_DIR") else ROOT_DIR / "vpngate_data"
CONFIG_DIR = DATA_DIR / "configs"
AUTH_FILE = DATA_DIR / "auth.txt"

config_lock = threading.RLock()

_config_cache: dict[str, Any] | None = None
_config_cache_time = 0.0
CONFIG_CACHE_TTL = 5

UI_HOST = os.environ.get("VPN_UI_HOST", "::")
UI_PORT = int(os.environ.get("VPN_UI_PORT", "8787"))
LOCAL_PROXY_PORT = int(os.environ.get("LOCAL_PROXY_PORT", "7928"))


def generate_random_password() -> str:
    chars = string.ascii_letters + string.digits
    while True:
        pwd = "".join(secrets.choice(chars) for _ in range(12))
        has_lower = any(c.islower() for c in pwd)
        has_upper = any(c.isupper() for c in pwd)
        has_digit = any(c.isdigit() for c in pwd)
        if has_lower and has_upper and has_digit:
            return pwd


def generate_random_username() -> str:
    chars = string.ascii_letters + string.digits
    while True:
        first_char = secrets.choice(string.ascii_letters)
        rest = "".join(secrets.choice(chars) for _ in range(11))
        uname = first_char + rest
        has_lower = any(c.islower() for c in uname)
        has_upper = any(c.isupper() for c in uname)
        has_digit = any(c.isdigit() for c in uname)
        if has_lower and has_upper and has_digit:
            return uname


def bounded_int(value: Any, default: int, min_value: int | None = None, max_value: int | None = None) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError):
        return default
    if min_value is not None and result < min_value:
        return min_value
    if max_value is not None and result > max_value:
        return max_value
    return result


def write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def load_ui_config() -> dict[str, Any]:
    with config_lock:
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
            "min_health_score": 0,
            "connection_enabled": True,
            "fixed_node_id": "",
            "favorite_node_ids": [],
            "fav_fail_fallback": True,
            "upstream_proxy": {"enabled": False}
        }
        updated = False
        if auth_file.exists():
            try:
                data = json.loads(auth_file.read_text(encoding="utf-8"))
                for key, val in data.items():
                    config[key] = val
                for key in ["host", "port", "proxy_port", "routing_mode", "force_country", "routing_ip_type", "min_health_score", "connection_enabled", "fixed_node_id", "favorite_node_ids", "fav_fail_fallback", "upstream_proxy"]:
                    if key not in data:
                        updated = True
            except Exception as e:
                print(f"[配置警告] 读取 ui_auth.json 配置失败，将使用默认配置: {e}", flush=True)

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


def _cached_load_ui_config() -> dict[str, Any]:
    global _config_cache, _config_cache_time
    now = time.time()
    if _config_cache is not None and now - _config_cache_time < CONFIG_CACHE_TTL:
        return _config_cache
    result = load_ui_config()
    with config_lock:
        _config_cache = result
        _config_cache_time = now
    return result


def save_ui_config(config: dict[str, Any]) -> None:
    with config_lock:
        global _config_cache, _config_cache_time
        auth_file = DATA_DIR / "ui_auth.json"
        DATA_DIR.mkdir(exist_ok=True, parents=True)
        write_json(auth_file, config)
        _config_cache = dict(config)
        _config_cache_time = time.time()


import time
