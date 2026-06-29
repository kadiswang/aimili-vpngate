#!/usr/bin/env python3
"""PublicVPNList OpenVPN 节点来源模块。

环境变量:
    PUBLICVPNLIST_ENABLED=1|0         是否启用（默认 1）
    PUBLICVPNLIST_COUNTRY_INDEX_URL   国家索引页 URL（默认 https://publicvpnlist.com/）
    PUBLICVPNLIST_SOURCES             手动国家页 URL，逗号分隔；留空自动发现
    PUBLICVPNLIST_MAX_COUNTRIES       最多抓取国家页数，0 不限制（默认 0）
    PUBLICVPNLIST_PER_COUNTRY_LIMIT   每个国家最多取 N 个节点（默认 20）
    PUBLICVPNLIST_MAX_DOWNLOADS       全局最多下载 .ovpn 数，0 不限制（默认 0）
    PUBLICVPNLIST_REQUIRE_REAL_DOWNLOAD=1|0  只接受真实下载且 remote 匹配的配置（默认 1）
    PUBLICVPNLIST_MIN_SPEED           最低速度 Mbps，0 不限制（默认 0）
    PUBLICVPNLIST_MAX_LATENCY          最高延迟 ms，0 不限制（默认 0）
    PUBLICVPNLIST_MIN_SCORE            最低 Technical score，0 不限制（默认 0）
    PUBLICVPNLIST_PROTO                all / tcp / udp（默认 all）
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.parse
import urllib.request
from typing import Any
from pathlib import Path

try:
    from vpn_utils import COUNTRY_TRANSLATIONS
except ImportError:
    COUNTRY_TRANSLATIONS = {}


def _env_bool(name: str, default: bool = True) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() not in ("0", "false", "no", "off")


def _env_int(name: str, default: int, minimum: int = 0) -> int:
    try:
        val = int(os.environ.get(name, default))
        return max(minimum, val)
    except (ValueError, TypeError):
        return default


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default).strip()


def _fetch_html(url: str, timeout: int = 15, referer: str | None = None) -> str | None:
    """抓取网页 HTML"""
    headers = {"User-Agent": "Mozilla/5.0 (compatible; AimiliVPN/1.0)"}
    if referer:
        headers["Referer"] = referer
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[PublicVPNList] 抓取失败 {url}: {e}", flush=True)
        return None


def discover_country_pages(index_url: str, max_countries: int) -> list[str]:
    """从索引页自动发现国家页链接"""
    html = _fetch_html(index_url)
    if not html:
        return []

    pattern = re.compile(r'href="(/country/[^"]+)"')
    links = pattern.findall(html)
    seen: set[str] = set()
    pages: list[str] = []
    for link in links:
        if link not in seen:
            seen.add(link)
            pages.append(urllib.parse.urljoin(index_url, link))
            if max_countries > 0 and len(pages) >= max_countries:
                break
    return pages


def _parse_nodes_from_html(html: str, country_url: str) -> list[dict[str, Any]]:
    """从国家页 HTML 提取节点列表"""
    nodes: list[dict[str, Any]] = []

    row_re = re.compile(
        r'data-id="([^"]+)".*?'
        r'data-country="([^"]*)".*?'
        r'data-country-name="([^"]*)".*?'
        r'data-host="([^"]*)".*?'
        r'data-ip="([^"]*)".*?'
        r'data-speed="([^"]*)".*?'
        r'data-latency="([^"]*)".*?'
        r'data-port="([^"]*)".*?'
        r'data-proto="([^"]*)"',
        re.DOTALL,
    )
    for m in row_re.finditer(html):
        nodes.append(
            {
                "data_id": m.group(1),
                "country_code": m.group(2),
                "country_name": m.group(3),
                "host": m.group(4),
                "ip": m.group(5),
                "speed": m.group(6),
                "latency": m.group(7),
                "port": m.group(8),
                "proto": m.group(9),
                "country_url": country_url,
            }
        )

    # 提取 Technical score（每行附近）
    score_re = re.compile(r"Technical score[:\s]*([0-9.]+)", re.IGNORECASE)
    scores = score_re.findall(html)
    for i, node in enumerate(nodes):
        node["technical_score"] = scores[i] if i < len(scores) else ""

    return nodes


def _get_download_token(data_id: str, detail_url: str) -> str | None:
    """获取下载 token：详情页 → get_token.php（test_server.php 非必需，跳过以提速）"""
    base_url = "https://publicvpnlist.com"
    html = _fetch_html(detail_url, timeout=15)
    if not html:
        return None

    token_url = f"{base_url}/get_token.php?id={data_id}"
    token_raw = _fetch_html(token_url, timeout=15, referer=detail_url)
    if not token_raw:
        return None

    try:
        token_data = json.loads(token_raw)
        return token_data.get("token")
    except json.JSONDecodeError:
        return None


def download_ovpn(token: str, referer: str) -> str | None:
    """使用 token 下载 .ovpn 配置"""
    download_url = f"https://publicvpnlist.com/download.php?token={token}"
    headers = {"User-Agent": "Mozilla/5.0", "Referer": referer}
    req = urllib.request.Request(download_url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[PublicVPNList] 下载 .ovpn 失败: {e}", flush=True)
        return None


def _parse_remote_from_ovpn(text: str, expected_ip: str, expected_port: str) -> tuple[str, int, str]:
    """从 .ovpn 提取 remote host/port/proto。
    
    注意：页面上显示的 IP 可能是代理 IP，.ovpn 里的 remote 才是真实连接地址。
    不再强制校验 IP 匹配，只记录警告。
    """
    remote_re = re.compile(r"^remote\s+(\S+)\s+(\d+)\s*(.*)?$", re.MULTILINE | re.IGNORECASE)
    m = remote_re.search(text)
    if not m:
        raise ValueError("ovpn 中未找到 remote 指令")

    host = m.group(1)
    port = int(m.group(2))
    proto_flag = (m.group(3) or "").strip().lower()
    proto = "udp" if proto_flag == "udp" else "tcp"

    # 页面 IP 和配置 IP 不一致时只记录日志，不跳过
    if expected_ip and host != expected_ip:
        print(f"[PublicVPNList] 注意: 页面 IP {expected_ip} 与配置 IP {host} 不一致，使用配置 IP", flush=True)

    if expected_port and str(port) != str(expected_port):
        print(f"[PublicVPNList] 注意: 页面 port {expected_port} 与配置 port {port} 不一致，使用配置 port", flush=True)

    return host, port, proto


def _build_node_id(data_id: str, ip: str, port: str, proto: str) -> str:
    return f"pvl_{data_id}_{ip}_{port}_{proto}"


def fetch_publicvpnlist_nodes() -> list[dict[str, Any]]:
    """主入口：抓取所有 PublicVPNList 节点并返回标准格式列表"""
    enabled = _env_bool("PUBLICVPNLIST_ENABLED", True)
    if not enabled:
        return []

    index_url = _env_str("PUBLICVPNLIST_COUNTRY_INDEX_URL", "https://publicvpnlist.com/")
    max_countries = _env_int("PUBLICVPNLIST_MAX_COUNTRIES", 5)
    per_country_limit = _env_int("PUBLICVPNLIST_PER_COUNTRY_LIMIT", 5)
    max_downloads = _env_int("PUBLICVPNLIST_MAX_DOWNLOADS", 10)
    require_real = _env_bool("PUBLICVPNLIST_REQUIRE_REAL_DOWNLOAD", True)
    min_speed = _env_int("PUBLICVPNLIST_MIN_SPEED", 0)
    max_latency = _env_int("PUBLICVPNLIST_MAX_LATENCY", 0)
    min_score = _env_int("PUBLICVPNLIST_MIN_SCORE", 0)
    proto_filter = _env_str("PUBLICVPNLIST_PROTO", "all").lower()

    manual_sources = _env_str("PUBLICVPNLIST_SOURCES", "")
    if manual_sources:
        country_pages = [u.strip() for u in manual_sources.split(",") if u.strip()]
    else:
        country_pages = discover_country_pages(index_url, max_countries)

    if not country_pages:
        print("[PublicVPNList] 未发现任何国家页", flush=True)
        return []

    print(f"[PublicVPNList] 开始抓取 {len(country_pages)} 个国家页...", flush=True)

    all_nodes: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    download_count = 0

    for page in country_pages:
        html = _fetch_html(page)
        if not html:
            continue

        raw_nodes = _parse_nodes_from_html(html, page)
        print(f"[PublicVPNList] {page} 解析到 {len(raw_nodes)} 个候选节点", flush=True)

        # 按速度降序取前 N 个
        raw_nodes.sort(key=lambda n: _safe_float(n.get("speed"), 0), reverse=True)
        selected = raw_nodes[:per_country_limit]

        for node in selected:
            # proto 过滤
            proto = (node.get("proto") or "").lower()
            if proto_filter != "all" and proto != proto_filter:
                continue

            # 速度/延迟/score 过滤
            speed = _safe_float(node.get("speed"), 0)
            latency = _safe_int(node.get("latency"), 0)
            score = _safe_float(node.get("technical_score"), 0)

            if min_speed > 0 and speed < min_speed:
                continue
            if max_latency > 0 and latency > max_latency:
                continue
            if min_score > 0 and score < min_score:
                continue

            nid = _build_node_id(node["data_id"], node["ip"], node["port"], node.get("proto", "tcp"))
            if nid in seen_ids:
                continue
            seen_ids.add(nid)

            if max_downloads > 0 and download_count >= max_downloads:
                break

            # 真实下载 .ovpn（可选；失败不跳过节点，仅无 config_text）
            config_text = None
            config_remote_host = node["host"]
            config_remote_port = int(node["port"])
            config_remote_ip = node["ip"]
            remote_proto = (node.get("proto", "tcp") or "tcp").lower()
            if require_real:
                detail_url = f"https://publicvpnlist.com/download/{node['data_id']}/"
                token = _get_download_token(node["data_id"], detail_url)
                if token:
                    ovpn_text = download_ovpn(token, detail_url)
                    if ovpn_text:
                        try:
                            parsed_host, parsed_port, remote_proto = _parse_remote_from_ovpn(
                                ovpn_text, node["ip"], node["port"]
                            )
                            config_text = ovpn_text
                            config_remote_host = parsed_host
                            config_remote_port = parsed_port
                            config_remote_ip = parsed_host
                            download_count += 1
                        except ValueError as e:
                            print(f"[PublicVPNList] 配置解析失败 id={node['data_id']}: {e}，保留页面数据", flush=True)
                    else:
                        print(f"[PublicVPNList] 下载 .ovpn 失败 id={node['data_id']}，保留页面数据", flush=True)
                else:
                    print(f"[PublicVPNList] 获取 token 失败 id={node['data_id']}，保留页面数据", flush=True)

            entry: dict[str, Any] = {
                "id": nid,
                "source": "publicvpnlist",
                "country": COUNTRY_TRANSLATIONS.get(node["country_name"], node["country_name"]),
                "country_en": node["country_name"],
                "country_short": node["country_code"].upper()[:2],
                "host_name": node.get("host", ""),
                "ip": config_remote_ip,
                "score": _safe_float(node.get("technical_score"), 0) or None,
                "ping": _safe_int(node.get("latency"), 0) or None,
                "speed": speed,
                "sessions": None,
                "owner": "",
                "asn": "",
                "as_name": "",
                "location": "",
                "ip_type": "",
                "quality": "",
                "latency_ms": latency,
                "config_text": config_text or "",
                "proto": remote_proto if config_text else (node.get("proto", "tcp").lower()),
                "remote_host": config_remote_host,
                "remote_port": config_remote_port,
                "fetched_at": time.time(),
                "probe_status": "not_checked",
                "probe_message": "",
                "probed_at": 0,
                "config_file": "",
            }
            if config_text:
                entry["config_file"] = str(
                    _config_dir() / f"{nid}.ovpn"
                )
            all_nodes.append(entry)

    print(f"[PublicVPNList] 完成，共获取 {len(all_nodes)} 个节点", flush=True)
    return all_nodes


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


def _config_dir() -> Path:
    """获取 config 目录路径（延迟导入避免循环依赖）"""
    try:
        from vpngate_manager import CONFIG_DIR  # type: ignore
        return CONFIG_DIR
    except ImportError:
        return Path(__file__).resolve().parent / "vpngate_data" / "configs"
