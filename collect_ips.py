#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""优选IP 聚合与优选流水线。

流水线：
    采集 -> 校验分类 -> 去重合并(保留多源 provenance) -> 预排序
    -> 真实 TCP 连接测速 -> 综合评分 -> 去重/多样性筛选 -> 产出 TOP N

设计要点见 README.md，核心区别于旧版：
  1. 结构化数据模型，地区/ISP/来源不再混在同一个字符串里；
  2. 按数据源语义分类 cf / relay / proxy，不把任意开放端口当优选IP；
  3. 地区来自数据源自带的国家码/城市标记，不再对 anycast IP 猜地理；
  4. 真实 TCP 握手测速，才谈得上"优选"；
  5. 输出为按评分排序的 TOP N，编号即排名。

用法：
    python collect_ips.py              # 完整流水线
    python collect_ips.py --self-test  # 离线自检（不联网）
    python collect_ips.py --no-measure # 跳过测速（仅调试采集/分类）
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import socket
import statistics
import sys
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Windows 控制台默认 GBK，强制 UTF-8 以免 emoji/CJK 输出崩溃
for _stream in (sys.stdout, sys.stderr):
    if hasattr(_stream, "reconfigure"):
        try:
            _stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass

# ============================================================
# 配置
# ============================================================

TOP_N = 30                      # 最终产出条数：最优的 N 个 IP
MEASURE_MAX_CANDIDATES = 600    # 进入实测的候选上限（超出按预排序截断）
MEASURE_SAMPLES = 3             # 每个目标 TCP 握手采样次数
MEASURE_TIMEOUT = 2.5           # 单次握手超时（秒）
MEASURE_WORKERS = 64            # 测速并发
# 地区多样性：每地区保底名额 = ceil(top_n / 有候选的地区数)，避免榜单被 RTT 最低的
# 一两个地区吃满（实测 HK 曾占 47%、SG 只剩 1 条条）。想纯按速度取就把这个设为 False。
REGION_BALANCE = True
MAX_PER_CF_24 = 2               # 同 /24 的 CF anycast 最多入选几条（防刷屏）
MAX_PER_RELAY_IP = 2            # 同一 IP 的不同端口最多入选几条
MAX_PER_RELAY_24 = 3            # 同 /24 的中转节点最多入选几条（防同机房邻居 IP 刷榜）
# 同一 ASN 的上限按「占榜单比例」而非绝对值：绝对上限会让 --top 变小时单 ASN 占比飙升
# （30 条时 6 条 = 20%，50 条时才 12%）。实际条数 = max(地板, ceil(top_n * 比例))，
# 于是 --top 50 仍是 6 条、--top 30 收紧到 4 条、--top 100 放宽到 12 条。
# 中转节点真正会"刷榜"的维度是上游而非 /24：像 NTT、AWS 这类上游横跨多个 /24，
# 只靠 /24 上限管不住（实测 12/50 条来自同一个上游）。
# 对 cf 不生效：anycast 不管哪个段都是 Cloudflare 的 AS13335，限了会把 CF 全灭。
MAX_PER_ASN_RATIO = 0.12
MAX_PER_ASN_MIN = 2
# 为 ASN 去重预取归属的候选数（按评分取前 N）。只覆盖"有机会入选"的范围，
# 与 enrich 共用 enrich_cache.json，不改变"只反查少量 IP"的初衷。
ASN_PRECHECK_LIMIT = 300
MIN_SUCCESS_RATE = 0.30         # 低于该握手成功率的候选直接淘汰（3 次采样中至少成功 1 次）

# 产物回落保护：本次产出条数不足上次的该比例时，视为数据源异常，拒绝覆盖原有产物。
# 比较基线取 min(上次条数, --top)，因此主动调小 --top 不会被误判。
MIN_OUTPUT_RATIO = 0.5

# 目标地区：relay/proxy 只保留亚太常用落地。
# CF anycast 不存在"地区"概念（由 BGP 就近路由），故不做地区过滤。
ALLOWED_REGIONS = {"HK", "SG", "JP", "KR", "TW"}

# 参与最终排名的数据源语义
#   cf    = Cloudflare anycast 边缘 IP（无端口，按 :443 实测）
#   relay = 数据源自带地区标记的 ip:port 中转节点
#   proxy = 通用开放端口代理（语义不可控，默认不参与优选）
#
# 只要 CF anycast：把下面改成 ("cf",)；只要中转节点：("relay",)
ALLOWED_KINDS = ("cf", "relay")

# 评分权重（仅在对应分量有数据时生效，权重会重新归一）
W_LATENCY = 0.65      # 延迟
W_RELIABILITY = 0.20  # 握手成功率
W_SOURCES = 0.10      # 多源共识：多个上游同时收录 == 更稳定
W_UPSTREAM = 0.10     # 上游自带测速值（覆盖率过低时自动禁用）

# 延迟绝对衰减常数：score = exp(-rtt / TAU)，100ms 约为 0.37。
# 用绝对值而非 min-max，避免个别极端超时的离群值把整段压缩成"接近满分"。
LATENCY_TAU_MS = 100.0
# 上游测速值的覆盖率低于该比例时，该分量不可靠，直接弃用并重分配权重
MIN_UPSTREAM_COVERAGE = 0.10

# 数据源声明
#   kind: cf_list     纯 CF IP 清单（强制 CIDR 校验）
#         region_feed 带国家码/城市标记的 ip:port 清单
#         speed_table 带速度标注的通用代理表（默认不入选，仅作参考/降级）
SOURCES = [
    {"name": "uouin", "kind": "cf_list", "url": "https://api.uouin.com/cloudflare.html"},
    {"name": "ip164746", "kind": "cf_list", "url": "https://ip.164746.xyz"},
    {"name": "ipdb030101", "kind": "cf_list", "url": "https://ipdb.api.030101.xyz/?type=bestcf&country=true"},
    {"name": "addr-cfyes", "kind": "cf_list", "url": "https://addressesapi.090227.xyz/CloudFlareYes"},
    {"name": "addr-164746", "kind": "cf_list", "url": "https://addressesapi.090227.xyz/ip.164746.xyz"},
    {"name": "ymyuuu", "kind": "cf_list", "url": "https://raw.githubusercontent.com/ymyuuu/IPDB/refs/heads/main/bestcf.txt"},
    {"name": "zip", "kind": "region_feed", "url": "https://zip.cm.edu.kg/all.txt"},
    # 已知失效（HTTP 403），保留注释以便日后恢复
    # {"name": "cf090227", "kind": "cf_list", "url": "https://cf.090227.xyz"},
    {"name": "cnjx", "kind": "speed_table", "url": "https://raw.githubusercontent.com/JiangXi9527/CNJX/refs/heads/main/test-ip.txt"},
]

LOCAL_CITY_FEED = "city.txt"          # 本地中转城市表，不再回环请求本仓库的 GitHub Raw
CF_CIDR_URL = "https://www.cloudflare.com/ips-v4"
CF_CIDR_URL6 = "https://www.cloudflare.com/ips-v6"
CF_CIDR_FALLBACK = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

OUTPUT_TXT = "ip.txt"
OUTPUT_JSON = "best.json"
ENRICH_CACHE = "enrich_cache.json"

IP_PORT_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?(?![\d.])")
SPEED_KBPS_RE = re.compile(r"(\d+(?:\.\d+)?)\s*(k|m)?b/s", re.IGNORECASE)

REGION_RULES = [
    ("HK", ("hong kong", "hongkong", "香港")),
    ("SG", ("singapore", "新加坡", "狮城")),
    ("JP", ("japan", "tokyo", "osaka", "日本", "东京", "東京", "大阪")),
    ("KR", ("korea", "seoul", "韩国", "韓國", "首尔", "首爾")),
    ("TW", ("taiwan", "taipei", "台湾", "台灣", "台北", "新北", "台中", "高雄")),
]
COUNTRY_CODE_REGION = {"HK", "SG", "JP", "KR", "TW"}

# ============================================================
# 数据模型
# ============================================================

@dataclass
class Entry:
    ip: str
    port: Optional[int] = None
    kind: str = "unknown"           # cf | relay | proxy
    region: Optional[str] = None    # HK/SG/... 或 None
    label: str = ""                 # 原始地区/城市文本
    sources: set = field(default_factory=set)
    upstream_kbps: float = 0.0
    # 测速结果
    rtt_ms: Optional[float] = None
    success_rate: float = 0.0
    score: float = 0.0
    # 展示用（仅对入选者做反查）
    isp: str = ""
    asn: str = ""
    country: str = ""
    city: str = ""

    @property
    def endpoint(self) -> str:
        return f"{self.ip}:{self.port}" if self.port else self.ip

    @property
    def probe_port(self) -> int:
        return self.port or 443

    @property
    def net24(self) -> str:
        return ".".join(self.ip.split(".")[:3])

    @property
    def asn_key(self) -> str:
        """只取 ASN 号本身（'AS2914 NTT America' -> 'AS2914'），避免同一 ASN 因命名差异漏判。"""
        return self.asn.split(" ", 1)[0].upper() if self.asn else ""

    @property
    def stable_id(self) -> str:
        return f"{self.kind}:{self.endpoint}"


# ============================================================
# HTTP
# ============================================================

def build_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(total=2, backoff_factor=1.5, status_forcelist=[429, 500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry, pool_connections=16, pool_maxsize=16)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers["User-Agent"] = "yxip-pipeline/2.0 (+https://github.com/chris202010/yxip)"
    return s


SESSION = build_session()


def safe_get(url: str, timeout: tuple = (6, 30)) -> Optional[requests.Response]:
    try:
        r = SESSION.get(url, timeout=timeout)
        r.raise_for_status()
        return r
    except requests.exceptions.Timeout:
        print(f"  ⏰ 超时: {url}")
    except requests.exceptions.RequestException as e:
        print(f"  ❌ 失败: {url} | {type(e).__name__}")
    return None


def load_cf_cidrs() -> list:
    nets = []
    for url in (CF_CIDR_URL, CF_CIDR_URL6):
        r = safe_get(url, timeout=(6, 15))
        if not r:
            continue
        for line in r.text.split():
            line = line.strip()
            if not line:
                continue
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                pass
    if not nets:
        print("  ⚠️ 无法获取 Cloudflare 官方网段，使用内置回退表")
        nets = [ipaddress.ip_network(c) for c in CF_CIDR_FALLBACK]
    return nets


def in_cf_cidr(ip: str, nets: list) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


# ============================================================
# 解析
# ============================================================

def valid_ip(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def valid_port(port: Optional[int]) -> bool:
    return port is not None and 0 < port < 65536


def parse_region(text: str) -> Optional[str]:
    """从地区/城市文本推断地区码。ASCII 关键词用词边界，避免 KR 命中 Krakow。"""
    if not text:
        return None
    low = text.lower()
    for code, keys in REGION_RULES:
        for k in keys:
            if k.isascii():
                if re.search(rf"(?<![a-z]){re.escape(k)}(?![a-z])", low):
                    return code
            elif k in text:
                return code
    return None


def parse_speed_kbps(text: str) -> float:
    """解析 '20642 kB/s' / 'CF-0.12MB/s' 之类标注，统一为 kB/s。"""
    m = SPEED_KBPS_RE.search(text or "")
    if not m:
        return 0.0
    val = float(m.group(1))
    unit = (m.group(2) or "k").lower()
    return val * 1024.0 if unit == "m" else val


def iter_ip_candidates(line: str):
    """产出 (ip, port)。过滤非法八位组与非法端口。"""
    for m in IP_PORT_RE.finditer(line):
        ip, port_s = m.group(1), m.group(2)
        if not valid_ip(ip):
            continue
        port = int(port_s) if port_s else None
        if port is not None and not valid_port(port):
            continue
        yield ip, port


def split_meta(line: str) -> tuple:
    """拆出 'IP[:port]#后面这段元数据'。"""
    if "#" in line:
        head, _, meta = line.partition("#")
        return head.strip(), meta.strip()
    return line.strip(), ""


# ============================================================
# 采集
# ============================================================

def collect_cf_list(text: str, source: str, cf_nets: list, pool: dict) -> int:
    """CF 清单：强制 CIDR 校验，非 CF 段直接丢弃。"""
    added = 0
    for line in text.splitlines():
        for ip, port in iter_ip_candidates(line):
            if not in_cf_cidr(ip, cf_nets):
                continue
            key = (ip, None)  # CF anycast 忽略端口，统一按 :443 实测
            e = pool.get(key)
            if e is None:
                e = pool[key] = Entry(ip=ip, port=None, kind="cf")
            e.sources.add(source)
            e.upstream_kbps = max(e.upstream_kbps, parse_speed_kbps(line))
            added += 1
    return added


def collect_region_feed(text: str, source: str, pool: dict, cf_nets: list) -> int:
    """地区清单：形如 ip:port#HK 或 ip:port#香港。地区以数据源自带标记为准。"""
    added = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        head, meta = split_meta(line)
        cands = list(iter_ip_candidates(head))
        if not cands:
            continue
        ip, port = cands[0]
        region = None
        code = meta.strip().upper()
        if code in COUNTRY_CODE_REGION:
            region = code
        else:
            region = parse_region(meta)
        kind = "cf" if in_cf_cidr(ip, cf_nets) else "relay"
        if kind == "cf":
            # anycast 无地区概念：地区标记对 CF IP 无意义，丢弃
            key = (ip, None)
            e = pool.get(key)
            if e is None:
                e = pool[key] = Entry(ip=ip, port=None, kind="cf")
            e.sources.add(source)
            added += 1
            continue
        if not valid_port(port):
            continue
        key = (ip, port)
        e = pool.get(key)
        if e is None:
            e = pool[key] = Entry(ip=ip, port=port, kind="relay")
        if region:
            e.region, e.label = region, meta
        e.sources.add(source)
        e.upstream_kbps = max(e.upstream_kbps, parse_speed_kbps(meta))
        added += 1
    return added


def collect_speed_table(text: str, source: str, pool: dict, cf_nets: list) -> int:
    """速度表：通用开放端口代理，标 proxy；若 IP 属 CF 段则归 cf。"""
    added = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        head, meta = split_meta(line)
        cands = list(iter_ip_candidates(head))
        if not cands:
            continue
        ip, port = cands[0]
        if in_cf_cidr(ip, cf_nets):
            key = (ip, None)
            e = pool.get(key)
            if e is None:
                e = pool[key] = Entry(ip=ip, port=None, kind="cf")
            e.sources.add(source)
            e.upstream_kbps = max(e.upstream_kbps, parse_speed_kbps(meta))
            added += 1
            continue
        if not valid_port(port):
            continue
        key = (ip, port)
        e = pool.get(key)
        if e is None:
            e = pool[key] = Entry(ip=ip, port=port, kind="proxy")
        e.sources.add(source)
        e.upstream_kbps = max(e.upstream_kbps, parse_speed_kbps(meta))
        region = parse_region(meta)
        if region and not e.region:
            e.region, e.label = region, meta
        added += 1
    return added


def load_local_city_feed(path: str) -> str:
    """可选的本地地区表。文件不存在时静默跳过（不报警、不占篇幅）。"""
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        print(f"  ⚠️ 无法读取本地 {path}: {e}")
        return ""


def collect_all(cf_nets: list) -> tuple:
    """返回 (pool, ok_sources, failed_sources)。源失败不再静默，交由 main 汇总告警。"""
    pool: dict = {}
    ok_sources: list = []
    failed_sources: list = []
    print("【采集】")
    for src in SOURCES:
        print(f"  → {src['name']} ({src['kind']})")
        r = safe_get(src["url"], timeout=(6, 45) if src["kind"] == "region_feed" else (6, 30))
        if not r:
            failed_sources.append(src["name"])
            continue
        text = r.text
        if src["kind"] == "cf_list":
            n = collect_cf_list(text, src["name"], cf_nets, pool)
        elif src["kind"] == "region_feed":
            n = collect_region_feed(text, src["name"], pool, cf_nets)
        else:
            n = collect_speed_table(text, src["name"], pool, cf_nets)
        ok_sources.append(src["name"])
        print(f"     ✅ 记录 {n} 条")

    city_text = load_local_city_feed(LOCAL_CITY_FEED)
    if city_text:
        n = collect_region_feed(city_text, "city.txt", pool, cf_nets)
        print(f"  → city.txt (本地 region_feed) ✅ 记录 {n} 条")

    return pool, ok_sources, failed_sources


# ============================================================
# 候选过滤 / 预排序
# ============================================================

def pre_score(e: Entry) -> float:
    """实测前的启发式权重：多源共识 + 上游测速 + 地区已知。"""
    s = 0.0
    s += min(len(e.sources), 4) * 1.0
    s += min(e.upstream_kbps / 5000.0, 2.0)
    if e.region:
        s += 0.5
    if e.kind == "cf":
        s += 0.5
    return s


def select_candidates(pool: dict) -> list:
    cands = []
    for e in pool.values():
        if e.kind not in ALLOWED_KINDS:
            continue
        if e.kind == "cf":
            # anycast 无地区概念，全部放行（是否参与由 ALLOWED_KINDS 决定）
            pass
        elif e.region is None or e.region not in ALLOWED_REGIONS:
            continue
        cands.append(e)

    cands.sort(key=pre_score, reverse=True)

    # 分地区轮转取样，避免单个地区/数据源吃满实测预算
    buckets: dict = defaultdict(list)
    for e in cands:
        buckets[e.region or "CF"].append(e)
    picked, i = [], 0
    order = sorted(buckets.keys(), key=lambda k: -len(buckets[k]))
    while len(picked) < MEASURE_MAX_CANDIDATES and any(buckets[k] for k in order):
        for k in order:
            if buckets[k] and len(picked) < MEASURE_MAX_CANDIDATES:
                picked.append(buckets[k].pop(0))
        i += 1
        if i > 10000:
            break
    return picked


# ============================================================
# 实测
# ============================================================

def tcp_probe(ip: str, port: int, samples: int, timeout: float) -> tuple:
    rtts = []
    for _ in range(samples):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                rtts.append((time.perf_counter() - t0) * 1000.0)
        except OSError:
            pass
    if not rtts:
        return None, 0.0
    return min(rtts), len(rtts) / samples


def measure(entries: list) -> None:
    print(f"\n【实测】TCP 握手 · {len(entries)} 个候选 · 每个 {MEASURE_SAMPLES} 次采样")
    done = 0
    with ThreadPoolExecutor(max_workers=MEASURE_WORKERS) as ex:
        futures = {
            ex.submit(tcp_probe, e.ip, e.probe_port, MEASURE_SAMPLES, MEASURE_TIMEOUT): e
            for e in entries
        }
        for fut in as_completed(futures):
            e = futures[fut]
            try:
                rtt, rate = fut.result()
            except Exception:
                rtt, rate = None, 0.0
            e.rtt_ms, e.success_rate = rtt, rate
            done += 1
            if done % 40 == 0:
                print(f"  ... {done}/{len(entries)}")
    ok = sum(1 for e in entries if e.rtt_ms is not None)
    print(f"  ✅ 可连通 {ok}/{len(entries)}")


def print_measurement_stats(entries: list) -> None:
    """说明"为什么这些入选"：给出按类型/地区/数据源的连通画像。"""
    print("\n【实测统计】")

    def line(tag: str, es: list, indent: str = "  ") -> None:
        oks = [e.rtt_ms for e in es if e.rtt_ms is not None]
        if oks:
            print(
                f"{indent}{tag:<9} 候选 {len(es):>4}  连通 {len(oks):>4} ({len(oks)/len(es):>4.0%})"
                f"  最快 {min(oks):>6.0f}ms  中位 {statistics.median(oks):>6.0f}ms"
            )
        else:
            print(f"{indent}{tag:<9} 候选 {len(es):>4}  连通 {0:>4} (  0%)  —— 全部不可达")

    by_kind = defaultdict(list)
    for e in entries:
        by_kind[e.kind].append(e)
    for kind in sorted(by_kind):
        line(kind, by_kind[kind])

    print("  按地区:")
    by_region = defaultdict(list)
    for e in entries:
        by_region[display_region(e)].append(e)
    for region in sorted(by_region):
        line(region, by_region[region], indent="    ")

    print("  按数据源(候选可带多源):")
    by_source = defaultdict(list)
    for e in entries:
        for s in e.sources:
            by_source[s].append(e)
    for src in sorted(by_source):
        line(src, by_source[src], indent="    ")


# ============================================================
# 评分
# ============================================================

def norm_map(values: dict, lower_better: bool) -> dict:
    if not values:
        return {}
    lo, hi = min(values.values()), max(values.values())
    if hi - lo < 1e-9:
        return {k: 1.0 for k in values}
    if lower_better:
        return {k: (hi - v) / (hi - lo) for k, v in values.items()}
    return {k: (v - lo) / (hi - lo) for k, v in values.items()}


def latency_score(rtt_ms: float) -> float:
    """绝对延迟得分：exp(-rtt/TAU)，与候选池无关，跨次运行可比。"""
    if rtt_ms is None:
        return 0.0
    return math.exp(-max(rtt_ms, 0.0) / LATENCY_TAU_MS)


def score_entries(entries: list) -> list:
    live = [e for e in entries if e.rtt_ms is not None and e.success_rate >= MIN_SUCCESS_RATE]
    if not live:
        print("  ⚠️ 没有通过连通性门槛的候选")
        return []

    up_raw = {id(e): e.upstream_kbps for e in live}
    coverage = sum(1 for v in up_raw.values() if v > 0) / len(live)
    use_upstream = coverage >= MIN_UPSTREAM_COVERAGE
    up_n = norm_map(up_raw, lower_better=False) if use_upstream else {}
    if not use_upstream:
        print(f"  · 上游测速值覆盖率 {coverage:.0%} < {MIN_UPSTREAM_COVERAGE:.0%}，该分量已弃用")

    for e in live:
        comps = [
            (W_LATENCY, latency_score(e.rtt_ms)),
            (W_RELIABILITY, e.success_rate),
            (W_SOURCES, min(len(e.sources), 3) / 3.0),
        ]
        if use_upstream:
            comps.append((W_UPSTREAM, up_n.get(id(e), 0.0)))
        total_w = sum(w for w, _ in comps)
        e.score = round(100.0 * sum(w * v for w, v in comps) / total_w, 2)

    live.sort(key=lambda e: e.score, reverse=True)
    return live


# ============================================================
# 多样性筛选 -> TOP N
# ============================================================

def cap_for_top(ratio: float, floor: int, top_n: int) -> int:
    """把「占榜单比例」换算成本次运行的实际条数上限（带最小条数地板）。

    上限必须随 --top 缩放，否则同一份配置在 30 条榜单里会允许单 ASN 占到 20%。
    """
    return max(floor, math.ceil(top_n * ratio))


def region_floor(entries: list, top_n: int) -> int:
    """每个地区的保底名额：ceil(top_n / 有候选的地区数)。

    没有它，榜单会被 RTT 最低的那一两个地区吃掉（实测 HK 曾占 47%、SG 只剩 1 条），
    因为 pick_top 在加地区约束前是纯按评分取的。`cf` 不参与：anycast 无地区概念。
    """
    if not REGION_BALANCE:
        return 0
    regions = {e.region for e in entries if e.kind != "cf" and e.region}
    if not regions:
        return 0
    return max(1, math.ceil(top_n / len(regions)))


# 多样性约束的放行顺序，元组含义 = (地区保底, /24 上限, ASN 上限)。
# 地区保底放最后：先容忍同 /24、再容忍同 ASN，才轮到放弃"每个地区都有代表"。
PICK_PHASES = (
    (True, True, True),      # 全严格
    (True, False, True),     # 放宽 /24
    (True, False, False),    # 再放宽 ASN
    (False, False, False),   # 最后放弃地区保底
)


def pick_top(entries: list, top_n: int) -> list:
    """按评分顺序做多样性筛选。

    每轮依次放行更宽松的约束，直到凑满 top_n：
    `/24`、ASN、地区保底都是软约束（备选不足时才放宽），同 IP 上限是硬约束（永不放宽）。
    放宽顺序是 /24 → ASN → 地区保底：地区保底放最后，因为"每个地区都得有代表"
    是这里最不该妥协的一条，宁可先放过同 ASN 的候选。

    这样加严多样性不会让榜单变短——变短会误触发产物回落保护。
    ASN 未知（反查失败）的候选不参与 ASN 限制，避免 ip-api 挂掉时把 relay 全灭。
    单 ASN 与单地区的条数上限都由 top_n 现算，不是固定值。
    """
    picked: list = []
    taken: set = set()          # Entry 是 dataclass（不可哈希），用 id 做身份标记
    max_asn = cap_for_top(MAX_PER_ASN_RATIO, MAX_PER_ASN_MIN, top_n)
    floor = region_floor(entries, top_n)
    per24_cf, per24_relay, per_ip, per_asn = Counter(), Counter(), Counter(), Counter()
    per_region = Counter()
    for keep_region, keep_24, keep_asn in PICK_PHASES:
        for e in entries:
            if len(picked) >= top_n:
                return picked
            if id(e) in taken:
                continue
            if e.kind == "cf":
                # 地区保底阶段不吸收 cf：它没有地区配额，若允许它在这几轮自由入选，
                # 会把本该留给 KR/SG/TW 的名额提前吃掉（实测让 CF 抢走 7 个名额）。
                # 因此 cf 只做为「relay 凑不满」时的补位，留到最后一个阶段。
                if keep_region and floor:
                    continue
                if keep_24 and per24_cf[e.net24] >= MAX_PER_CF_24:
                    continue
            else:
                if per_ip[e.ip] >= MAX_PER_RELAY_IP:
                    continue
                if keep_region and e.region and per_region[e.region] >= floor:
                    continue
                if keep_24 and per24_relay[e.net24] >= MAX_PER_RELAY_24:
                    continue
                if keep_asn and e.asn_key and per_asn[e.asn_key] >= max_asn:
                    continue
            picked.append(e)
            taken.add(id(e))
            if e.kind == "cf":
                per24_cf[e.net24] += 1
            else:
                per_ip[e.ip] += 1
                per24_relay[e.net24] += 1
                if e.region:
                    per_region[e.region] += 1
                if e.asn_key:
                    per_asn[e.asn_key] += 1
    return picked


# ============================================================
# 产物完整性保护
# ============================================================

def count_previous(path: str) -> int:
    """统计既有产物的有效行数，作为回落保护的基线；文件不存在视为首次运行。"""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return sum(1 for line in f if line.strip())
    except OSError:
        return 0


def output_regression(prev_count: int, top: list, top_n: int) -> Optional[str]:
    """检测产物回落：明显少于上次时返回原因，否则返回 None。纯函数，便于离线自检。"""
    baseline = min(prev_count, top_n)
    if baseline > 0 and len(top) < baseline * MIN_OUTPUT_RATIO:
        return (
            f"本次仅 {len(top)} 条，低于上次基线 {baseline} 条的 {MIN_OUTPUT_RATIO:.0%}"
            f"（阈值 {baseline * MIN_OUTPUT_RATIO:.0f} 条）"
        )
    return None


# ============================================================
# 归属反查（ASN 预取 + 入选者详情），均走本地缓存
# ============================================================

def load_enrich_cache() -> dict:
    try:
        with open(ENRICH_CACHE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_enrich_cache(cache: dict) -> None:
    try:
        with open(ENRICH_CACHE, "w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=1, sort_keys=True)
    except OSError:
        pass


IPAPI_URL = "http://ip-api.com/batch?lang=zh-CN&fields=status,country,city,isp,as,query"


def ipapi_batch(ips: list) -> dict:
    """批量反查归属，返回 {ip: 记录}。整批失败只丢这一批，不抛出。"""
    out: dict = {}
    if not ips:
        return out
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            r = SESSION.post(IPAPI_URL, json=chunk, timeout=(6, 25))
            if not r.ok:
                print(f"  ⚠️ batch 返回 {r.status_code}")
                continue
            for item in r.json():
                if item.get("status") == "success":
                    out[item.get("query", "")] = item
        except (requests.RequestException, ValueError) as exc:
            print(f"  ⚠️ 反查失败: {type(exc).__name__}")
    return out


def apply_location(entries: list, records: dict) -> None:
    """把反查结果写进 Entry 的展示字段。"""
    for e in entries:
        d = records.get(e.ip) or {}
        if d:
            e.country = d.get("country", "") or ""
            e.city = d.get("city", "") or ""
            e.isp = d.get("isp", "") or ""
            e.asn = d.get("as", "") or ""


def prefetch_asn(entries: list, limit: int) -> set:
    """为 ASN 多样性预取归属信息，返回覆盖到的 IP 集合（供 enrich 复用缓存）。

    只取评分靠前的 limit 个候选：同一 ASN 的上限只需要在"有机会入选"的范围内比对，
    因此请求量仍然很小（默认 300 个 IP = 3 个 batch 请求）。
    """
    window = entries[:limit]
    cache = load_enrich_cache()
    targets = [e.ip for e in window if not cache.get(e.ip, {}).get("as")]
    if targets:
        print(f"\n【预取】ip-api batch · {len(targets)} 个 IP（ASN 多样性）")
        cache.update(ipapi_batch(targets))
    apply_location(window, {e.ip: cache.get(e.ip, {}) for e in window})
    return {e.ip for e in window if cache.get(e.ip, {}).get("as")}


def enrich(entries: list, keep_extra: Optional[set] = None) -> None:
    cache = load_enrich_cache()
    targets = [e.ip for e in entries if e.ip not in cache]
    if targets:
        print(f"\n【反查】ip-api batch · {len(targets)} 个 IP")
        cache.update(ipapi_batch(targets))

    apply_location(entries, {e.ip: cache.get(e.ip, {}) for e in entries})

    # 只保留当前相关的缓存条目（入选者 + ASN 预取窗口），避免无限膨胀
    keep = {e.ip for e in entries} | (keep_extra or set())
    save_enrich_cache({k: v for k, v in cache.items() if k in keep})


# ============================================================
# 输出
# ============================================================

def display_region(e: Entry) -> str:
    if e.kind == "cf":
        return e.region or "CF"
    return e.region or "??"


def write_outputs(top: list, txt_path: str = OUTPUT_TXT, json_path: str = OUTPUT_JSON) -> None:
    now = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")

    with open(txt_path, "w", encoding="utf-8") as f:
        for rank, e in enumerate(top, 1):
            tag = e.isp or e.kind
            f.write(f"{e.endpoint}#{display_region(e)}-{rank}-{tag}\n")

    payload = {
        "generated_at": now,
        "top_n": len(top),
        "scoring": {
            "latency": W_LATENCY,
            "reliability": W_RELIABILITY,
            "sources": W_SOURCES,
            "upstream": W_UPSTREAM,
        },
        "measurement": {
            "type": "tcp_connect",
            "samples": MEASURE_SAMPLES,
            "timeout_s": MEASURE_TIMEOUT,
            "note": "RTT 由本机/本 runner 测得，仅供横向比较；客户端应结合自身网络复测",
        },
        "entries": [
            {
                "rank": rank,
                "endpoint": e.endpoint,
                "ip": e.ip,
                "port": e.port,
                "kind": e.kind,
                "region": e.region,
                "label": e.label,
                "country": e.country,
                "city": e.city,
                "isp": e.isp,
                "asn": e.asn,
                "rtt_ms": round(e.rtt_ms, 2) if e.rtt_ms is not None else None,
                "success_rate": round(e.success_rate, 2),
                "score": e.score,
                "sources": sorted(e.sources),
                "stable_id": e.stable_id,
            }
            for rank, e in enumerate(top, 1)
        ],
    }
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def print_summary(top: list) -> None:
    print(f"\n【结果】最优 {len(top)} 个 IP\n")
    print(f"  {'#':>3}  {'端点':<24}{'类':<6}{'区':<5}{'RTT':>8}{'成功率':>7}{'评分':>7}  {'来源'}")
    print("  " + "-" * 92)
    for rank, e in enumerate(top, 1):
        rtt = f"{e.rtt_ms:.0f}ms" if e.rtt_ms is not None else "-"
        print(
            f"  {rank:>3}  {e.endpoint:<24}{e.kind:<6}{display_region(e):<5}"
            f"{rtt:>8}{e.success_rate:>7.0%}{e.score:>7.1f}  {','.join(sorted(e.sources))}"
        )
    by_region = Counter(display_region(e) for e in top)
    print(f"\n  地区分布: {dict(sorted(by_region.items()))}")
    by_kind = Counter(e.kind for e in top)
    print(f"  类型分布: {dict(by_kind)}")


# ============================================================
# 自检
# ============================================================

def self_test() -> int:
    fails = []

    def check(cond, msg):
        if not cond:
            fails.append(msg)

    # 地区推断
    check(parse_region("香港") == "HK", "parse_region 香港")
    check(parse_region("新加坡") == "SG", "parse_region 新加坡")
    check(parse_region("Los Angeles") is None, "parse_region 不应命中 LA")
    check(parse_region("Krakow") is None, "parse_region 不应命中 KR 子串")
    check(parse_region("Tokyo") == "JP", "parse_region Tokyo")
    check(parse_region("smtp") is None, "parse_region 不应命中 TP 子串")

    # 速度解析
    check(parse_speed_kbps("#中国26929 kB/s") == 26929, "parse_speed kB/s")
    check(abs(parse_speed_kbps("#CF-0.12MB/s") - 122.88) < 0.01, "parse_speed MB/s")

    # IP / 端口校验
    check(valid_ip("1.2.3.4"), "valid_ip ok")
    check(not valid_ip("999.2.3.4"), "valid_ip 999")
    check(not valid_port(0) and not valid_port(70000) and valid_port(443), "valid_port")

    # 提取候选
    got = list(iter_ip_candidates("175.29.22.104:21029#香港"))
    check(got == [("175.29.22.104", 21029)], f"iter_ip_candidates 得到 {got}")
    got = list(iter_ip_candidates("104.17.115.76"))
    check(got == [("104.17.115.76", None)], "iter_ip_candidates 无端口")

    # CF 网段
    nets = [ipaddress.ip_network(c) for c in CF_CIDR_FALLBACK]
    check(in_cf_cidr("104.17.115.76", nets), "in_cf_cidr 命中")
    check(not in_cf_cidr("175.29.22.104", nets), "in_cf_cidr 未命中")

    # 采集与分类
    pool: dict = {}
    collect_region_feed("175.29.22.104:21029#香港\n175.29.22.104:21027#日本", "t", pool, nets)
    check(pool[("175.29.22.104", 21029)].kind == "relay", "region_feed relay")
    check(pool[("175.29.22.104", 21029)].region == "HK", "region_feed region")
    collect_cf_list("104.17.115.76\n175.29.22.104:21029", "c", nets, pool)
    check(pool[("104.17.115.76", None)].kind == "cf", "cf_list cf")
    check(("175.29.22.104", 21029) in pool, "cf_list 不应删除已有 relay")
    # 非 CF 段不得进入 cf 池
    check(("175.29.22.104", None) not in pool, "cf_list 必须过滤非 CF 段")

    # 去重合并保留多源
    collect_cf_list("104.17.115.76", "c2", nets, pool)
    check(pool[("104.17.115.76", None)].sources == {"c", "c2"}, "多源 provenance 合并")

    # anycast 不应携带地区标记
    collect_region_feed("104.18.40.100:443#SG", "z", pool, nets)
    check(pool[("104.18.40.100", None)].region is None, "CF anycast 应丢弃地区标记")

    # 地区清单只保留目标地区
    pool2: dict = {}
    collect_region_feed("1.2.3.4:8443#DE\n1.2.3.5:8443#SG", "z", pool2, nets)
    keep = select_candidates(pool2)
    check([e.ip for e in keep] == ["1.2.3.5"], f"非目标地区应被过滤, 得到 {[e.ip for e in keep]}")

    # 通用代理端口默认不入选
    pool3: dict = {}
    collect_speed_table("166.108.239.108:3389#新加坡", "s", pool3, nets)
    check(pool3[("166.108.239.108", 3389)].kind == "proxy", "speed_table 归 proxy")
    check(select_candidates(pool3) == [], "proxy 默认不参与优选")

    # /24 与稳定 ID
    e = Entry(ip="104.17.115.76", kind="cf")
    check(e.net24 == "104.17.115", "net24")
    e2 = Entry(ip="175.29.22.104", port=21029, kind="relay")
    check(e2.endpoint == "175.29.22.104:21029", "endpoint")

    # 评分与筛选
    a = Entry(ip="1.1.1.1", kind="cf", rtt_ms=50, success_rate=1.0, sources={"a", "b", "c"})
    b = Entry(ip="2.2.2.2", kind="cf", rtt_ms=200, success_rate=1.0, sources={"a"})
    c = Entry(ip="3.3.3.3", kind="cf", rtt_ms=10, success_rate=0.0, sources={"a"})
    ranked = score_entries([a, b, c])
    check(all(x.ip != "3.3.3.3" for x in ranked), "成功率过低应淘汰")
    check(ranked[0].ip == "1.1.1.1", "低延迟+多源应排第一")

    # 回归：离群值不得压缩延迟尺度（旧 min-max 实现的 bug）
    fast = Entry(ip="4.4.4.4", kind="cf", rtt_ms=47, success_rate=1.0, sources={"a"})
    mid = Entry(ip="5.5.5.5", kind="cf", rtt_ms=207, success_rate=1.0, sources={"a", "b"})
    slow = Entry(ip="6.6.6.6", kind="cf", rtt_ms=1301, success_rate=1.0, sources={"a"})
    ranked2 = score_entries([fast, mid, slow])
    check(ranked2[0].ip == "4.4.4.4", f"最快者应第一，实际 {ranked2[0].endpoint}")
    check(ranked2[-1].ip == "6.6.6.6", "最慢者应最后")
    check(ranked2[0].score - ranked2[1].score > 10, "47ms 与 207ms 的评分应显著拉开差距")

    # 延迟得分单调、绝对
    check(latency_score(0) == 1.0, "latency_score(0)")
    check(latency_score(100) < 0.4 and latency_score(100) > 0.3, "latency_score(100)≈0.37")
    check(latency_score(50) > latency_score(100) > latency_score(200), "latency_score 单调")

    # 上游测速值覆盖率过低时应弃用该分量
    lone = Entry(ip="7.7.7.7", kind="cf", rtt_ms=60, success_rate=1.0,
                 sources={"a"}, upstream_kbps=5000.0)
    plain = [Entry(ip=f"8.8.8.{i}", kind="cf", rtt_ms=60, success_rate=1.0, sources={"a"})
             for i in range(1, 20)]
    mixed = score_entries([lone] + plain)
    check(mixed[0].upstream_kbps == 5000.0, "稀疏上游数据不应改变排序")

    # 多样性：/24 与同 IP 上限（备选充足时严格生效）
    same24 = [Entry(ip=f"9.9.9.{i}", kind="cf", rtt_ms=10, success_rate=1.0, score=100 - i) for i in range(10)]
    other24 = [Entry(ip=f"9.9.8.{i}", kind="cf", rtt_ms=10, success_rate=1.0, score=50 - i) for i in range(10)]
    top = pick_top(same24 + other24, 4)
    check(sum(1 for e in top if e.net24 == "9.9.9") == MAX_PER_CF_24, "cf 同 /24 应受限")
    check(len(top) == 4, "cf 应换 /24 补足条数")

    # 备选不足时放宽 /24 补足，产出不得被多样性约束压到不足额
    solo24 = [Entry(ip=f"9.9.9.{i}", kind="cf", rtt_ms=10, success_rate=1.0, score=100 - i) for i in range(6)]
    check(len(pick_top(solo24, 6)) == 6, "备选不足时应放宽 /24 补足")

    # relay 同 /24 也受限（回归：同机房的邻居 IP 刷满榜位）
    ntt = [Entry(ip=f"207.57.126.{i}", port=443, kind="relay", score=100 - i) for i in range(6)]
    jp = [Entry(ip=f"103.27.187.{i}", port=443, kind="relay", score=50 - i) for i in range(6)]
    rtop = pick_top(ntt + jp, 4)
    check(sum(1 for e in rtop if e.net24 == "207.57.126") == MAX_PER_RELAY_24, "relay 同 /24 应受限")
    check(len(rtop) == 4, "relay 应换 /24 补足条数")

    # 同一 IP 的多端口上限在补足阶段不放宽
    dup = [Entry(ip="1.2.3.4", port=p, kind="relay", score=100 - i)
           for i, p in enumerate((443, 8443, 2053, 2087))]
    check(sum(1 for e in pick_top(dup, 4) if e.ip == "1.2.3.4") == MAX_PER_RELAY_IP, "同 IP 端口数受限")

    # ASN 多样性：同一上游横跨多个 /24 时也要限流（/24 上限管不到这种情况）
    check(Entry(ip="1.1.1.1", asn="AS2914 NTT America, Inc.").asn_key == "AS2914", "asn_key 取号")
    check(Entry(ip="1.1.1.1").asn_key == "", "asn_key 为空")

    # 上限随 --top 缩放（回归：绝对值让 --top 30 时单 ASN 占到 20%）
    cap30 = cap_for_top(MAX_PER_ASN_RATIO, MAX_PER_ASN_MIN, 30)
    cap50 = cap_for_top(MAX_PER_ASN_RATIO, MAX_PER_ASN_MIN, 50)
    check(cap30 < cap50, f"ASN 上限应随 top_n 增长（{cap30} vs {cap50}）")
    check(cap30 / 30 <= MAX_PER_ASN_RATIO + 0.05, "小榜单的单 ASN 占比不应失控")
    check(cap50 / 50 <= MAX_PER_ASN_RATIO + 0.02, "大榜单的单 ASN 占比不应超比例太多")
    check(cap_for_top(MAX_PER_ASN_RATIO, MAX_PER_ASN_MIN, 3) == MAX_PER_ASN_MIN, "极小榜单走最小条数地板")

    ntt_asn = [Entry(ip=f"207.57.{i}.1", port=443, kind="relay", score=100 - i,
                     asn="AS2914 NTT America, Inc.") for i in range(cap50 + 6)]
    other_asn = [Entry(ip=f"103.{i + 1}.9.1", port=443, kind="relay", score=10 - i,
                       asn=f"AS{10000 + i} Other{i}") for i in range(60)]
    at = pick_top(ntt_asn + other_asn, 50)
    check(sum(1 for e in at if e.asn_key == "AS2914") == cap50, f"同 ASN 应受限于 {cap50} 条")
    check(len(at) == 50, "其他 ASN 应补足条数")

    # 同一批候选、不同 top_n：上限必须跟着收紧
    at30 = pick_top(ntt_asn + other_asn, 30)
    check(sum(1 for e in at30 if e.asn_key == "AS2914") == cap30, f"top_n=30 时应收紧到 {cap30} 条")
    check(len(at30) == 30, "top_n=30 时仍应凑满")

    # 地区保底：RTT 明显更低的地区不得吃满榜单（回归：HK 曾占 47%、SG 只剩 1 条）
    regions5 = ("HK", "JP", "KR", "SG", "TW")
    spread = [Entry(ip=f"{r_i + 1}.{i}.0.1", port=443, kind="relay", region=r,
                    score=100 - r_i * 20 - i, asn=f"AS{9000 + r_i} ISP{r}")
              for r_i, r in enumerate(regions5) for i in range(20)]
    bt = pick_top(spread, 30)
    got = Counter(e.region for e in bt)
    would_floor = math.ceil(30 / len(regions5))
    check(len(bt) == 30, "地区均衡后仍应凑满 30 条")
    check(all(got[r] == would_floor for r in regions5),
          f"每个地区应各得 {would_floor} 条，实际 {dict(got)}")

    # 候选不足的地区按实际可用数入选，空缺由其他地区补足
    scarce = [Entry(ip=f"7.{i}.0.1", port=443, kind="relay", region="TW", score=50,
                    asn=f"AS{7000 + i} T{i}") for i in range(2)]
    plenty = [Entry(ip=f"8.{i}.0.1", port=443, kind="relay", region="HK", score=90 - i,
                    asn=f"AS{8000 + i} H{i}") for i in range(40)]
    st = pick_top(scarce + plenty, 10)
    check(Counter(e.region for e in st)["TW"] == 2, "候选不足的地区按其可用数入选")
    check(len(st) == 10 and Counter(e.region for e in st)["HK"] == 8, "空缺应由其他地区补足")

    # 纯 cf 榜单没有地区概念，地区保底必须自动失效
    check(region_floor([Entry(ip="104.16.0.1", kind="cf")], 30) == 0, "纯 cf 不应有地区保底")

    # cf 不得在地区保底阶段抢名额（回归：实测 CF 抢走 7 个本该给 KR/SG/TW 的名额）
    relay_pool = [Entry(ip=f"{r_i + 1}.{i}.0.1", port=443, kind="relay", region=r,
                        score=60 - r_i * 10 - i, asn=f"AS{9000 + r_i} ISP{r}")
                  for r_i, r in enumerate(regions5) for i in range(20)]
    cf_pool = [Entry(ip=f"104.{16 + i}.{i}.1", kind="cf", score=99 - i) for i in range(20)]
    mixed_top = pick_top(relay_pool + cf_pool, 30)
    check(Counter(e.kind for e in mixed_top)["cf"] == 0,
          "relay 充足时 cf 不应挤进地区保底名额")
    check(Counter(e.region for e in mixed_top)["TW"] == would_floor, "小地区的名额不应被 cf 抢走")

    # relay 凑不满时 cf 仍然可以补位
    thin = [Entry(ip=f"5.{i}.0.1", port=443, kind="relay", region="HK", score=60 - i,
                  asn=f"AS{5000 + i} H{i}") for i in range(3)]
    thin_cf = [Entry(ip=f"162.159.{i}.1", kind="cf", score=99 - i) for i in range(10)]
    check(len(pick_top(thin + thin_cf, 10)) == 10, "relay 不足时应由 cf 补满")

    # ASN 未知（反查失败）时不限流，避免 ip-api 挂掉把 relay 全灭
    unknown = [Entry(ip=f"103.{(i + 1) * 2}.7.1", port=443, kind="relay", score=100 - i)
               for i in range(10)]
    check(len(pick_top(unknown, 10)) == 10, "ASN 未知时不应限流")

    # cf 不受 ASN 上限约束（anycast 都是 Cloudflare 的 AS13335，限了会全灭）
    cf_one_asn = [Entry(ip=f"104.{16 + i}.1.1", kind="cf", score=100 - i,
                        asn="AS13335 Cloudflare, Inc.") for i in range(10)]
    check(len(pick_top(cf_one_asn, 10)) == 10, "cf 不应受 ASN 上限约束")

    # 产物回落保护
    check(count_previous("__no_such_output__.txt") == 0, "缺少产物应视为首次运行")
    check(output_regression(0, [], 30) is None, "首次运行不应拦截")
    check(output_regression(50, list(range(10)), 50) is not None, "产出腰斩应被拦截")
    check(output_regression(50, list(range(30)), 50) is None, "回落到一半以上应放行")
    check(output_regression(50, list(range(10)), 10) is None, "主动调小 --top 不应误判")
    check(not output_regression(50, [], 0), "--top 0 不应拦截")

    if fails:
        print("❌ 自检失败:")
        for f in fails:
            print("   -", f)
        return 1
    print("✅ 自检全部通过")
    return 0


# ============================================================
# 主流程
# ============================================================

def main(argv: Iterable[str] = None) -> int:
    ap = argparse.ArgumentParser(description="优选IP 聚合与优选流水线")
    ap.add_argument("--self-test", action="store_true", help="离线自检，不联网")
    ap.add_argument("--no-measure", action="store_true", help="跳过实测（调试采集/分类）")
    ap.add_argument("--top", type=int, default=TOP_N, help=f"产出条数，默认 {TOP_N}")
    ap.add_argument(
        "--kinds", default=None,
        help='参与排名的类型，逗号分隔：cf,relay,proxy。默认 "cf,relay"；只跑 CF 用 --kinds cf',
    )
    ap.add_argument("--out", default=None, help=f"输出文件名，默认 {OUTPUT_TXT}")
    ap.add_argument(
        "--force", action="store_true",
        help=f"忽略产物回落保护（本次条数不足上次的 {MIN_OUTPUT_RATIO:.0%} 时仍覆盖）",
    )
    args = ap.parse_args(list(argv) if argv is not None else None)

    if args.self_test:
        return self_test()

    global ALLOWED_KINDS
    if args.kinds:
        want = tuple(k.strip() for k in args.kinds.split(",") if k.strip())
        unknown = [k for k in want if k not in ("cf", "relay", "proxy")]
        if unknown:
            print(f"❌ 未知类型: {unknown}")
            return 2
        ALLOWED_KINDS = want

    txt_path = args.out or OUTPUT_TXT
    if args.out:
        json_path = txt_path[:-4] + ".json" if txt_path.endswith(".txt") else txt_path + ".json"
    else:
        json_path = OUTPUT_JSON

    started = time.time()
    print("=" * 78)
    print("优选IP 流水线")
    print("=" * 78)

    print("\n【网段】加载 Cloudflare CIDR")
    cf_nets = load_cf_cidrs()
    print(f"  共 {len(cf_nets)} 个网段")

    pool, ok_sources, failed_sources = collect_all(cf_nets)
    print(f"\n  数据源健康: 成功 {len(ok_sources)}/{len(SOURCES)}")
    if failed_sources:
        print(f"  ⚠️ 失败源: {', '.join(failed_sources)}")
    if not any(s["kind"] == "region_feed" and s["name"] in ok_sources for s in SOURCES):
        print("  ⚠️ 无任何 region_feed 源可用：relay 类候选将完全缺失（最多只剩 cf）")
    print(f"  合并去重后候选总数: {len(pool)}")

    kc = Counter(e.kind for e in pool.values())
    print(f"  类型分布: {dict(kc)}")

    cands = select_candidates(pool)
    print(f"  进入实测的候选: {len(cands)}")

    if not cands:
        print("❌ 无候选，终止")
        return 1

    if args.no_measure:
        print("\n（--no-measure：跳过实测与评分）")
        return 0

    measure(cands)
    print_measurement_stats(cands)
    ranked = score_entries(cands)
    if not ranked:
        print(f"❌ 无可连通候选，保留原有 {txt_path} 不覆盖")
        return 1

    # ASN 去重需要归属信息，而归属通常只在反查阶段才有：先对评分靠前的候选取一次。
    # 纯 cf 榜单不需要（anycast 全是同一 ASN，上限对 cf 不生效），跳过这批请求。
    prefetched: set = set()
    if any(e.kind == "relay" for e in ranked[:ASN_PRECHECK_LIMIT]):
        prefetched = prefetch_asn(ranked, ASN_PRECHECK_LIMIT)

    top = pick_top(ranked, args.top)

    # 产物回落保护：源大量失效时宁可保留旧榜，也不要把几十条的好榜换成几条
    reason = output_regression(count_previous(txt_path), top, args.top)
    if reason and not args.force:
        print(f"\n❌ 产物回落保护生效：{reason}")
        print(f"   已保留原有 {txt_path} 不覆盖。请先排查上文的数据源/连通性告警；")
        print("   若确认减少是预期结果（如上游大面积下线），加 --force 强制覆盖。")
        return 1
    if reason:
        print(f"\n⚠️ --force：已忽略产物回落保护（{reason}）")

    enrich(top, keep_extra=prefetched)
    write_outputs(top, txt_path, json_path)
    print_summary(top)

    print(f"\n✅ 已写入 {txt_path} 与 {json_path}")
    print(f"⏱  耗时 {time.time() - started:.1f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
