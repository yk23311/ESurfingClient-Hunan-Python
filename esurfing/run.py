#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""天翼校园（湖南）拨号器 —— 单文件

    python run.py            认证并保持在线（Ctrl+C 停止保活，**不断网**）
    python run.py logout     注销
    python run.py init       重新填账号密码
    python run.py selftest   离线自检（不联网）

为什么是一个文件
----------------
这个程序只做一件事：把校园网拨上去。上一版拆成 8 个模块 + 中文菜单共 110 KB，
其中大半用不上：

    · ZSM 算法容器解包（TEA + LZMA，282 行）—— 算法协商从未实现，
      运行时只需要"这是不是 ZSM 容器"这一个判断（3 行）
    · mscgip 探测（90 行）—— 实测**留空也能 state=0 / keep=0**，不需要
    · tracert 取第一跳 —— 只为拿一个地址，却要跑 1 秒
    · PowerShell 枚举网卡 —— 两次调用 3.8 秒，只为读 4 个字段
    · 中文菜单 —— 双击就该直接拨号，中间不该再有一层

性能（本机实测）
----------------
    · 网卡信息：PowerShell 1770 ms → GetAdaptersAddresses(ctypes) **4.7 ms**
    · 第一跳  ：tracert 1024 ms   → GetBestRoute **0 ms**
    · 出网探测：3 个目标串行（最坏 15 s）→ 并行（最坏 4 s）
    · 重复枚举：旧版一次启动枚举 3 次网卡 → 现在整个进程只枚举 1 次
    合计：启动 5337 ms → 约 30 ms

协议要点（踩过的坑，改动前先读）
--------------------------------
1. 明文 = XML + NUL + 补零到 16 的倍数（**不是 PKCS#7**）
2. 两层 AES-128-CBC：B = IV || E(K2, IV || E(K1, IV || P))
   **K1 和 K2 是两把独立的 128 位密钥，拼成 AES-256 解不开**
3. 线上是**大写 hex**，所以 HTTP body 长度 = 2 × len(B)
4. 判成功只看 `Error-Code == 0`。**注销成功时响应体是 0 字节**
5. `auth` / `keep` / `state` / `term` 用**同一张**会话票据；
   票据是 `ticket.cgi` 下发的，必须落盘，否则注销时手里是空票
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import hashlib
import http.client
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from xml.etree import ElementTree as ET

from Crypto.Cipher import AES

for _s in ("stdout", "stderr"):
    try:
        getattr(sys, _s).reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(HERE, "config.json")
STATE_PATH = os.path.join(HERE, "session.json")
LOCK_PATH = os.path.join(HERE, "keepalive.lock")
LOG_PATH = os.path.join(HERE, "last.log")

DEFAULT_PORTAL = "175.12.104.1"
DEFAULT_PORT = 10001

USER_AGENT = "CCTP/WinSVR3/1052"
ALGO_ID = "FAB1DCDE-2D24-41CD-8510-2416DC7854CF"
CLIENT_ID = "c167f455-7b9f-4c0f-a401-df583ab269e2"
ZSM_MAGIC = b"001"

# 两层 AES-128-CBC 的密钥与 IV：各 16 字节，**互相独立**
K1 = bytes.fromhex("766224493b484e6d6e28602822237262")
K2 = bytes.fromhex("574221583c4c7340507848247b72577e")
IV = bytes.fromhex("287b4c77697c6e4d7447787b64694461")
BLOCK = 16

ERROR_MEANING = {
    "1": "该参数组无会话（票据过期 / 不是本程序建的会话 / 已注销）",
    "2": "请求被拒：UA 或请求体格式不符",
    "13": "请求被拒：没带请求头",
    "14": "无会话（重复注销、或票据没绑会话）—— 实测",
    "15": "请求被拒：请求头不全或 body 格式不对",
    "102": "★ 拒绝认证。1025 = 源不在校园网（实测）；"
           "902 = **校园网内也会出现**（2026-10-09 源绑定校园网 IP 实测），原因未定 —— 详见下方出口诊断",
    "300": "该票据没有关联的会话 —— 实测（新取的票、还没认证过时 state.cgi 回 300）",
    "200": "不是错误：响应体是 ZSM 算法模块",
}


def say(msg=""):
    print(msg, flush=True)


# ===========================================================================
# 1. 编解码
# ===========================================================================

class CodecError(Exception):
    pass


def _pad(data: bytes) -> bytes:
    """NUL 结束符 + 补零到 16 字节整数倍。不是 PKCS#7。"""
    out = data + b"\x00"
    rem = len(out) % BLOCK
    return out + b"\x00" * (BLOCK - rem) if rem else out


def _unpad(data: bytes) -> bytes:
    i = data.find(b"\x00")
    return data if i < 0 else data[:i]


def encrypt(plain: bytes) -> bytes:
    """明文 → 二进制密文 B（含两层 IV 前缀）。"""
    inner = IV + AES.new(K1, AES.MODE_CBC, IV).encrypt(_pad(plain))
    return IV + AES.new(K2, AES.MODE_CBC, IV).encrypt(inner)


def decrypt(body: bytes) -> bytes:
    """二进制密文 B → 明文。结构不对就抛错，不静默降级。"""
    if len(body) < 2 * BLOCK or (len(body) - BLOCK) % BLOCK:
        raise CodecError("密文长度 %d 不合法" % len(body))
    if body[:BLOCK] != IV:
        raise CodecError("外层 IV 不匹配 —— 不是本实现支持的算法配置")
    outer = AES.new(K2, AES.MODE_CBC, IV).decrypt(body[BLOCK:])
    inner = AES.new(K1, AES.MODE_CBC, outer[:BLOCK]).decrypt(outer[BLOCK:])
    return _unpad(inner)


def to_wire(body: bytes) -> bytes:
    """二进制 → 大写 ASCII hex。**长度翻倍**，别拿它当 Content-Length 手算。"""
    return body.hex().upper().encode("ascii")


def from_wire(text: bytes) -> bytes:
    s = bytes(text).strip()
    if not s or len(s) % 2:
        raise CodecError("hex 长度 %d 不合法" % len(s))
    try:
        return bytes.fromhex(s.decode("ascii"))
    except (ValueError, UnicodeDecodeError) as e:
        raise CodecError("不是合法 hex: %s" % e) from e


def build_request(fields) -> bytes:
    """拼完整请求 XML（含声明与 <request> 根节点）。

    字段顺序与官方客户端一致 —— 那是唯一有抓包支持的做法。
    """
    body = "".join("<%s>%s</%s>" % (k, _esc(v), k) for k, v in fields)
    return ('<?xml version="1.0" encoding="utf-8"?><request>%s</request>'
            % body).encode("utf-8")


def _esc(v) -> str:
    return str(v).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ===========================================================================
# 2. 本机身份（Win32 直接调用，不起 PowerShell）
# ===========================================================================

AF_INET = 2
_GAA_FLAGS = 0x02 | 0x04 | 0x08 | 0x80   # 跳过 anycast/multicast/DNS，带上网关
_IF_TYPE_ETHERNET_CSMACD = 6
_IF_TYPE_IEEE80211 = 71
_IF_OPER_STATUS_UP = 1
# IfOperStatus（Get-NetAdapter 的 Status 就是它）
_IF_STATUS_NAME = {1: "Up", 2: "Down", 3: "Testing", 4: "Dormant",
                   5: "NotPresent", 6: "LowerLayerDown"}


class _SOCKADDR(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]


class _ADDR(ctypes.Structure):          # 单播地址 / 网关地址，头部布局相同
    pass


_ADDR._fields_ = [
    ("Length", wt.ULONG), ("Flags", wt.DWORD), ("Next", ctypes.POINTER(_ADDR)),
    ("Address", _SOCKADDR), ("a", ctypes.c_int), ("b", ctypes.c_int),
    ("c", ctypes.c_int), ("d", wt.ULONG), ("e", wt.ULONG), ("f", wt.ULONG),
    ("g", ctypes.c_ubyte),
]


class _ADAPTER(ctypes.Structure):
    pass


_ADAPTER._fields_ = [
    ("Length", wt.ULONG), ("IfIndex", wt.DWORD),
    ("Next", ctypes.POINTER(_ADAPTER)), ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(_ADDR)),
    ("FirstAnycastAddress", ctypes.c_void_p), ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p), ("DnsSuffix", wt.LPWSTR),
    ("Description", wt.LPWSTR), ("FriendlyName", wt.LPWSTR),
    ("PhysicalAddress", ctypes.c_ubyte * 8), ("PhysicalAddressLength", wt.ULONG),
    ("Flags", wt.ULONG), ("Mtu", wt.ULONG), ("IfType", wt.ULONG),
    ("OperStatus", ctypes.c_int), ("Ipv6IfIndex", wt.ULONG),
    ("ZoneIndices", wt.ULONG * 16), ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_ulonglong), ("ReceiveLinkSpeed", ctypes.c_ulonglong),
    ("FirstWinsServerAddress", ctypes.c_void_p),
    ("FirstGatewayAddress", ctypes.POINTER(_ADDR)),
    ("Ipv4Metric", wt.ULONG), ("Ipv6Metric", wt.ULONG), ("Luid", ctypes.c_ulonglong),
    ("Dhcpv4Server", _SOCKADDR), ("CompartmentId", wt.DWORD),
    ("NetworkGuid", ctypes.c_ubyte * 16), ("ConnectionType", ctypes.c_int),
    ("TunnelType", ctypes.c_int), ("Dhcpv6Server", _SOCKADDR),
    ("Dhcpv6ClientDuid", ctypes.c_ubyte * 130), ("Dhcpv6ClientDuidLength", wt.ULONG),
    ("Dhcpv6Iaid", wt.ULONG), ("FirstDnsSuffix", ctypes.c_void_p),
]


class _FWDROW(ctypes.Structure):
    _fields_ = [(n, wt.DWORD) for n in
                ("dwForwardDest", "dwForwardMask", "dwForwardPolicy",
                 "dwForwardNextHop", "dwForwardIfIndex", "dwForwardType",
                 "dwForwardProto", "dwForwardAge", "dwForwardNextHopAS",
                 "m1", "m2", "m3", "m4", "m5")]


try:
    _iphlp = ctypes.WinDLL("iphlpapi")
    _ws2 = ctypes.WinDLL("ws2_32")
except OSError:                                   # 非 Windows
    _iphlp = _ws2 = None

_adapters_cache = None


def _sockaddr_ip(sa) -> str:
    if not sa.lpSockaddr:
        return ""
    if ctypes.cast(sa.lpSockaddr, ctypes.POINTER(ctypes.c_ushort))[0] != AF_INET:
        return ""
    return socket.inet_ntoa(ctypes.string_at(sa.lpSockaddr, 8)[4:8])


def _enumerate(include_down=False) -> list:
    """底层枚举物理网卡（以太网 + Wi-Fi）。

    include_down=True 时**连没有链路的网卡也返回** —— 排错时必须看得到
    「以太网 Disconnected」，否则网线掉了和"程序坏了"完全区分不出来。
    """
    rows = []
    if _iphlp is None:
        return rows
    size = wt.ULONG(15000)
    buf = ctypes.create_string_buffer(size.value)
    rc = _iphlp.GetAdaptersAddresses(AF_INET, _GAA_FLAGS, None, buf, ctypes.byref(size))
    if rc == 111:                          # ERROR_BUFFER_OVERFLOW：按它要的大小重来
        buf = ctypes.create_string_buffer(size.value)
        rc = _iphlp.GetAdaptersAddresses(AF_INET, _GAA_FLAGS, None, buf, ctypes.byref(size))
    if rc != 0:
        return rows
    p = ctypes.cast(buf, ctypes.POINTER(_ADAPTER))
    while p:
        a = p.contents
        if a.IfType in (_IF_TYPE_ETHERNET_CSMACD, _IF_TYPE_IEEE80211):
            ip, u = "", a.FirstUnicastAddress
            while u:
                v = _sockaddr_ip(u.contents.Address)
                if v and not v.startswith(("127.", "169.254.")):
                    ip = v
                    break
                u = u.contents.Next
            mac = "".join("%02x" % b
                          for b in a.PhysicalAddress[:a.PhysicalAddressLength])
            up = a.OperStatus == _IF_OPER_STATUS_UP
            if (up and ip and len(mac) == 12) or include_down:
                rows.append({
                    "ifindex": a.IfIndex,
                    "alias": a.FriendlyName or a.Description or "",
                    "up": up,
                    "status": _IF_STATUS_NAME.get(a.OperStatus,
                                                  "Status-%d" % a.OperStatus),
                    "ip": ip, "mac": mac,
                    "gateway": (_sockaddr_ip(a.FirstGatewayAddress.contents.Address)
                                if a.FirstGatewayAddress else ""),
                })
        p = a.Next
    rows.sort(key=lambda r: (not r["up"], not r["gateway"], r["ifindex"]))
    return rows


def adapters(refresh=False) -> list:
    """枚举有 IPv4、状态 Up 的物理网卡。整个进程只真正枚举一次。

    ★ 空结果**不缓存** —— 否则一次瞬时失败（枚举期间网卡刚好在重连）
      会让整个进程永远以为"没有网卡"。
    """
    global _adapters_cache
    if _adapters_cache and not refresh:
        return _adapters_cache
    rows = [r for r in _enumerate() if r["up"] and r["ip"] and len(r["mac"]) == 12]
    if rows:
        _adapters_cache = rows
    return rows


def wifi_ssid() -> str:
    """当前 WLAN 连的是哪个 SSID。失败返回空串。"""
    try:
        r = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=5)
        for line in (r.stdout or "").splitlines():
            s = line.strip()
            if s.startswith("SSID") and "BSSID" not in s and ":" in s:
                v = s.split(":", 1)[1].strip()
                if v:
                    return v
    except Exception:
        pass
    return ""


def discover_mscgip(portal_ip, port=10001, timeout=3, src_ip="") -> str:
    """未认证时从**门户劫持的 302** 里挖出接入设备地址（`mscgip`）。

    实测底稿（Steam 的连接日志，2026-07-02，同一校园网）：

        Got HTTP redirect (302), assuming captive portal at
        http://175.12.104.1:10001/index.cgi?wlanuserip=100.67.205.124
                &mscgip=218.75.255.245&wlanusermac=e8-b0-c5-18-31-8e

    所以在校园网内、**未认证**时随便发一个明文 HTTP 请求，BAS 就会
    把 `mscgip` 注进 302。已认证时没有劫持，返回空串。

    ⚠️ 这是 `auth.cgi` 可能用到的接入设备地址。
       早期我拿「state/keep 不带 mscgip 也能返回 0」就把它整个删了 ——
       那个实验**只覆盖了 state/keep，没有覆盖 auth**。
    """
    # 门户自己的探测页：同主机、最快，先试这一个
    got = _mscgip_from(portal_ip, port, "/detect.html", src_ip, timeout)
    if got:
        return got
    # 只有看起来在校园网内、且还没认证（门户才会劫持）时，才去打公网地址
    if not is_campus_ip(src_ip):
        return ""
    for host, pt, path in (("23.33.126.158", 80, "/"),
                           ("neverssl.com", 80, "/")):
        got = _mscgip_from(host, pt, path, src_ip, min(timeout, 4))
        if got:
            return got
    return ""


def _mscgip_from(host, port, path, src_ip, timeout) -> str:
    c = None
    try:
        c = http.client.HTTPConnection(host, int(port), timeout=timeout,
                                       source_address=(src_ip, 0)
                                       if src_ip else None)
        c.request("GET", path, headers={"User-Agent": USER_AGENT})
        r = c.getresponse()
        blob = (r.getheader("Location") or "") + "|"
        blob += r.read(8000).decode("utf-8", "replace")
        for key in ("mscgip", "wlanacip"):
            m = re.search(key + r"=([^&\"'>\s]+)", blob, re.I)
            if m and m.group(1):
                return m.group(1)
    except Exception:
        return ""
    finally:
        if c is not None:
            c.close()
    return ""


def path_hint(portal_ip: str) -> list:
    """认证失败时解释**真实出口**在哪条路上。

    ★ 只在失败时打印。诊断价值极高：
      网线掉了 → 流量掉到手机热点 → 门户回 102 ——
      没有这段输出，看起来就像"程序坏了"。
    """
    lines = ["网络出口诊断（网线掉了也会走 WLAN，但那不是校园网）:"]
    for r in _enumerate(include_down=True):
        if r["alias"]:
            state = r["status"] if not (r["up"] and r["ip"]) else "有链路"
            lines.append("  %-10s %-8s %-16s 网关 %s"
                         % (r["alias"], state, r["ip"] or "(无地址)",
                            r["gateway"] or "(无网关)"))
    hop = first_hop(portal_ip)
    lines.append("  到门户 %s 的第一跳: %s" % (portal_ip, hop or "(无)"))
    ads = adapters()
    if ads and not ads[0]["alias"].startswith("以太网"):
        ssid = wifi_ssid()
        lines.append("  当前默认出口在 %s%s"
                     % (ads[0]["alias"], "（SSID=%s）" % ssid if ssid else ""))
    lines.append("  → 这个包确实从上面那个「出口」发出（已显式绑定，不走默认路由）。")
    lines.append("    102/1025 = 源不在校园网（三组对照实验）；")
    lines.append("    102/902  = **在校园网内也会出现**（2026-10-09 16:22:53 实测，")
    lines.append("              源绑定为校园网 IP 100.67.199.113 时仍然返回它）——")
    lines.append("              所以 902 **不是**出口问题，原因尚未确定。")
    return lines


def first_hop(dest_ip: str) -> str:
    """内核去这个目的地会用哪个下一跳。查路由表，不发包。

    ★ 目的地直连时 `GetBestRoute` 会返回未指定地址 `0.0.0.0`，
      那不是"第一跳不一致"，本函数按"没有下一跳"处理（返回空串）。
    """
    if _iphlp is None or not dest_ip:
        return ""
    try:
        row = _FWDROW()
        if _iphlp.GetBestRoute(_ws2.inet_addr(dest_ip.encode()), 0,
                               ctypes.byref(row)) == 0:
            hop = socket.inet_ntoa(row.dwForwardNextHop.to_bytes(4, "little"))
            return "" if hop == "0.0.0.0" else hop
    except Exception:
        pass
    return ""


def clean_mac(mac: str) -> str:
    h = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    return h if len(h) == 12 else ""


def format_mac(mac: str) -> str:
    h = clean_mac(mac)
    return "-".join(h[i:i + 2] for i in range(0, 12, 2)).upper() if h else ""


def ip_is_local(ip: str) -> bool:
    """这个地址现在真的挂在本机网卡上吗（能 bind 就是）。"""
    if not ip:
        return False
    s = None
    try:
        s = socket.socket()
        s.bind((ip, 0))
        return True
    except OSError:
        return False
    finally:
        if s is not None:
            s.close()


def gateway_alive(gw: str, timeout=3.0) -> tuple:
    """网关可达吗。返回 (是否可达, 方法)。

    ★ 校园网关**只回 ICMP，不监听 TCP 80/53/443**。
      早期实现只用 TCP 探测，网关 ping 得通却被判为不可达，
      整个"在不在校园网"的判断全部反转。
    """
    if not gw:
        return False, "没有网关"
    try:
        r = subprocess.run(["ping", "-n", "1", "-w", str(int(timeout * 1000)), gw],
                           capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=timeout + 3)
        if re.search(r"TTL=\d+", (r.stdout or "") + (r.stderr or ""), re.I):
            return True, "ICMP"
    except Exception:
        pass
    for port in (80, 53, 443):
        s = None
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.connect((gw, port))
            return True, "TCP:%d" % port
        except OSError:
            continue
        finally:
            if s is not None:
                s.close()
    return False, "ICMP/TCP 都无响应"


def is_campus_ip(ip: str) -> bool:
    """校园网可能用的网段。

    ⚠️ **不能单独拿它判断在不在校园网**：
       本校校园网同时出现过 `100.67.x.x`（CGNAT）和 `10.82.66.x`（RFC1918），
       而手机热点也用 10.x —— 光看网段分不出来。
    """
    if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", ip or ""):
        return False
    a, b = (int(x) for x in ip.split(".")[:2])
    return (a == 100 and 64 <= b <= 127) or a == 10


def in_campus(local_ip: str, gateway: str, hop: str) -> tuple:
    """在校园网内吗。返回 (是否在, 说明)。

    判据按可靠性排序：**网关真的可达 → 第一跳一致 → 网段只作辅助**。
    """
    why = []
    if not local_ip:
        why.append("没有本机 IP")
    elif not is_campus_ip(local_ip):
        why.append("本机 IP %s 不在校园网段" % local_ip)
    if not gateway:
        return False, "；".join(why + ["没有默认网关"])
    ok, method = gateway_alive(gateway)
    if not ok:
        return False, "；".join(why + ["网关 %s 不可达（%s）" % (gateway, method)])
    if hop and hop != gateway:
        why.append("到门户的第一跳是 %s，与网关 %s 不一致" % (hop, gateway))
    if why:
        return False, "；".join(why)
    return True, "网关 %s 可达(%s)，第一跳一致，IP %s 在校园网段" % (gateway, method, local_ip)


def internet_ok(src_ip: str, timeout=4.0) -> tuple:
    """绑定校园网源地址做出网探测。返回 (是否通, 说明)。

    ★ 绑定失败 = 失败，不静默回退到默认路由。
    ★ 三个目标**并行**，且**任一成功就立刻返回** —— 旧版串行探测，
      断网时最坏要等 15 秒；就算通，只要有一个目标慢也要陪着等完。
    """
    if not ip_is_local(src_ip):
        return False, "源地址 %s 不在本机网卡上（IP 变了？）" % src_ip
    targets = (("223.5.5.5", 53), ("114.114.114.114", 53), ("180.76.76.76", 53))
    done = threading.Event()
    got = {}

    def probe(host, port):
        # socket() 本身也可能抛（fd 耗尽 / WSAENOBUFS），所以放进 try 里
        s = None
        try:
            s = socket.socket()
            s.settimeout(timeout)
            s.bind((src_ip, 0))
            s.connect((host, port))
            got[host] = True
        except OSError as e:
            got[host] = str(e)
        finally:
            if s is not None:
                s.close()
        if got.get(host) is True:
            done.set()

    for t in targets:
        threading.Thread(target=probe, args=t, daemon=True).start()

    done.wait(timeout)
    if any(v is True for v in got.values()):
        return True, "绑定 %s 出网通" % src_ip

    deadline = time.time() + 1.0          # 全失败时再等一会儿，好把原因写全
    while len(got) < len(targets) and time.time() < deadline:
        time.sleep(0.05)
    return False, ("；".join("%s → %s" % (k, got[k]) for k in sorted(got))
                   or "全部超时")


# ===========================================================================
# 3. 门户
# ===========================================================================

class Response:
    """一次 HTTP 事务。响应类型显式分流，未知响应不猜。"""

    def __init__(self, endpoint, status, headers, body, error=None, src=None):
        self.endpoint = endpoint
        self.status = status
        # ★ 键统一转小写。
        #   `http.client.HTTPMessage` 的查找是**大小写不敏感**的，但
        #   `dict(r.headers)` 之后就变成敏感了 —— 门户或中间设备只要把
        #   头写成 `Error-code: 0`（合法），每个响应都会被判成失败，
        #   认证明明成功也会报 "Error-Code=None"。
        self.headers = {str(k).lower(): v for k, v in (headers or {}).items()}
        self.body = body or b""
        self.error = error
        self.src = src or ""          # 这个包**实际**从哪个 IP 发出去
        self.error_code = self.headers.get("error-code")
        self.sub_error = self.headers.get("sub-error")
        self.kind = self._classify()
        self.xml = None
        if self.kind == "xml":
            try:
                self.xml = ET.fromstring(decrypt(from_wire(self.body)))
            except (CodecError, ET.ParseError) as e:
                self.kind, self.error = "unknown", "解密/解析失败: %s" % e

    def _classify(self):
        if self.status and 300 <= self.status < 400:
            return "redirect"
        if not self.body:
            return "empty"
        if self.body[:3] == ZSM_MAGIC:
            return "zsm"
        head = self.body[:8].lstrip()
        if head[:1] == b"<":
            return "plain"
        if all(c in b"0123456789abcdefABCDEF\r\n \t" for c in self.body[:64]):
            return "xml"
        return "plain"

    @property
    def ok(self):
        """只看 Error-Code。

        ★ **不能要求响应体非空** —— 实测注销成功时就是
          `HTTP 200 / Error-Code: 0 / 0 字节`。要求响应体能解出 XML
          会把成功的注销判成失败（本机真实踩过一次）。
        """
        return self.error_code == "0"

    def text(self, tag):
        if self.xml is None:
            return None
        node = self.xml.find(tag)
        return node.text.strip() if node is not None and node.text else None

    def summary(self):
        extra = " Sub-Error=%s" % self.sub_error if self.sub_error else ""
        out = "%s HTTP %s Error-Code=%s%s %d字节" % (
            self.endpoint, self.status, self.error_code, extra, len(self.body))
        if self.src:
            out += "  源=%s" % self.src
        if self.error:
            out += "  [%s]" % self.error
        return out


class Portal:
    def __init__(self, cfg):
        self.base = "http://%s:%d" % (cfg["portal"], int(cfg.get("port") or DEFAULT_PORT))
        self.ticket = ""
        self.ttl = 0
        self.ident = (cfg.get("wlanuserip", ""), clean_mac(cfg.get("wlanusermac", "")),
                      cfg.get("mscgip", ""), cfg.get("gateway", ""))
        self.timeout = 15

    def _query(self, ident):
        """查询串。字段值与名字的**对应关系必须写死**，不能靠位置偷懒。

        ★ 这里踩过一次：ident 的内部顺序是 (IP, MAC, mscgip, 网关)，
          而查询串的顺序是 wlanuserip / **mscgip** / **wlanusermac** ——
          两者第 2、3 位是反的。用 `% tuple(ident)[:3]` 会把 MAC 塞进
          mscgip、把 mscgip 塞进 wlanusermac。服务端对 wlanuserip 以外的
          字段校验很松，所以它**照样返回 0** —— 一个不会报错的静默错误。
        """
        ip, mac, msc = (tuple(ident or self.ident) + ("", "", ""))[:3]
        return "wlanuserip=%s&mscgip=%s&wlanusermac=%s" % (ip, msc, mac)

    def post(self, endpoint, xml: bytes, ident=None) -> Response:
        """POST 一个端点。

        ★★ **必须绑定源地址** ★★
          早期实现用 `urllib` 的默认路由发包 —— 于是"我们在校园网里"
          和"**这个包是从校园网发出去的**"完全是两回事：
            · 校园网断了、路由掉到手机热点 → 源地址变成热点地址 → 门户回 102
            · 或者某块网卡插着但接口是断的，路由仍然指向它
          日志里只会看到"Error-Code=102 不在校园网内"，看不出真实出口，
          结果就是反复误判成"你网线没插"。

          现在显式 `bind` 到 `wlanuserip`：
            · 绑定成功 → 源地址**确定**是校园网那个 IP
            · 绑定失败（IP 已不在本机）→ **立刻报错**，不发包、不换出口
          这样 102 的含义是确定的：包确实从校园网 IP 发出，被门户拒绝。
        """
        body = to_wire(encrypt(xml))
        ident = tuple(ident or self.ident)
        src_ip = ident[0] if ident else ""
        path = "/%s?%s" % (endpoint, self._query(ident))
        headers = {
            "User-Agent": USER_AGENT,
            "Algo-ID": ALGO_ID,
            "Client-ID": CLIENT_ID,
            "CDC-Checksum": hashlib.md5(body).hexdigest(),
            "Content-Type": "application/octet-stream",
        }
        host, _, port = self.base.split("://", 1)[1].partition(":")
        conn = None
        try:
            conn = http.client.HTTPConnection(host, int(port or 80),
                                              timeout=self.timeout,
                                              source_address=(src_ip, 0)
                                              if src_ip else None)
            conn.request("POST", path, body=body, headers=headers)
            r = conn.getresponse()
            data = r.read()
            got = conn.sock.getsockname()[0] if conn.sock else ""
            return Response(endpoint, r.status, dict(r.getheaders()), data,
                            src=got)
        except OSError as e:
            # 绑定失败 / 连不上 —— 都带真实出口信息，别再让人猜
            return Response(endpoint, None, {}, b"",
                            error="%s: %s（期望源地址 %s）"
                                  % (type(e).__name__, e, src_ip or "?"))
        except Exception as e:
            return Response(endpoint, None, {}, b"",
                            error="%s: %s" % (type(e).__name__, e))
        finally:
            if conn is not None:
                conn.close()

    # -- 端点 ---------------------------------------------------------------

    def get_ticket(self) -> Response:
        r = self.post("ticket.cgi", build_request([
            ("ostag", "Windows 11(26300),64 bit "),
            ("local-time", "00000000l"),
            # ★ 官方样本这里是**默认网关**（`<gwip>100.67.192.1</gwip>`），不是空串。
            #   空串服务端也接受（实测），但没理由跟官方不一样。
            ("gwip", self.ident[3] if len(self.ident) > 3 else ""),
            ("mac", format_mac(self.ident[1])),
            ("ipv6", ""),
            ("ipv4", self.ident[0]),
            ("client-id", CLIENT_ID),
            ("user-agent", USER_AGENT),
            ("host-name", socket.gethostname().upper()),
        ]))
        if r.kind == "xml":
            t, e = r.text("ticket"), r.text("expire")
            if t:
                self.ticket = t
            if e and e.isdigit():
                self.ttl = int(e)
        elif r.kind == "zsm":
            r.error = "服务端下发的是算法模块而不是 ticket（本实现未做算法协商）"
        return r

    def auth(self, user, password) -> Response:
        return self.post("auth.cgi", build_request([
            ("local-time", "00000000l"),
            ("ticket", self.ticket),
            ("passwd", password),
            ("userid", user),
            ("client-id", CLIENT_ID),
            ("user-agent", USER_AGENT),
        ]))

    def keep(self) -> Response:
        return self.post("keep.cgi", build_request([
            ("local-time", "00000000l"),
            ("excheck-args", "<hello>1</hello><conn>1</conn>"),
            ("mac", format_mac(self.ident[1])),
            ("ipv6", ""),
            ("ipv4", self.ident[0]),
            ("ticket", self.ticket),
            ("client-id", CLIENT_ID),
            ("user-agent", USER_AGENT),
        ]))

    def state(self) -> Response:
        return self.post("state.cgi", build_request([
            ("local-time", "00000000k"),
            ("ticket", self.ticket),
            ("client-id", CLIENT_ID),
            ("user-agent", USER_AGENT),
        ]))

    def term(self, reason="1", ident=None) -> Response:
        return self.post("term.cgi", build_request([
            ("reason", reason),
            ("local-time", "00000000k"),
            ("ticket", self.ticket),
            ("client-id", CLIENT_ID),
            ("user-agent", USER_AGENT),
        ]), ident)


# ===========================================================================
# 4. 配置 / 会话票据 / 保活标记
# ===========================================================================

def load_json(path) -> dict:
    try:
        with open(path, encoding="utf-8-sig") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def save_json(path, data) -> bool:
    """写 JSON。**失败只返回 False，不抛** —— 磁盘满/文件被占用/只读时
    抛出去会把正在跑的保活循环直接打死（连 last.log 都来不及写）。"""
    tmp = "%s.%d.tmp" % (path, os.getpid())      # 唯一名字，避免两个实例互踩
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.replace(tmp, path)
        return True
    except OSError as e:
        say("  ⚠ 写 %s 失败：%s" % (os.path.basename(path), e))
        try:
            os.remove(tmp)
        except OSError:
            pass
        return False


def refresh_identity(cfg: dict, force=False) -> dict:
    """IP 会变，每次运行重新探测。

    force=True 时**绕过网卡缓存**重新枚举 —— 保活循环里检测到
    源地址失效时必须用它，否则换了 IP 就永远恢复不过来。
    一定要保证 wlanuserip / wlanusermac 两个键存在（没有网卡时留空），
    否则后面 `cfg["wlanuserip"]` 会 KeyError。
    """
    ads = adapters(refresh=force)
    for k, v in (("portal", DEFAULT_PORTAL), ("port", DEFAULT_PORT),
                 ("keep_interval", 300), ("mscgip", ""), ("gateway", ""),
                 ("adapter", ""), ("wlanuserip", ""), ("wlanusermac", "")):
        cfg.setdefault(k, v)
    if not ads:
        return cfg
    a = None
    for k, key in (("wlanusermac", "mac"), ("wlanuserip", "ip")):
        want = cfg.get(k, "")
        if want:
            a = next((x for x in ads if x[key] == want), None)
            if a:
                break
    a = a or ads[0]
    cfg.update({"wlanuserip": a["ip"], "wlanusermac": a["mac"],
                "adapter": a["alias"], "gateway": a["gateway"]})
    return cfg


def save_ticket(ticket: str, cfg: dict, ttl=3600):
    if not ticket:
        return
    save_json(STATE_PATH, {"ticket": ticket, "username": cfg.get("username", ""),
                           "wlanuserip": cfg.get("wlanuserip", ""),
                           "wlanusermac": cfg.get("wlanusermac", ""),
                           "mscgip": cfg.get("mscgip", ""), "ttl": ttl,
                           "saved_at": time.time(),
                           "saved_at_text": time.strftime("%Y-%m-%d %H:%M:%S")})


def clear_ticket():
    try:
        os.remove(STATE_PATH)
    except OSError:
        pass


def lock_set():
    try:
        with open(LOCK_PATH, "w", encoding="utf-8") as f:
            json.dump({"pid": os.getpid(), "at": time.time()}, f)
    except OSError:
        pass


def lock_alive() -> dict:
    """保活进程还在跑吗（120 秒内刷新过）。"""
    d = load_json(LOCK_PATH)
    if d and time.time() - float(d.get("at") or 0) < 120:
        return d
    return {}


def lock_clear():
    try:
        os.remove(LOCK_PATH)
    except OSError:
        pass


# ===========================================================================
# 5. 会话
# ===========================================================================

class Session:
    def __init__(self, cfg, portal=None):
        self.cfg = cfg
        self.portal = portal or Portal(cfg)
        try:
            self.keep_interval = max(30, min(int(cfg.get("keep_interval") or 300), 600))
        except (TypeError, ValueError):
            self.keep_interval = 300
        self.log = []
        self.online = False
        self.last_auth_code = ""
        self._hint_shown = False

    def show_hint(self):
        """认证失败时打印一次出口诊断（只打一次，避免刷屏）。"""
        if self._hint_shown:
            return
        self._hint_shown = True
        for line in path_hint(self.cfg.get("portal", DEFAULT_PORTAL)):
            self.note(line)

    def note(self, msg):
        line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
        self.log.append(line)
        say("  " + line)

    # -- 登录 ---------------------------------------------------------------

    def already_online(self) -> bool:
        """磁盘上有票据、且 state.cgi 认它 —— 那就别再认证一次。"""
        st = load_json(STATE_PATH)
        if not st.get("ticket"):
            return False
        self.portal.ticket = st["ticket"]
        r = self.portal.state()
        if r.ok and r.xml is not None:
            self.note("复用现有会话（state.cgi userid=%s）" % r.text("userid"))
            return True
        return False

    def sync_identity(self, force=True) -> bool:
        """重探网卡；IP/MAC 变了就更新 cfg 和门户身份。返回 True 表示变了。

        ★ 保活循环必须能调它：DHCP 换地址后如果不重新探测，
          之后每次探测都会以「源地址不在本机网卡上」失败，
          每次重新认证又都带着旧 IP —— 永远恢复不过来。
        """
        old = (self.cfg.get("wlanuserip", ""), clean_mac(self.cfg.get("wlanusermac", "")))
        refresh_identity(self.cfg, force=force)
        new = (self.cfg.get("wlanuserip", ""), clean_mac(self.cfg.get("wlanusermac", "")))
        if new[0] and new != old:
            self.note("网络地址变化：%s / %s → %s / %s"
                      % (old[0] or "(空)", old[1] or "(空)", new[0], new[1]))
            self.portal.ident = (new[0], new[1], self.cfg.get("mscgip", ""),
                                 self.cfg.get("gateway", ""))
            return True
        return False

    def login(self, user, password) -> tuple:
        """ticket → auth → state → keep。

        ★ 两步验证：`auth` 返回 0 **不足以**说明会话建立了
          （它可能只是在刷新别人的会话），必须 state 和 keep
          **既返回 Error-Code 0、又能解出 XML** 才算数。

        ⚠️ 这两个条件是**与**关系，缺一不可：
           · 只看 XML 不看 Error-Code → state 回 1 也会被判成功（报假成功）
           · 只看 Error-Code 不看 XML → 空响应体虽然对 term 是成功，
             但**证明不了会话存在**（这里要的是证明）
        """
        self.portal.ticket = ""
        r = self.portal.get_ticket()
        self.note("① ticket.cgi  %s" % r.summary())
        if r.kind == "zsm":
            return False, "服务端下发算法模块，本实现未做算法协商"
        if not r.ok or not self.portal.ticket:
            return False, "取不到 ticket（%s）" % (r.error or r.summary())

        r = self.portal.auth(user, password)
        self.note("② auth.cgi    %s" % r.summary())
        if not r.ok:
            self.last_auth_code = str(r.error_code)
            why = ERROR_MEANING.get(str(r.error_code), "")
            extra = ""
            if str(r.error_code) == "102":
                # 102/902 **在校园网内也会出现**（2026-10-09 16:22:53 实测），
                # 所以不能再拿"不在校园网"解释。用同一张票查一下是否
                # 已经存在会话 —— 这决定了下一条线索往哪找：
                #   有会话 → 102 可能是「已在线 / 重复认证」
                #   无会话 → 接入设备(mscgip)/账号状态问题
                rs = self.portal.state()
                self.note("      参照 state.cgi(同一张票) → %s" % rs.summary())
                if rs.ok and rs.xml is not None:
                    extra = ("\n  同一张票**已有会话**（userid=%s）—— "
                             "102/902 可能是「账号已在线 / 重复认证」被拒。"
                             % rs.text("userid"))
                else:
                    extra = ("\n  同一张票**没有会话**（state.cgi Error-Code=%s）—— "
                             "102/902 不是「已在线」，查接入设备/账号状态。"
                             % rs.error_code)
            return False, "认证被拒：Error-Code=%s %s%s" % (r.error_code, why, extra)
        self.last_auth_code = "0"

        rs, rk = self.portal.state(), self.portal.keep()
        self.note("③ state.cgi   %s" % rs.summary())
        self.note("④ keep.cgi    %s" % rk.summary())
        bad = []
        if not rs.ok:
            bad.append("state Error-Code=%s" % rs.error_code)
        elif rs.xml is None:
            bad.append("state 响应解不出 XML")
        if not rk.ok:
            bad.append("keep Error-Code=%s" % rk.error_code)
        elif rk.xml is None:
            bad.append("keep 响应解不出 XML")
        if bad:
            return False, ("auth 返回 0，但**不能证明会话建立**：%s"
                           % "；".join(bad))

        self.apply_keep(rk)
        save_ticket(self.portal.ticket, self.cfg, self.portal.ttl or 3600)
        self.online = True
        return True, "会话已建立并验证（auth=0 state=0 keep=0）userid=%s" % rs.text("userid")

    # -- 保活 ---------------------------------------------------------------

    def apply_keep(self, r):
        """从 keep 响应里取 interval，并在服务端换票时跟着换。

        ★ login 里的那次 keep 也要走这里 —— 否则服务端在 keep 时换了票，
          session.json 存的是**上一张**，注销就会拿到废票。
        """
        iv = r.text("interval")
        if iv and iv.isdigit():
            self.keep_interval = max(30, min(int(iv), 600))
        newt = r.text("ticket")
        if newt and newt != self.portal.ticket:
            self.portal.ticket = newt

    def do_keep(self) -> bool:
        r = self.portal.keep()
        if not r.ok:
            self.note("✗ 保活失败 %s %s" % (r.summary(),
                                            ERROR_MEANING.get(str(r.error_code), "")))
            return False
        self.apply_keep(r)
        save_ticket(self.portal.ticket, self.cfg, self.portal.ttl or 3600)
        return True

    def re_login(self, user, password):
        ok, why = self.login(user, password)
        self.note(("✓ " if ok else "✗ ") + why)
        if not ok:
            self.show_hint()
        return ok

    def run(self, user, password):
        """认证（可选）+ 保活，直到 Ctrl+C。"""
        last_keep = last_probe = last_lock = last_sync = time.time()
        try:
            while True:
                now = time.time()

                # 保活标记每 10 秒刷一次 —— 只在开头写一次的话，
                # 跑过 2 分钟之后 logout 就看不出保活还活着了。
                if now - last_lock >= 10:
                    last_lock = now
                    lock_set()

                # 每 5 分钟重新枚举网卡，跟上 DHCP 变化
                if now - last_sync >= 300:
                    last_sync = now
                    self.sync_identity()

                if now - last_probe >= 60:
                    last_probe = now
                    if not ip_is_local(self.cfg.get("wlanuserip", "")):
                        # 源地址没了 = 换了 IP，先重新探测再认证
                        self.sync_identity()
                        last_sync = time.time()
                    ok, why = internet_ok(self.cfg.get("wlanuserip", ""))
                    if not ok:
                        self.note("出网断了（%s），重新认证" % why)
                        # ★ 出网断通常意味着**换了出口**（网线掉了 / 切了 WiFi）。
                        #   必须重新枚举网卡再认证，否则会拿旧 IP 去认证 ——
                        #   门户会回 Error-Code 102「不在校园网内」，
                        #   看起来就像程序坏了，其实只是出口变了。
                        if self.sync_identity():
                            self.note("出口已变化，改用新的源地址重新认证")
                        self.online = False
                        self.re_login(user, password)
                        last_probe = time.time()
                        continue

                if now - last_keep >= self.keep_interval:
                    last_keep = now
                    if self.do_keep():
                        self.note("✓ 保活正常（每 %d 秒）" % self.keep_interval)
                    else:
                        self.note("重新认证")
                        self.online = False
                        self.re_login(user, password)
                        last_keep = time.time()
                time.sleep(1)
        except KeyboardInterrupt:
            say("")
            say("  已停止保活。**没有注销，仍然在线。**")
            say("  要断开请跑：python run.py logout")
        finally:
            lock_clear()
        return self.online

    # -- 注销 ---------------------------------------------------------------

    def logout(self):
        """注销。返回 (ok, 说明)。

        ★ `term.cgi` **必须带会话票据**。票据是 `ticket.cgi` 下发的，
          只存在于内存里；把认证和注销拆成两个进程而票据没落盘，
          发出去的就是 `<ticket></ticket>`（body 544 字节，官方 608），
          服务端回 Error-Code=1，注销静默失败。

        策略：① 存盘票据 + 当前身份 → ② + 存盘时的身份 → ③ 现场取一张新票据。
        """
        st = load_json(STATE_PATH)
        if st.get("ticket"):
            age = time.time() - float(st.get("saved_at") or 0)
            self.note("本地票据 %s…（%s 保存，%.0f 秒前）"
                      % (st["ticket"][:12], st.get("saved_at_text", "?"), age))
        else:
            self.note("本地票据：无 —— 这次会话不是本程序认证的，改为现场取票")

        live = lock_alive()
        if live:
            self.note("⚠ 常驻保活还在跑（PID %s）！它发现掉线会**重新认证**，" % live["pid"])
            self.note("  现在注销最多 1 分钟后你又会自动上线。请先 Ctrl+C 停掉它。")

        myip = self.cfg.get("wlanuserip", "")
        ident = (myip, clean_mac(self.cfg.get("wlanusermac", "")),
                 self.cfg.get("mscgip", ""))
        before = False
        if myip:
            before, _ = internet_ok(myip, timeout=3)
        self.note("注销前出网：%s" % ("通" if before else "不通"))

        tries = []
        if st.get("ticket"):
            tries.append(("存盘票据", st["ticket"], ident))
            old = (st.get("wlanuserip", ""), st.get("wlanusermac", ""), st.get("mscgip", ""))
            if old != ident and old[0]:
                tries.append(("存盘票据+存盘身份", st["ticket"], old))

        def add_fresh():
            """现场向 ticket.cgi 取一张 —— 已认证时它返回的就是本会话的票。"""
            self.portal.get_ticket()
            if self.portal.ticket:
                self.note("现场取到票据 %s…" % self.portal.ticket[:12])
                tries.append(("现场票据", self.portal.ticket, ident))

        if not tries:
            add_fresh()

        if not tries:
            return False, ("拿不到任何票据，注销无法进行。\n"
                           "  （既没有 session.json，ticket.cgi 也没取到票 —— 多半是不在校园网）")

        codes = []
        for label, tk, idt in tries:
            self.portal.ticket = tk
            r = self.portal.term(ident=idt)
            codes.append(str(r.error_code))
            self.note("%-18s → %s" % (label, r.summary()))
            if not r.ok:
                continue
            after, _ = internet_ok(myip, timeout=5) if myip else (False, "")
            if before and after:
                # ★ 不清 session.json：注销可能没生效，票是唯一还能用的东西
                return False, ("服务端返回 0，但出网**仍然通** —— 注销可能没生效。\n"
                               "  票据已保留，可以再跑一次 logout。\n"
                               "  （如果网页确实打不开了，忽略本条）")
            clear_ticket()
            return True, "注销成功：服务端返回 0，出网已断"

        # 存盘票据不行就再试一张现场票（策略 ③）
        if st.get("ticket"):
            add_fresh()
            if tries and tries[-1][0] == "现场票据":
                label, tk, idt = tries[-1]
                self.portal.ticket = tk
                r = self.portal.term(ident=idt)
                codes.append(str(r.error_code))
                self.note("%-18s → %s" % (label, r.summary()))
                if r.ok:
                    after, _ = internet_ok(myip, timeout=5) if myip else (False, "")
                    if not (before and after):
                        clear_ticket()
                        return True, "注销成功（现场票据）：服务端返回 0，出网已断"

        # 本来就不在线 —— 不算失败（但要用 state.cgi 复核，别只信出网探测）
        if not before:
            still = None
            if st.get("ticket"):
                self.portal.ticket = st["ticket"]
                rs = self.portal.state()
                self.note("复核 state.cgi → %s" % rs.summary())
                if rs.ok and rs.xml is not None:
                    still = rs.text("userid")
            if still:
                return False, ("会话其实还在（state.cgi userid=%s）—— 注销没成功。\n"
                               "  出网探测不通可能只是探测目标被挡。" % still)
            clear_ticket()
            return True, "本来就不在线（出网不通，state.cgi 也不认票据），无需注销。"

        hint = ""
        if "14" in codes:
            hint = "\n  出现 Error-Code=14 = **重复注销**：第一次其实已经成功了。"
        elif codes and all(c == "1" for c in codes):
            hint = ("\n  全是 Error-Code=1 = 服务端认为这些参数下没有会话：\n"
                    "    · 会话不是本程序建的（票据对不上），或已被别的客户端注销")
        return False, ("注销失败（%d 次尝试都没返回 Error-Code 0）。%s\n"
                       "  常驻保活在跑时会立刻重新认证 —— 先确认它停了。"
                       % (len(tries), hint))


# ===========================================================================
# 6. 命令行
# ===========================================================================

USAGE = __doc__.split("为什么是一个文件")[0].strip()


def ensure_config(force=False) -> dict:
    cfg = load_json(CONFIG_PATH)
    # 文件在却读不出来 = 会被当成"首次运行"，静默重建 —— 会丢掉
    # mscgip 这类非必填字段，而 auth.cgi 可能正是靠它。
    if not cfg and os.path.exists(CONFIG_PATH) and os.path.getsize(CONFIG_PATH) > 0:
        say("⚠ config.json 在但**读取失败**，将按默认重建。")
        say("  这会丢掉 mscgip 等字段 —— 如果之后 auth.cgi 回 102，先查这里。")
        say("")
    need = force or not cfg.get("username") or not cfg.get("password")
    if need:
        say("只需填账号和密码，其余（IP / MAC / 网关 / 门户）自动探测。")
        say("")
        try:
            u = input("  账号（手机号）: ").strip()
            p = input("  密码          : ").strip()
        except (EOFError, KeyboardInterrupt):
            return {}
        if not u or not p:
            say("账号或密码为空，已取消。")
            return {}
        cfg.update({"username": u, "password": p})
    cfg = refresh_identity(cfg)

    # mscgip 缺失 → 现场从门户劫持的 302 里挖（见 discover_mscgip）
    if not cfg.get("mscgip"):
        got = discover_mscgip(cfg.get("portal", DEFAULT_PORTAL),
                              cfg.get("port", DEFAULT_PORT),
                              src_ip=cfg.get("wlanuserip", ""))
        if got:
            cfg["mscgip"] = got
            say("✓ 从门户重定向取到 mscgip = %s" % got)

    save_json(CONFIG_PATH, cfg)
    if need:
        say("✓ 配置已写入 %s" % CONFIG_PATH)
    return cfg


def env_report(cfg) -> tuple:
    """打印环境，返回 (是否像在校园网, 说明)。

    ★ **把没有链路的网卡也打出来**。只列"有地址的网卡"会掩盖掉
      「以太网 Disconnected」这一条 —— 而它恰恰是"认证不了"最常见
      的原因（网线掉了 → 流量掉到手机热点 → 门户回 102）。
    """
    all_if = _enumerate(include_down=True)
    if not all_if:
        say("  网卡    ✗ 枚举不到任何物理网卡")
        return False, "没有可用网卡"

    say("  网卡")
    eth_link = False
    for r in all_if:
        has = r["up"] and r["ip"]
        if r["alias"].startswith("以太") or r["alias"].lower().startswith("eth"):
            eth_link = eth_link or has
        say("    %-10s %-10s %s" % (r["alias"], "有链路" if has else r["status"],
                                    r["ip"] or "(无地址)"))

    ads = adapters()
    if not ads:
        say("  出口    ✗ 没有任何带地址的网卡")
        return False, "没有可用网卡"
    cur = ads[0]
    ssid = wifi_ssid() if re.search(r"WLAN|Wi-Fi|无线", cur["alias"], re.I) else ""
    say("  出口    %s%s → %s" % (cur["alias"],
                                 "（SSID=%s）" % ssid if ssid else "",
                                 cur["gateway"] or "(无网关)"))
    hop = first_hop(cfg["portal"])
    say("  第一跳  %s" % (hop or "?"))

    ok, why = in_campus(cur["ip"], cur["gateway"], hop)
    say("  校园网  %s %s" % ("✓ 在校园网内：" if ok else "✗ 不在校园网内：", why))
    if not eth_link:
        say("  ⚠ 以太网没有链路，现在只走 %s。校园网通常走网线，" % cur["alias"])
        say("    手机热点/家用 WiFi 的网关同样可达、IP 同样在 10.x —— 光看")
        say("    这两条分不出来，最终由门户说了算（拒绝时回 Error-Code 102）。")
    return ok, why


def cmd_dial() -> int:
    cfg = ensure_config()
    if not cfg:
        return 1
    say("")
    say("天翼校园拨号器   账号 %s   门户 %s" % (cfg["username"], cfg["portal"]))
    say("-" * 60)
    ok, why = env_report(cfg)
    if not ok:
        say("")
        say("  不在校园网内，认证必然失败（门户会返回 Error-Code 102）。")
        say("  请先插好网线、确认适配器 Status = Up。")
        return 1

    s = Session(cfg)
    say("-" * 60)
    if s.already_online():
        ok, why = True, "已在线，直接保活"
    else:
        ok, why = s.login(cfg["username"], cfg["password"])
        say("  %s%s" % ("✓ " if ok else "✗ ", why))
        if not ok:
            s.show_hint()
    if not ok:
        return 1
    say("-" * 60)
    say("  Ctrl+C 停止保活（不断网）")
    say("")
    s.run(cfg["username"], cfg["password"])
    write_log(s)
    return 0


def cmd_logout() -> int:
    cfg = load_json(CONFIG_PATH)
    if not cfg:
        say("没有 config.json，先跑 python run.py")
        return 1
    cfg = refresh_identity(cfg)
    say("注销会断开当前会话，之后需要重新认证。")
    try:
        if input("确认注销？(y/N): ").strip().lower() != "y":
            say("已取消")
            return 0
    except (EOFError, KeyboardInterrupt):
        return 0
    say("")
    s = Session(cfg)
    ok, why = s.logout()
    say("")
    for i, line in enumerate(why.splitlines()):
        say(("  ✓ " if ok else "  ✗ ") + line if i == 0 else "    " + line)
    s.log.append(("%s %s" % ("✓" if ok else "✗", why.splitlines()[0])))
    write_log(s)
    return 0 if ok else 1


def cmd_init() -> int:
    cfg = ensure_config(force=True)
    return 0 if cfg else 1


def write_log(s):
    try:
        with open(LOG_PATH, "w", encoding="utf-8") as f:
            f.write("=== %s ===\n" % time.strftime("%Y-%m-%d %H:%M:%S"))
            f.write("\n".join(s.log))
            f.write("\n")
    except OSError:
        pass


# --- 离线自检 --------------------------------------------------------------
#
# 内嵌一个**真实抓包样本**（state.cgi，576 个 hex 字符）。
# 旧版自检要扫描 C:\temp\zx\extracted 之类的目录，样本一删就失效。

_SAMPLE = (
    "287B4C77697C6E4D7447787B646944619F8470FC7E1A08B2561516632FF4E263AC961CFBC670880913E2AD6F"
    "E506037831E55C906604D3EA9C04E008070F086099575E6A2133FC20559CBDD531CC5C06A836A33CC90EDDFB"
    "78DAE335180132406EEB5A247D8D4A4774D9B1B9BA792A9967B94B53EDABB438143F062112AAC306C4B015D7"
    "2CEBADF37EE008AFB32DAC1934BF59366082C66EA7EFDFD6D52E5F3EA4F6D2640D2199071B6D0B1191FD9467"
    "746754F9EB147783B3F457EFB4A3301DAC1C6EEE8FA213A5D3A850D631A4E0F607747BC8B9906580C54B6C19"
    "D1CBFB25F328C6C9DA3789B9BB7DC107FB3BE1764D2C144FE22AC8135DB3E5E74459605EA21B9E4D62AF36D9"
    "003D556A73DD75DD1577B105A43CDF4DF02F16D6EE9404B5"
)


def selftest() -> int:
    say("离线自检（不联网）")
    say("-" * 60)
    bad = 0

    # ① 编解码往返
    plain = b'<?xml version="1.0" encoding="utf-8"?><request><a>1</a></request>'
    if decrypt(encrypt(plain)) != plain:
        say("  ✗ 加解密往返失败")
        bad += 1
    else:
        say("  ✓ 加解密往返一致")

    # ② 长度公式
    n_bad0 = bad
    for L, want_body in ((265, 608), (299, 672), (246, 576), (361, 800), (384, 864)):
        B = 32 + BLOCK * -(-(L + 1) // BLOCK)
        if 2 * B != want_body:
            say("  ✗ 长度公式不符：L=%d → %d，应为 %d" % (L, 2 * B, want_body))
            bad += 1
    if bad == n_bad0:
        say("  ✓ 长度公式与 5 个官方样本一致")

    # ③ 真实样本往返（证明密钥正确，而不只是自洽）
    if len(_SAMPLE) % 2 == 0 and len(_SAMPLE) > 100:
        try:
            got = decrypt(from_wire(_SAMPLE.encode()))
            if to_wire(encrypt(got)) != _SAMPLE.encode():
                raise CodecError("回加密不一致")
            if b"<ticket>" not in got:
                raise CodecError("解出来不是预期的 XML")
            say("  ✓ 真实样本往返逐字节一致（%d 字节）" % (len(_SAMPLE) // 2))
        except Exception as e:
            say("  ✗ 真实样本往返失败：%s" % e)
            bad += 1

    # ④ Error-Code 判据（含**小写头**——门户/中间设备可能规范化大小写）
    n_bad0 = bad
    for hdr, want in (({"Error-Code": "0"}, True), ({"Error-code": "0"}, True),
                      ({"ERROR-CODE": "0"}, True), ({"Error-Code": "1"}, False),
                      ({"Error-Code": "14"}, False), ({"Error-Code": "102"}, False),
                      ({}, False)):
        r = Response("term.cgi", 200, hdr, b"")
        if r.ok != want:
            say("  ✗ 响应头 %s 判成 %s，应为 %s" % (hdr, r.ok, want))
            bad += 1
    if bad == n_bad0:
        say("  ✓ Error-Code 0 = 成功（空响应体也是），大小写不敏感")

    # ⑤ 注销报文：走**真实构造路径**，不是手抄一遍
    cap = {}

    class _Cap(Portal):
        def post(self, endpoint, xml, ident=None):
            cap["ep"], cap["xml"] = endpoint, xml
            cap["query"] = self._query(ident or self.ident)   # 走真实查询串构造
            return Response(endpoint, 200, {"Error-Code": "0"}, b"")

    p = _Cap({"portal": "1.1.1.1", "port": 10001, "wlanuserip": "1.2.3.4",
              "wlanusermac": "aabbccddeeff", "mscgip": "5.6.7.8", "gateway": "1.2.3.1"})
    p.ticket = "05759407fe1cb58b9938509c2c0a0a39"
    p.term()
    n = len(to_wire(encrypt(cap["xml"])))
    q = cap.get("query", "")
    ok_all = (cap.get("ep") == "term.cgi"
              and p.ticket.encode() in cap["xml"]
              and "wlanuserip=1.2.3.4" in q and "wlanusermac=aabbccddeeff" in q)
    if n != 608 or not ok_all:
        say("  ✗ 注销报文不对：端点=%s 长度=%d 查询串=%s"
            % (cap.get("ep"), n, q))
        bad += 1
    else:
        say("  ✓ 注销报文 608 字节，走 term() 真实路径，含票据与身份查询串")

    # ⑥ 垃圾输入必须被识别，不能静默当成 XML
    n_bad0 = bad
    for name, body in (("HTML 页面", b"<html><body>302</body></html>"),
                       ("奇数长度 hex", b"ABC"),
                       ("非 hex 垃圾", b"zzzzzzzz")):
        try:
            r = Response("x.cgi", 200, {"Error-Code": "0"}, body)
            if r.kind == "xml" and r.xml is not None:
                say("  ✗ %s 被当成了合法 XML" % name)
                bad += 1
        except Exception as e:
            say("  ✗ %s 让程序抛了异常：%s" % (name, e))
            bad += 1
    if bad == n_bad0:
        say("  ✓ HTML / 奇数 hex / 垃圾输入都不会被误当成合法响应")

    say("-" * 60)
    say("  %s" % ("✓ 全部通过" if not bad else "✗ %d 项失败" % bad))
    return 1 if bad else 0


def main() -> int:
    cmd = (sys.argv[1].lower() if len(sys.argv) > 1 else "")
    if cmd in ("-h", "--help", "help", "?"):
        say(USAGE)
        return 0
    if cmd in ("", "dial", "login", "run"):
        return cmd_dial()
    if cmd == "logout":
        return cmd_logout()
    if cmd == "init":
        return cmd_init()
    if cmd == "selftest":
        return selftest()
    say("未知命令：%s\n" % cmd)
    say(USAGE)
    return 2


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        say("\n已中断")
        sys.exit(130)

