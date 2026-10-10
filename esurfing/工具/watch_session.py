#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""等网络自然断开，然后立刻用 **C 版** 从断线状态重新认证。

为什么这样探测
--------------
上一版用 `state.cgi` 每 10 秒轮询，跑了 351 秒会话都还活着 —— 而服务端自报的
心跳间隔只有 300 秒。分不清是「TTL 本来就长」还是「轮询本身在续命」。

所以这一版**完全不碰门户**：只用「绑定校园网源地址、TCP 连公网 DNS」判断通不通。
这既不可能给会话续命，又直接测的正是你关心的那件事 —— 网到底断没断。

脚本做四件事
------------
1. 每 15 秒 TCP 探一次公网（不发心跳、不查门户），记录状态变化
2. 连续 2 次不通 = 真的断线；**立刻抓一份完整的网卡快照**
   （IP 还在不在、默认路由还在不在、拿到新 IP 没有）—— 这正是步骤 9 需要的证据
3. 断线后立刻调 hunan_live.exe auth，用 C 版重新认证并验证
4. C 版失败 → 自动拉起 restore_network.bat（Python 版）兜底

全程写 session-watch.log，所以即使远程会话（AI）失联，证据也在盘上。

用法:
    python watch_session.py [--interval 15] [--max-wait 1800] [--fail-threshold 2]

注意: 同一时刻只允许一个实例（session-watch.lock）。
"""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
import time

SELF_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_root(start):
    """往上找放 run.py 的那层（esurfing 根）。本脚本住在 工具\\ 子目录里。"""
    d = start
    for _ in range(4):
        if os.path.isfile(os.path.join(d, "run.py")):
            return d
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return start


HERE = _find_root(SELF_DIR)
sys.path.insert(0, HERE)

import run as R  # noqa: E402

LOG_PATH = os.path.join(SELF_DIR, "session-watch.log")
LOCK_PATH = os.path.join(SELF_DIR, "session-watch.lock")
RESTORE_BAT = os.path.join(SELF_DIR, "restore_network.bat")
TOOL = r"C:\temp\esurfing_build\hunan_live.exe"
CFG = os.path.join(HERE, "config.json")

PROBE_TARGETS = (("223.5.5.5", 53), ("114.114.114.114", 53), ("180.76.76.76", 53))

_logf = None


# ------------------------------------------------------------------ 基础设施

def take_lock() -> bool:
    try:
        if os.path.exists(LOCK_PATH):
            with open(LOCK_PATH, encoding="utf-8") as f:
                pid_txt = (f.read().split() or [""])[0]
            # 进程还在就不抢
            if pid_txt.isdigit() and _pid_alive(int(pid_txt)):
                return False
    except (OSError, ValueError):
        pass
    with open(LOCK_PATH, "w", encoding="utf-8") as f:
        f.write("%d %.0f" % (os.getpid(), time.time()))
    return True


def _pid_alive(pid: int) -> bool:
    try:
        out = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid, "/NH"],
                             capture_output=True, text=True, timeout=10)
        return str(pid) in (out.stdout or "")
    except Exception:  # noqa: BLE001
        return False


def drop_lock():
    try:
        os.remove(LOCK_PATH)
    except OSError:
        pass


def note(msg=""):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    if _logf:
        _logf.write(line + "\n")
        _logf.flush()


# ------------------------------------------------------------------ 探测

def net_ok(src_ip: str) -> tuple:
    """绑定 src_ip 去连公网 DNS。返回 (是否通, 说明)。**完全不碰门户。**"""
    if not R.ip_is_local(src_ip):
        return False, "源地址 %s 已不在本机网卡上" % src_ip
    errs = []
    for host, port in PROBE_TARGETS:
        s = None
        try:
            s = socket.socket()
            s.settimeout(4)
            s.bind((src_ip, 0))
            s.connect((host, port))
            return True, "%s:%d 通" % (host, port)
        except OSError as e:
            errs.append("%s:%d %s" % (host, port, e))
        finally:
            if s is not None:
                s.close()
    return False, "；".join(errs) or "全部失败"


def snapshot(label: str):
    """抓一份网卡快照 —— 步骤 9（真实网卡身份）需要的证据。"""
    note("── 网卡快照（%s）──" % label)
    try:
        rows = R._enumerate(include_down=True)
    except Exception as e:  # noqa: BLE001
        note("  枚举网卡失败: %s" % e)
        return
    if not rows:
        note("  （枚举不到任何物理网卡）")
        return
    for r in rows:
        note("  %-14s %-10s %-16s 网关 %s"
             % (r["alias"], "有链路" if (r["up"] and r["ip"]) else r["status"],
                r["ip"] or "(无地址)", r["gateway"] or "(无网关)"))


# ------------------------------------------------------------------ 主流程

def run_tool(mode: str) -> int:
    note("  → 调用 hunan_live.exe %s" % mode)
    try:
        p = subprocess.run([TOOL, mode, CFG], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
    except Exception as e:  # noqa: BLE001
        note("  ✗ 调用失败: %s" % e)
        return 1
    for line in (p.stdout or "").splitlines():
        # state.cgi 的响应很长，只保留关键行
        s = line.strip()
        if s.startswith("<?xml") or s.startswith("<process") or s.startswith("<driver") \
                or s.startswith("<API") or s.startswith("<shared") or s.startswith("<against") \
                or s.startswith("<public") or s.startswith("<private") or s.startswith("<virtual") \
                or s.startswith("<sandbox") or s.startswith("<logout-delay") or s == "":
            continue
        note("    | " + line)
    for line in (p.stderr or "").splitlines():
        note("    ! " + line)
    return p.returncode


def main() -> int:
    global _logf
    ap = argparse.ArgumentParser()
    ap.add_argument("--interval", type=float, default=15.0)
    ap.add_argument("--max-wait", type=float, default=1800.0)
    ap.add_argument("--fail-threshold", type=int, default=2)
    a = ap.parse_args()

    _logf = open(LOG_PATH, "a", encoding="utf-8")

    if not take_lock():
        note("已有另一个 watch_session 在跑，本次退出。")
        note("确认没有别的实例后，删掉 session-watch.lock 再试。")
        return 3

    note("=" * 62)
    note("等断线 → 用 C 版拨回来")
    note("探测方式: 绑定校园网源地址 TCP 连公网 DNS（不碰门户，不会续命）")
    note("间隔 %.0fs  最长等 %.0f 分钟  连续 %d 次失败判定断线"
         % (a.interval, a.max_wait / 60.0, a.fail_threshold))
    note("=" * 62)

    cfg = R.load_json(CFG)
    if not cfg:
        note("✗ 读不到 config.json")
        return 2
    cfg = R.refresh_identity(cfg)
    src = cfg.get("wlanuserip", "")
    if not src:
        note("✗ 探测不到本机 IP（网卡掉了？）")
        return 2

    note("本机 %s / %s   门户 %s" % (src, cfg.get("wlanusermac", ""), cfg.get("portal", "")))
    snapshot("起点")

    ok, why = net_ok(src)
    note("当前网络: %s（%s）" % ("通" if ok else "不通", why))
    if not ok:
        note("一开始就不通 —— 那就直接进认证流程")
        fails = a.fail_threshold
        t0 = time.time()
    else:
        fails = 0
        t0 = time.time()

    alive = ok
    n = 0
    while time.time() - t0 < a.max_wait and fails < a.fail_threshold:
        time.sleep(a.interval)
        n += 1
        el = time.time() - t0
        ok, why = net_ok(src)
        if ok:
            if not alive:
                note("—— 网络恢复（第 %.0f 秒）" % el)
            alive = True
            fails = 0
            if n % 8 == 0:
                note("  …通了 %.0f 秒（第 %d 次探测）" % (el, n))
        else:
            fails += 1
            alive = False
            note("—— 第 %d/%d 次探测不通: %s（第 %.0f 秒）"
                 % (fails, a.fail_threshold, why, el))

    if fails < a.fail_threshold:
        note("")
        note("等待 %.0f 分钟网络都没断。可能 keep-retry 很长，或有别的东西在续命。"
             % (a.max_wait / 60.0))
        note("退出，不改动任何东西。")
        return 0

    # ---- 断线了 --------------------------------------------------------
    note("")
    note("=" * 62)
    note("★ 网络已断。现在用 C 版从断线状态把它拨回来")
    note("=" * 62)
    snapshot("断线后")

    # 断线后 IP 可能变了 —— 重新探测一次，这正是步骤 9 要的证据
    before = (cfg.get("wlanuserip", ""), cfg.get("wlanusermac", ""), cfg.get("gateway", ""))
    cfg2 = R.refresh_identity(dict(cfg))
    after = (cfg2.get("wlanuserip", ""), cfg2.get("wlanusermac", ""), cfg2.get("gateway", ""))
    if before != after:
        note("身份变化: %s → %s" % (before, after))
        R.save_json(CFG, cfg2)
        note("（已写回 config.json，供 C 版使用）")
    else:
        note("身份未变: %s" % (after,))
        note("  ← 注意: 断线后源地址仍然有效 = 僵尸租约，Python 版 README 记过这个坑")

    note("")
    rc = run_tool("auth")
    if rc != 0:
        note("")
        note("✗ C 版认证失败 —— 启动 Python 版兜底恢复")
        try:
            subprocess.Popen(["cmd", "/c", "start", "esurfing restore",
                              RESTORE_BAT],
                             cwd=HERE)
            note("  已在新窗口启动 restore_network.bat")
        except Exception as e:  # noqa: BLE001
            note("  ✗ 启动兜底脚本失败: %s" % e)
            note("  请手动双击 启动拨号.bat")
        note("")
        note("结果: 从断线状态用 C 版恢复 **失败**，已交回 Python 版。")
        return 1

    note("")
    note("✓ C 版从断线状态认证成功，做只读验证")
    run_tool("read")
    ok2, why2 = net_ok(cfg2.get("wlanuserip", src))
    note("出网复测: %s（%s）" % ("通" if ok2 else "不通", why2))
    note("")
    note("=" * 62)
    if ok2:
        note("结果: **C 版成功从真正断线的状态把网拨了回来**")
    else:
        note("结果: C 版认证返回 0，但出网探测仍不通 —— 需要人工看一眼")
    note("=" * 62)
    return 0 if ok2 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        note("被 Ctrl+C 中断")
        sys.exit(130)
    finally:
        drop_lock()
