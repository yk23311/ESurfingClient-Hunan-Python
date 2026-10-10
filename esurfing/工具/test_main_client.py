#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""主程序 ESurfingClient.exe 的湖南路径 —— 一键联网实测。

与之前的 hunan_live 测试不同: 这次跑的是**主程序本身**, 会走完整的
    网络检测 → 配置分流 → 初始化会话 → 取票 → 登录 → 心跳循环
以及监管进程 / 看门狗 / Web UI 那一整套。

前置条件 (脚本会自己检查)
------------------------
1. **必须先停掉 Python 版保活**。它每 60 秒探一次网、发现掉线就重新认证,
   不停掉的话会和 C 版抢同一个会话, 测出来的结果没有意义。
   判断依据是 esurfing 目录下的 keepalive.lock。

流程
----
[1] 检查保活已停
[2] 用 esurfing/config.json 里的账号密码, 生成湖南配置写到 exe 目录
[3] 先强制断一次网 (hunan_live term), 制造「需要认证」的状态
    —— 否则会话还活着, 主程序会判定「已在线」而一直等, 要等十几分钟
[4] 启动主程序 (新窗口, 无参数 = 前台完整模式)
[5] 观察最多 N 秒: 看日志 + 探网络
[6] 成功 → 你可以就用 C 版了; 失败 → 自动拉起 Python 版恢复

用法:
    python test_main_client.py [--wait 180] [--no-drop]
"""

from __future__ import annotations

import argparse
import glob
import json
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

EXE_DIR = r"C:\temp\esurfing_build\app_build"
EXE = os.path.join(EXE_DIR, "ESurfingClient.exe")
CFG_OUT = os.path.join(EXE_DIR, "ESurfingClient.json")
TOOL = r"C:\temp\esurfing_build\hunan_live.exe"
ESD_CFG = os.path.join(HERE, "config.json")
LOG_PATH = os.path.join(SELF_DIR, "main-client-test.log")
RESTORE_BAT = os.path.join(SELF_DIR, "restore_network.bat")
BACKUP = CFG_OUT + ".bak"

PROBE = (("223.5.5.5", 53), ("114.114.114.114", 53))

_logf = None


def note(msg=""):
    line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
    print(line, flush=True)
    if _logf:
        _logf.write(line + "\n")
        _logf.flush()


def net_ok(src_ip: str):
    """绑定校园网源地址 TCP 连公网。不碰门户。"""
    if src_ip and not R.ip_is_local(src_ip):
        return False, "源地址 %s 已不在本机" % src_ip
    for host, port in PROBE:
        s = None
        try:
            s = socket.socket()
            s.settimeout(4)
            if src_ip:
                s.bind((src_ip, 0))
            s.connect((host, port))
            return True, "%s:%d 通" % (host, port)
        except OSError as e:
            last = "%s:%d %s" % (host, port, e)
        finally:
            if s is not None:
                s.close()
    return False, last


def find_log():
    """找主程序写到哪了。log_dir 默认 './', 落点是 exe 目录下的 logs/。"""
    cands = [
        os.path.join(EXE_DIR, "logs", "run.log"),
        os.path.join(EXE_DIR, "run.log"),
        os.path.join(EXE_DIR, "logs", "*.log"),
    ]
    for c in cands:
        if os.path.isfile(c):
            return c
        hits = glob.glob(c)
        if hits:
            return max(hits, key=os.path.getmtime)
    return None


def tail(path, n=40):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read().splitlines()[-n:]
    except OSError:
        return []


def main() -> int:
    global _logf
    ap = argparse.ArgumentParser()
    ap.add_argument("--wait", type=float, default=180.0, help="最长观察秒数")
    ap.add_argument("--no-drop", action="store_true",
                    help="不先强制断网 (会话还活着时主程序会一直等, 可能要十几分钟)")
    a = ap.parse_args()

    _logf = open(LOG_PATH, "a", encoding="utf-8")
    note("=" * 64)
    note("主程序湖南路径实测")
    note("=" * 64)

    # ---- 前置检查 --------------------------------------------------
    if not os.path.isfile(EXE):
        note("✗ 找不到主程序: %s" % EXE)
        return 2
    if not os.path.isfile(TOOL):
        note("✗ 找不到 hunan_live.exe: %s" % TOOL)
        return 2

    esd = R.load_json(ESD_CFG)
    if not esd.get("username") or not esd.get("password"):
        note("✗ esurfing/config.json 里没有账号密码, 无法生成配置")
        return 2

    live = R.lock_alive()
    if live:
        note("")
        note("✗ Python 版保活还在跑 (PID %s)。" % live.get("pid"))
        note("  它会每 60 秒重新认证, 和 C 版抢同一个会话 —— 测出来的结果没意义。")
        note("")
        note("  请先在那个窗口按 Ctrl+C 停掉它, 然后重新运行本脚本。")
        note("  (判断依据: esurfing/keepalive.lock 在 120 秒内被刷新过)")
        note("")
        return 3
    note("✓ Python 保活已停")

    # ---- 生成湖南配置 ----------------------------------------------
    if os.path.isfile(CFG_OUT) and not os.path.isfile(BACKUP):
        try:
            os.replace(CFG_OUT, BACKUP)
            note("已备份原有配置 → %s" % os.path.basename(BACKUP))
        except OSError as e:
            note("⚠ 备份失败: %s" % e)

    cfg = {
        "enabled": True,
        "web_external_acc": False,
        "log_lv": 5,               # DEBUG: 要看清楚省份分流与报文
        "log_dir": "./",
        "conn_timeout": 7,
        "op_timeout": 10,
        "web_port": 8888,
        "accounts": [{
            "username": esd["username"],
            "password": esd["password"],
            "channel": 3,
            "mark": "",
            "province": "hunan",
            "portal": esd.get("portal", "175.12.104.1"),
            "portal_port": int(esd.get("port", 10001)),
            "mscgip": esd.get("mscgip", ""),
            "time_windows": [],
        }],
    }
    with open(CFG_OUT, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=1)
    note("✓ 已写入湖南配置 → %s" % CFG_OUT)
    note("  province=hunan  portal=%s:%s  mscgip=%s"
         % (cfg["accounts"][0]["portal"], cfg["accounts"][0]["portal_port"],
            cfg["accounts"][0]["mscgip"] or "(空)"))

    src_ip = esd.get("wlanuserip", "")
    ok, why = net_ok(src_ip)
    note("当前网络: %s (%s)" % ("通" if ok else "不通", why))

    # ---- 制造「需要认证」状态 ---------------------------------------
    if not a.no_drop and ok:
        note("")
        note("先用 hunan_live term 强制断一次网 —— 会话还活着的话,")
        note("主程序会判定「已在线」而一直等, 要等十几分钟才轮到它认证。")
        p = subprocess.run([TOOL, "term", ESD_CFG], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=120)
        for line in (p.stdout or "").splitlines():
            note("  | " + line)
        if p.returncode != 0:
            note("✗ 强制断网失败 —— 中止, 网络未被改动")
            return 1
        time.sleep(3)
        note("✓ 已断网, 现在交给主程序")

    # ---- 启动主程序 -------------------------------------------------
    note("")
    note("启动主程序 (新窗口): %s" % EXE)
    try:
        proc = subprocess.Popen([EXE], cwd=EXE_DIR,
                                creationflags=subprocess.CREATE_NEW_CONSOLE)
    except Exception as e:  # noqa: BLE001
        note("✗ 启动失败: %s" % e)
        return 1

    # ---- 观察 -------------------------------------------------------
    note("观察最长 %.0f 秒 ..." % a.wait)
    notice = ("省份模式", "Ticket URL", "Auth URL", "Algo-ID", "ZSM",
              "已认证登录", "登录失败", "初始化会话", "取票", "ERROR", "FATAL")
    t0 = time.time()
    ok_net = False
    authed = False
    last_line = ""
    while time.time() - t0 < a.wait:
        time.sleep(5)
        el = time.time() - t0
        ok_net, why = net_ok(src_ip if src_ip else None)

        lg = find_log()
        if lg:
            lines = tail(lg, 80)
            if any(("已认证登录" in ln or "认证成功" in ln) for ln in lines):
                authed = True
            for ln in reversed(lines):
                if any(k in ln for k in notice):
                    last_line = ln.strip()
                    break

        note("  +%.0fs  网络=%s  %s" % (el, "通" if ok_net else "不通",
                                       ("| " + last_line[-110:]) if last_line else ""))
        if authed:
            break

        # 主进程没了 = 启动就崩 / 立刻退出。别让用户白等满整个观察窗口。
        if proc.poll() is not None and not ok_net:
            note("")
            note("✗ 主程序已退出 (退出码 %s) 而网络仍不通 —— 立刻走兜底恢复。"
                 % proc.returncode)
            break

    note("")
    note("=" * 64)
    lg = find_log()
    if lg:
        note("主程序日志: %s" % lg)
        note("---- 最后 25 行 ----")
        for ln in tail(lg, 25):
            note("  " + ln)
    else:
        note("⚠ 没找到主程序日志 (它可能还没写, 或者写到别处去了)")

    ok_net, why = net_ok(src_ip if src_ip else None)
    note("")
    if ok_net:
        note("结果: **网络已恢复** (%s)" % why)
        note("主程序应仍在那个新窗口里跑着 —— 想长期用 C 版就留着它;")
        note("想换回 Python 版, 先关掉那个窗口, 再双击 启动拨号.bat。")
        rc = 0
    else:
        note("结果: **网络仍不通** —— 主程序没能把网拨回来。")
        note("启动 Python 版兜底恢复 ...")
        try:
            subprocess.Popen(["cmd", "/c", "start", "esurfing restore",
                              RESTORE_BAT], cwd=HERE)
            note("已在新窗口启动 restore_network.bat")
        except Exception as e:  # noqa: BLE001
            note("✗ 启动兜底失败: %s —— 请手动双击 启动拨号.bat" % e)
        rc = 1
    note("=" * 64)
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        note("被 Ctrl+C 中断")
        sys.exit(130)
