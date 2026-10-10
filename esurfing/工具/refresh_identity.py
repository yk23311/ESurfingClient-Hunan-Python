#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""在断网前刷新一次网卡身份，写回 config.json。

单独做成一个 .py 文件，而不是写在 .bat 里的一行式命令 ——
cmd 会把 `%s` 之类的片段当成变量引用吃掉（`%s mac=%` 会被展开成空串），
导致 Python 收到的是残缺代码，报 SyntaxError 而脚本却继续往下跑。
放在 .py 里就完全没有这个问题。

退出码：0 = 刷新成功，1 = 失败。
"""

import os
import sys

SELF_DIR = os.path.dirname(os.path.abspath(__file__))


def _find_root(start):
    """往上找放 run.py 的那层（esurfing 根）。

    本脚本住在 工具\\ 子目录里，而 run.py / config.json 在上一层。
    写死相对层数会在再挪一次目录时又断掉，所以按标志文件找。
    """
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

import run  # noqa: E402


def main() -> int:
    cfg = run.load_json(run.CONFIG_PATH)
    if not cfg:
        print("  config.json 读不出来，跳过身份刷新")
        return 1

    before = (cfg.get("wlanuserip", ""), cfg.get("wlanusermac", ""))
    cfg = run.refresh_identity(cfg)
    after = (cfg.get("wlanuserip", ""), cfg.get("wlanusermac", ""))

    if not after[0]:
        print("  探测不到任何带地址的网卡，跳过身份刷新")
        return 1

    if not run.save_json(run.CONFIG_PATH, cfg):
        print("  写 config.json 失败")
        return 1

    print("  身份 ip=%s mac=%s gw=%s" % (after[0], after[1], cfg.get("gateway", "")))
    if before != after:
        print("  （相比配置里原值有变化：%s/%s → %s/%s）"
              % (before[0] or "(空)", before[1] or "(空)", after[0], after[1]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
