# 天翼校园拨号器 —— 湖南版

湖南天翼校园网（中国电信）认证客户端的两套独立实现。

> ### ⚠️ 先读这段
>
> **Python 版并不完善，仅供参考，不建议日常使用。** 它是协议实验与原型，
> 能跑通认证与保活，但边界情况处理不足、没经过长期运行检验。
> 不完善之处逐条列在 [`esurfing/README.md`](esurfing/README.md) 的「已知不足」里。
>
> **C 版才是能日常用的那个** —— 有网页界面、掉线自动重连、心跳保活、开机自启。
> 但它的源码**不在本仓库**，在单独的仓库里：
> **[yk23311/ESurfingClient-Hunan](https://github.com/yk23311/ESurfingClient-Hunan)**。
> 本仓库的 `esurfing-c/` 只放它的源码归档（bundle + zip），方便离线保存。

> **免责声明**：本项目与中国电信、任何高校均无关联，为个人学习与自用而写。
> 协议参数由抓包分析得出。使用前请确认不违反你所在学校的网络使用规定。

---

## 仓库里有什么

```
├─ esurfing/              Python 版（实验性，单文件 1500 行）
│   ├─ run.py             全部代码
│   ├─ 启动拨号.bat        双击等于 `python run.py`
│   ├─ 文档/              可行性分析 / 路线B-进展 / 开源协议分析
│   └─ 工具/              测试与恢复脚本（见下）
│
├─ esurfing-c/            C 版的源码归档 —— 用于离线保存，不是工作副本
│   ├─ esurfing-c-源码.bundle            完整 git 历史 + 全部标签
│   └─ esurfing-c-源码(含湖南适配).zip    HEAD 的工作树快照
│
└─ LICENSE                Apache License 2.0
```

还原 C 版源码：

```bash
git clone esurfing-c/esurfing-c-源码.bundle esurfing-c-src
# 或者直接解压 zip
```

## 这套程序解决什么

校园网在未认证时会拦截明文 HTTP，把请求重定向到门户。程序负责：

1. 探测是否"需要认证"；
2. 从接入设备下发的重定向里**取出门户地址**（所以不用你填）；
3. 读真实网卡的 IP / MAC / 网关作为身份；
4. 按湖南的报文格式加密、取票据、登录；
5. 心跳保活，掉线重新认证；需要时正常注销。

### 湖南与广东的机制差异

两地协议不同，这是本项目最花时间的地方：

| | 广东 | 湖南 |
|---|---|---|
| 算法协商 | 向服务端 POST Algo-ID，回 ZSM 块 | **不协商**，Algo-ID 固定 |
| 密钥 | 从服务端下发的块里取 | **本地内置** |
| 端点 | 从门户页 `campus.js` 注释块里挖 | **固定的一组 `.cgi` 名** |
| 身份 | 主要靠门户页查询串 | **真实网卡**的 IP / MAC / 网关 |
| 查询串 | `wlanuserip` / `wlanacip` | `wlanuserip` / `mscgip` / `wlanusermac` |
| 补零规则 | `ceil(L/16)*16` | `ceil((L+1)/16)*16` |

完整踩坑记录见 [`esurfing/文档/路线B-进展.md`](esurfing/文档/路线B-进展.md)。

## 从哪里开始读

| 你想知道 | 看哪 |
|---|---|
| 怎么用 Python 版 | [`esurfing/README.md`](esurfing/README.md) |
| 协议细节、踩过哪些坑 | [`esurfing/文档/路线B-进展.md`](esurfing/文档/路线B-进展.md) |
| 许可证怎么算的 | [`esurfing/文档/开源协议分析.md`](esurfing/文档/开源协议分析.md) |
| C 版怎么用、怎么编译 | [C 版仓库的 README](https://github.com/yk23311/ESurfingClient-Hunan) |

## `esurfing/工具/` 里的脚本

这些是作者自用的开发辅助脚本，**要么依赖本地环境、要么会主动断网**，
外人一般用不上，列在这里是免得你误跑：

| 脚本 | 作用 | 会不会断网 |
|---|---|---|
| `refresh_identity.py` | 刷新网卡身份写回配置 | 不会 |
| `watch_session.py` / `.bat` | 等网络自然断开，再拨回来 | 会（等它自己断） |
| `test_main_client.py` / `.bat` | 测试 C 主程序的湖南路径 | 会（故意断一次） |
| `run_full_test.bat` | `term → auth → read` 三步测试 | 会 |
| `restore_network.bat` | **兜底恢复**：把网拨回来 | 只会连回来 |

会断网的脚本自带兜底：失败时自动拉起 `restore_network.bat`。

## 许可

**Apache License 2.0**，全文见 [`LICENSE`](LICENSE)。

- **Python 版**（`esurfing/`）是本仓库作者独立写的，不含第三方代码。
- **C 版**（`esurfing-c/` 里的归档）是
  [BadGhost520/ESurfingClient-CVersion](https://github.com/BadGhost520/ESurfingClient-CVersion)
  的改造版。它的归属声明、修改清单、以及仓库内第三方组件（LZMA SDK 公有领域、
  cJSON MIT、自写 minihttp）的许可，都写在那份归档内的 `NOTICE` 里。
  上游 mongoose（GPL-2.0-only 或商业授权）已被彻底移除，改用自写的 `minihttp`。
- 两地的协议参数来自对**官方闭源客户端**的抓包分析 —— 属于互操作性研究，
  不是复制第三方源码。相应的抓包与逆向记录**不在本仓库**。

## 安全

`esurfing/config.json`（明文账号密码）与 `esurfing/session.json`（有效会话票据）
都在 `.gitignore` 里。**不要外传、不要提交。**
