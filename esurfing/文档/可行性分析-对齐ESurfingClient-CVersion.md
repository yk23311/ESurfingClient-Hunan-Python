# 湖南天翼脚本 → 对齐 ESurfingClient-CVersion：可行性分析

> 分析对象：本目录 `run.py`（湖南，1499 行单文件 Python）
> 参照项目：`Rsplwe/ESurfingClient-CVersion`（广东，纯 C，README 称 200–300 kB）
> ⚠️ **仓库关系更正**：你给的链接是一个 **fork**（1 star / 0 fork，最后提交 2026-09-14，无 release）。
> 它的**上游主仓库**是 **[BadGhost520/ESurfingClient-CVersion](https://github.com/BadGhost520/ESurfingClient-CVersion)**
> （137 star / 27 fork，最后提交 2026-10-08，Active）。**要动手请用 BadGhost520 那个。** 两者都是 Apache-2.0。
> 另注：README 说 C 版是照 Rsplwe 的 **Kotlin** 源码写的 —— Rsplwe 是最初 Kotlin 版的作者，C 版的 upstream 是 BadGhost520。
> 分析方式：实际拉取参照项目源码逐文件核对 + 本机运行 `run.py selftest` + 真实网络环境探测

---

## 一、结论先说

**能对齐，但"像那个项目"必须拆成三件成本差 10 倍的事：**

| 想要的"像" | 成本 | 值不值 |
|---|---|---|
| **工程形态**：跨平台、常驻后台、Web UI、多账号、日志轮转、CI | 中（1–3 天） | 看你是否要上路由器 |
| **协议健壮性**：补上 ZSM 算法协商 | 高（2–4 天），且是唯一真正的**正确性**风险 | 值得，但可以等 |
| **语言迁移**：把 Python 改写成 C | 很高，且会丢东西 | **不建议** |

**一个必须先纠正的前提**：这两个客户端**不是同一套协议**，C 项目不能直接拿来在湖南用。但它俩确实是**同一套协议族**（同一家厂商平台，XML 字段名几乎逐个对得上）——所以值得考虑的路可能是**第三条**：不是把 1499 行 Python 改成 C，而是**改 C 项目的会话层来适配湖南**。

⚠️ 但这条路**不像我一开始以为的那么便宜**：两侧端点的**获取方式**不同（广东从门户网页里发现，湖南是写死的 `.cgi`），细节见 **2.3**。

---

## 二、前提纠正：它们不是同一个协议

我把两个客户端的线上行为逐项核对了一遍：

| 项目 | 广东（C 项目） | 湖南（你的脚本） |
|---|---|---|
| 门户地址 | `14.146.227.141:7001`（另有备用 `121.8.177.212:7001`） | `175.12.104.1:10001`（**无备用**） |
| `Algo-ID` | **24 个 UUID**（15 生效 / 9 注释），部分由服务端运行时下发 | 固定 `FAB1DCDE-2D24-41CD-8510-2416DC7854CF` |
| 密钥来源 | `KeyData.h` 按 UUID 命名硬编码（12 组） | `run.py:80-82` 硬编码 K1/K2/IV |
| 算法协商 | **有**：服务端下发 ZSM 模块，客户端解包 | **无**：静态 |
| `Content-Type` | `application/x-www-form-urlencoded` | `application/octet-stream` |
| 请求头 | `CDC-Checksum`/`Algo-ID`/`Client-ID` + `cdc_sid`/`cdc_d`/`cdc_a` | 同名前 3 个 + `User-Agent` + `Content-Type` |

**共同点（证明是同一套平台）**：`CDC-Checksum`（body 的 MD5）、`Algo-ID`、`Client-ID` 三个请求头**名字完全一致**；都是「XML → 两层加密 → 大写 hex」；都有 `ticket`/`auth`/`state`/`keep`/`term` 这套会话概念。

### 2.1 决定性证据：C 项目里没有湖南那一档

参照项目的算法选择逻辑是：

```c
// esurfingclient/main/src/cipher/CipherFactory.c
static cipher_interface_t* create_cipher_factory(const char* algo_id)
{
    if (!algo_id) return NULL;
    // ... 24 个 strcmp 分支（15 生效 + 9 注释）：Algo-ID UUID → 算法实现 + 该 UUID 的密钥
    if (strcmp(algo_id, "1A7343EC-7F9B-4570-BF58-16279A81116B") == 0)
        return create_desede_cbc_linux_cipher(
            key1_1A7343EC_..., key2_1A7343EC_..., iv1_1A7343EC_..., iv2_1A7343EC_...);
    ...
}
```

我实际拉下这个文件核对：**生效分支 15 个、注释掉 9 个，其中没有 `FAB1DCDE-2D24-41CD-8510-2416DC7854CF`**。

所以：

- **把 C 项目原样拿到湖南 → 用不了。** 不是改配置能解决的，是缺一整档算法+密钥。
- 补这一档本身不难（就是一个 `strcmp` 分支 + 一组常量），**但算法不是唯一要改的地方** —— 见 2.3，以及第五节路线 B 的修正成本。

### 2.2 广东走的是服务端驱动，湖南走的是静态约定

C 项目的 `DialerClient.c:373 load_cipher()` 揭示了完整机制：

```
POST ticket_url（body = Algo-ID）返回 ZSM 块
  ├─ 若像 iOS/macOS 模块（TEA+LZMA 压缩的 JS）→ init_ios_cipher_from_zsm() 解出**动态密钥**
  ├─ 否则 → extract_algo_id_from_zsm() 抽出 Algo-ID → init_cipher(algo_id) 查上面的表
  └─ 都失败 → 回退 CipherFactory
拿到 Algo-ID 后 → 写进后续请求的 `Algo-ID:` 头（NetClient.c:400）
```

**这正好解释了你的脚本为什么能跑**：湖南门户目前**不下发 ZSM**，直接给明文票据，所以 `Algo-ID` 由客户端自己定死即可。你的脚本 `run.py:75` 把它写成了常量。

**也正好暴露了你的脚本唯一的硬伤**：`run.py:601` 只判断「响应体前 3 字节是不是 `001`」，一旦服务端真的下发 ZSM 模块：

- `run.py:732` → `"服务端下发的是算法模块而不是 ticket（本实现未做算法协商）"`
- `run.py:954` → 直接 `return False`

即 **Hunan 侧一旦启用算法协商，脚本立刻失效，且无法自救**。这是协议级单点，不是工程问题。

### 2.3 更关键的差异：端点从哪来（这条改写了路线 B 的成本）

我原本以为两边只差「门户地址 + 密钥」。**核对了 `DialerClient.c` 之后发现不是** —— 端点的**获取方式**根本不同：

```c
// DialerClient.c:500-536  —— 广东：端点是从门户网页里"挖"出来的
const char portal_start_tag[] = "<!--//config.campus.js.chinatelecom.com";
const char portal_end_tag[]   = "//config.campus.js.chinatelecom.com-->";
char* portal_config = extract_between_tags(resp.body_data, portal_start_tag, portal_end_tag);
char* auth_url   = xml_parser(portal_config, "auth-url");     // :518
char* ticket_url = xml_parser(portal_config, "ticket-url");   // :536
char* client_ip  = extract_url_param(cleaned_ticket_url, "wlanuserip");  // :554
char* ac_ip      = extract_url_param(cleaned_ticket_url, "wlanacip");    // :564
// 而 keep-url / term-url / keep-retry 来自 auth 响应的解密 XML（:166/:186/:206）
```

| | 广东（C 项目） | 湖南（你的脚本） |
|---|---|---|
| 门户从哪来 | `generate_204` 探测的 **302 Location** | 硬编码 `175.12.104.1:10001` |
| 端点从哪来 | **门户网页 CDATA 块里发现** `auth-url`/`ticket-url` | **固定写死** `ticket.cgi`/`auth.cgi`/`state.cgi`… |
| 身份参数 | 塞在被发现的 `ticket_url` 自身的查询串里（`wlanuserip`/`wlanacip`） | 每次自行拼 `wlanuserip`/`mscgip`/`wlanusermac` |
| `ticket` 取几次 | **两次**：先 POST Algo-ID 换 ZSM，再 POST 加密 XML | **一次** |
| `state` 端点 | 未见（靠 login 响应给的 keep/term URL） | 有 `state.cgi` |

**好消息**：XML 字段集几乎完全一致（`user-agent`/`client-id`/`local-time`/`host-name`/`ipv4`/`ipv6`/`mac`/`ostag`/`gwip`/`ticket`/`userid`/`passwd`），说明确实是同一协议族。
**坏消息**：**这不像"加一行配置"，而像"换掉会话建立那一层"。** 我原先给路线 B 的 2–5 天偏乐观。

---

## 三、能力对照表（完整差距清单）

| 能力 | C 项目 | 你的脚本 | 差距性质 |
|---|---|---|---|
| **算法协商 ZSM** | ✅ TEA+LZMA 解包 / Algo-ID 提取 / 动态密钥 | ❌ 遇到即报错 | **协议·高风险** |
| 门户容灾 | ✅ 主+备 两个 IP | ❌ 单 IP 硬编码 | **协议·中风险** |
| 跨平台 | ✅ Win/Linux/macOS/OpenWrt 数十种架构 | ⚠️ 仅 Windows | 工程·中 |
| 后台常驻 | ✅ Windows 服务 + procd/init.d | ❌ 前台，Ctrl+C 就停 | 工程·中 |
| 开机自启 | ✅ | ❌ 要手动双击 | 工程·小 |
| Web UI | ✅ mongoose `0.0.0.0:8888` + REST + 前端 | ❌ | 工程·中 |
| 非交互配置 | ✅ JSON，**多账号** + **定时窗口** | ⚠️ 首次要输账号密码，单账号 | 工程·小 |
| 日志 | ✅ 分级 + 轮转 + 跨平台路径 | ⚠️ 单文件，每次覆盖 | 工程·小 |
| 体积/依赖 | ✅ 200–300 kB，无运行时依赖 | ❌ 需 Python 3.8+ 与 pycryptodome | **部署·大** |
| CI/发布 | ✅ 8 个 GitHub Actions 工作流 | ❌ 无（且目录不是 git 仓库） | 工程·小 |
| **网络诊断** | 一般 | ✅ **明显更强** | **你的脚本赢** |

### 3.1 你的脚本在诊断上反而更强

这一点很重要，因为它是「不要重写成 C」的核心理由。`run.py` 里有而 C 项目**没有**的：

- `_enumerate(include_down=True)`：把**没有链路的网卡**也列出来（区分"网线掉了"和"程序坏了"）
- `first_hop()`：查路由表拿第一跳，不发包
- `in_campus()`：网关可达 → 第一跳一致 → 网段辅助，三级判据
- `path_hint()`：认证失败时解释**真实出口**走的是哪条路
- 区分 `102/1025`（不在校园网）与 `102/902`（**在校园网内也会出现**，原因未定）

C 项目对应位置只有一个 `generate_204` 探测。更极端的是我核对源码后的发现：

- **它不读真实网卡 MAC** —— `States.c` 的 `reset_mac_addr()` 用 `get_rand_bytes()` 随机生成（`mac[0] &= 0xFE`）；
- **它没有任何网关查询代码** —— `<gwip>` 填的是从 `ticket_url` 里挖出来的 `wlanacip`；
- `get_adapters()` 是它**唯一**真正的系统网络调用，而且只服务于 Web UI。

也就是说，**在"这台机器到底从哪个网口、以什么身份上网"这件事上，那个 C 项目基本是盲的**；你的脚本却把它当作一等公民。**逐行翻译成 C 会把这些丢掉。**

---

## 四、Python 侧的真实短板（按优先级）

**P0 — 协议**
1. **ZSM 未实现**（`run.py:601/732/954`）。唯一"将来会坏且坏了没法查"的点。
2. **门户单 IP**（`run.py:71`）。`175.12.104.1` 变了就全废，C 项目有主备两个。

**P1 — 可靠性**
3. **无单实例保护**。`keepalive.lock` 只在 `logout()` 里被读（`lock_alive()`），`cmd_dial()` 启动时不检查 → **双击两次 `启动拨号.bat` 会跑起两个保活循环**，互相抢票、重复认证。
4. **无常驻/自启**。重启后必须记得双击。

**P2 — 工程**
5. Windows 绑定集中在 5 个函数（约 150 行）：`_enumerate`、`wifi_ssid`、`first_hop`、`gateway_alive`、以及 `run.py:234` 的 DLL 加载。其余（编解码、Portal、Session、配置）已天然跨平台，`http.client` 的 `source_address` 在 Linux/macOS 同样可用。
6. 明文密码存 `config.json`。
7. 日志无轮转，`last.log` 每次覆盖。

**文档漂移（顺手修）**
- `README.md:39` 说"1 个文件 39 KB"，实际 `run.py` 已是 **61,097 字节**。
- `README.md:12` 列了 `requirements.txt`，**该文件不存在**。

---

## 五、三条路线

### 路线 A：保住 Python，补齐工程形态
> 适合：只想在 Windows 上稳定省心

1. `cmd_dial()` 启动时查 `lock_alive()`，活着就拒绝启动（约 15 行）
2. 加 Windows 计划任务/服务自启，或 `启动拨号.bat` 里带后台模式
3. 门户主备列表 + 失败自动切换
4. 日志按天轮转
5. 非交互配置（支持多账号 + 可选定时窗口）
6. 跨平台层（若确定要 Linux/macOS）：抽 `_enumerate`/`first_hop`/`wifi_ssid`/`gateway_alive` 四个函数

**成本 1–2 天。零协议风险。**

### 路线 B：改 C 项目做湖南版
> 适合：想上路由器 / 软路由 / OpenWrt（这正是 C 项目存在的意义）

**先说修正**：我最初的判断是"加一档 Algo-ID 就行"，核对完 2.3 之后**这个判断偏乐观**。实际要动五处：

1. **端点层**（主要工作量）：给广东那套"从门户网页发现 URL"的逻辑加一条湖南分支 —— 固定 `ticket.cgi`/`auth.cgi`/`state.cgi`/`keep.cgi`/`term.cgi`，并自行拼接 `wlanuserip`/`mscgip`/`wlanusermac` 查询串。
2. **会话建立流程**：广东 `ticket_url` 要 POST 两次（先 Algo-ID 换 ZSM，再加密 XML）。湖南只需一次，且必须**跳过 ZSM 拉取**，否则第一步就白跑。
3. **算法表**：`CipherFactory.c` 加一个分支 + `KeyData.h` 加常量：
   ```c
   if (strcmp(algo_id, "FAB1DCDE-2D24-41CD-8510-2416DC7854CF") == 0)
       return create_aes_cbc_linux_cipher(
           key1_FAB1DCDE_..., key2_FAB1DCDE_..., iv1_FAB1DCDE_..., iv2_FAB1DCDE_...);
   ```
   密钥取 `run.py:80-82` 的 K1/K2/IV（湖南两层 CBC 用**同一个 IV**，即 `iv1 == iv2`）。
4. **身份采集**：⚠️ **C 项目根本不读真实网卡 MAC** —— `States.c` 的 `reset_mac_addr()` 是 `get_rand_bytes()` **随机生成**的，而且**没有任何网关查询代码**（`<gwip>` 填的是从 `ticket_url` 里挖的 `wlanacip`）。你的脚本是 `GetAdaptersAddresses` 读**真实**网卡 IP/MAC/网关。**湖南门户是否校验真实 MAC 未知** —— 若校验，就得把真实的网卡枚举也移植过去（Linux 用 `getifaddrs`）。这是本路线**最大的未知数**。
5. 核对 `Content-Type`（广东 `x-www-form-urlencoded` / 湖南 `octet-stream`）与额外请求头。

**成本修正：3–7 天**（熟悉 C 的前提下；主要不确定性在第 4 点）。
换来的是：单文件二进制、Windows 服务自启、OpenWrt 一键装、Web UI、多账号、定时拨号。

> 💡 顺带一提：同类项目还有 [Pandaft/go-esurfing](https://github.com/Pandaft/go-esurfing)（Go，24 star，**GPL-3.0**，2024 年后未更新）。
> 若你更愿意碰 Go 而不是 C，它的交叉编译体验更好，但**许可证是 GPL-3.0**，传染性比 Apache-2.0 强，且已停更。

> ⚠️ 这条路要注意：那 15 个生效的广东 Algo-ID 与其密钥是别人的研究成果；改动后**不要**把你的湖南密钥回传到公共仓库。
> 许可证已核实为 **Apache-2.0**（可自由 fork/修改，需保留版权与变更声明）。

### 路线 C：Python 补 ZSM 算法协商
> 适合：想把协议风险彻底关掉，且暂时不换语言

需要移植：`IosZsm.h` 的容器识别 + TEA 解密 + LZMA 解压 + JS 模块里的密钥提取，再接到现有 `decrypt()` 前。
**成本 2–4 天，是三条路里最难的一块，而且只在湖南真的启用协商时才有用。** 建议先放着，等出现 `Error-Code=200` 或"服务端下发算法模块"再动。

---

## 六、我的建议

**别做的事：把 1499 行 Python 逐行翻译成 C。**
你会丢掉 `path_hint`/`env_report`/`in_campus` 这套诊断（第三节 3.1），换来一个你已经有的东西——能上网。投入产出比最差。

**按目标二选一：**

| 你的目标 | 走哪条 | 一句话 |
|---|---|---|
| 就这台 Windows 电脑，稳定上网 | **A**（只做 P0-1 单实例 + 自启 + 门户主备） | 半天，风险为零 |
| 想让路由器/软路由自己拨，或宿舍多设备 | **B** | 协议族相通，但**端点层要重写**，见 2.3 —— 不是加一行配置 |
| 担心哪天突然认证不了 | **C**，但**等真的坏了再做** | 现在做是过度设计 |

**共通的第一步（无论选哪条，都建议先做）**：把单实例保护和门户主备补上。这两条各十几行，是当前脚本里唯一"会自己坏掉"的地方。

---

## 七、验证基础

本次分析的可复现证据：

- `py -3 run.py selftest` → **6/6 通过**（加解密往返、5 个官方样本长度公式、288 字节真实样本逐字节往返、Error-Code 大小写、注销报文 608 字节、垃圾输入不误判）
- `last.log` 记录了 2026-10-09 的真实认证：`ticket/auth/state/keep` 四步全部 `Error-Code=0`，源 `100.67.199.113`
- 本机当前**确实在湖南校园网内**：以太网 100.67.199.113 有链路、网关 100.67.192.1 ICMP 可达、第一跳一致 → **端到端改造后可以直接真机验证**
- 参照项目的 `CipherFactory.c`/`DialerClient.c`/`NetClient.c`/`WebServer.c`/`Service.c`/`PlatformUtils.c`/`ESurfingClient.json` 均已拉取源码逐项核对（非凭印象）
- **第二轮复核（针对本文档的更正）**：`DialerClient.c:500-564` 的端点发现逻辑、`KeyData.h` 密钥组数、
  `.github/workflows` 工作流数量、LICENSE、以及上游/ fork 关系，均已再次直接从源码与 GitHub API 核实

> 📌 **本文档已修订过一次**。最初我把路线 B 估成「加一档 Algo-ID 就行」（2–5 天），
> 核对 `DialerClient.c` 的端点发现逻辑后修正为「端点层要重写」（3–7 天），见 2.3 与路线 B。
> 同时更正了仓库关系（Rsplwe 是 fork，upstream 是 BadGhost520）。

> 参照项目的 `ESurfingClient.json` 结构也值得借鉴（这是你脚本目前没有的）：
> `enabled` / `log_lv` / `accounts[]`，每个账号含 `username` / `password` / **`channel`** / `mark` / **`time_windows[]`**。
> `channel` 是 **UA/主机名通道**（1=Windows〔源码里未实现，回退 Android〕/ 2=Linux / 3=Android / 4=iOS / 5=macOS）——
> 它**不直接决定密钥**（源码注释：*"通道号只决定 UA/主机名, 不决定密钥解包方式"*），但会改变服务端下发什么，从而间接决定算法。
> `time_windows` 是定时拨号窗口（格式如 `{"start":"mon 08:13","end":"mon 23:57"}`，最多 16 条）；`mark` 是 OpenWrt 多拨用的 `SO_MARK`。

---

## 附：安全提醒

`config.json`（明文账号密码）与 `session.json`（有效会话票据）**都不要外传**。
若走路线 B，改造产物里同样会带上湖南密钥与门户地址——发到公开仓库前请先脱敏。

**⚠️ 若要照搬 C 项目的 Web UI 设计，先看这条**：它的 Web 服务监听 `http://0.0.0.0:8888`，
**没有任何认证/令牌/CORS 处理**，而 `GET /api/getConfigs` 会**明文返回账号密码**，
`POST /api/applyConfigs` 能重启进程。也就是说**同网段任何人都能读到你的密码并让程序重启**。
你自己加 Web UI 时，至少改成监听 `127.0.0.1`，或加一层令牌。

（另外：那个 C 项目全程**纯 HTTP、无 TLS**（libcurl 是 `--without-ssl` 编的），密码只靠会话密码学保护——
这一点和你的脚本一样，属于该平台的固有性质，不是它的缺陷。）
