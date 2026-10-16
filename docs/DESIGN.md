# HuntGuard 框架设计

> 目标：在你用 AI（或自己）做漏洞挖掘时，对**出站请求**和**命令行**做关键词级别的护栏拦截，
> 防止出现 `delete / remove / drop / rm -rf` 这类**不可逆**动作。带 Web UI，规则可随时增删。

---

## 1. 一句话定位

HuntGuard 不是"防外敌的 WAF"，而是**给自己用的出站护栏（egress guardrail）**：

* 拦截面（入口）：`curl` 命令行、Burp Suite、AI 写的 Python 脚本、本地 HTTP 代理。
* 判定方式：规则引擎 + 关键词 / 正则匹配 + 多轮归一化（URL 编码、Unicode、大小写、分隔符混淆）。
* 输出：和截图一致的 JSON（`success / blocked / reason / stage / hits[]`）。
* **激活原则：你不打开，它就不生效**（见第 3 节）。

---

## 2. 总体架构

```
                        ┌─────────────────────────────────────────┐
   入口 (4 个 frontend)  │             核心 (core)                  │
                        │                                         │
  curl  → bin/curl shim │  ┌──────────┐   ┌──────────────────┐    │
  Burp  → burp/burp_waf │→ │  Router  │ → │  Rule Engine     │    │
  AI py → waf-run/guard │  │ 统一请求  │   │ 归一化 + 关键词/  │    │
  浏览器→ waf proxy     │  │ 数据模型  │   │ 正则 + 白名单     │    │
                        │  └──────────┘   └──────────────────┘    │
                        │        │                 │              │
                        │        ▼                 ▼              │
                        │  ┌──────────┐   ┌──────────────────┐    │
                        │  │ LogStore │   │  rules.json      │    │
                        │  │ SQLite   │   │  (热重载)         │    │
                        │  └──────────┘   └──────────────────┘    │
                        └──────────────┬──────────────────────────┘
                                       │ 所有被动入口先问它
                        ┌──────────────▼──────────────────────────┐
                        │  state.py  激活态                        │
                        │  心跳文件 data/run/active.json           │
                        │  (mtime ≤ 20s = 已开启)                  │
                        └──────────────┬──────────────────────────┘
                                       ▲
                        ┌──────────────┴──────────────────────────┐
                        │  Web UI (ui/index.html)                 │
                        │  总开关 / 规则管理 / 放行名单 / 日志      │
                        └─────────────────────────────────────────┘
```

### 组件清单

| 文件 | 职责 |
|---|---|
| `waf/config.py` | 路径、端口、版本、控制台编码 |
| `waf/state.py` | **激活态**：心跳写入/刷新/判定，统一"要不要拦"的决策 |
| `waf/models.py` | `ScanTarget`（待检对象）、`Hit`（命中）、`Verdict`（结论） |
| `waf/normalize.py` | 归一化管线：URL 解码 → HTML/Unicode 反转义 → 去隐藏字符 → 去分隔符 → 小写 |
| `waf/engine.py` | 规则加载 / 热重载 / 匹配 / 白名单 / 解锁窗口 / 日志落库 |
| `waf/rules.py` | 规则增删改查、校验、默认规则、**版本迁移（rev + 内容指纹）** |
| `waf/install_path.py` | PATH 接入：cmd AutoRun / 机器级 PATH / PowerShell profile |
| `waf/logstore.py` | SQLite 事件日志 + 统计 |
| `waf/curlshim.py` | 解析 curl 参数 → 扫描 → 放行则转发真实 curl，拦截则打印 JSON 并 exit 126 |
| `waf/guard.py` | Python 运行时补丁：`requests` / `urllib` / `httpx` / `aiohttp` 出站前先过 WAF |
| `waf/runner.py` | `waf-run python x.py`：给子进程自动装 guard |
| `waf/api.py` | 本地 REST API + UI 静态服务（stdlib，无依赖） |
| `waf/proxy.py` | 本地 HTTP(S) 代理（Burp upstream / 系统代理），可选 MITM |
| `waf/certs.py` | MITM 用 CA 与按域名签发证书（`cryptography`） |
| `waf/cli.py` | `wafctl start/stop/on/off/status/doctor/check/unlock/rules/events/install-path` |
| `burp/burp_waf.py` | Burp（Jython）扩展，命中则直接返回 403，不发出真实请求 |
| `ui/index.html` | 单文件仪表盘（无构建、无 CDN） |

---

## 3. 激活态：你不打开就不生效（核心需求）

需求原文："我开启了才启用，我没打开就不要生效。"

### 判定模型

被动拦截（curl shim / 代理 / Burp 扩展）需要**两个条件同时满足**：

| # | 条件 | 存储 | 变更方式 |
|---|---|---|---|
| 1 | 控制台在运行 | `data/run/active.json` 的 mtime ≤ 20 秒 | 启动/关闭控制台自动维护 |
| 2 | 用户开关为开 | `rules.json` 的 `settings.enabled` | UI 总开关 / `wafctl on\|off` |

任一不满足 → 请求直接透传，**不检查、不记录、不打扰**。

### 心跳机制

```
控制台启动 → state.activate()   写 active.json + 起后台线程每 5s 刷新 mtime
控制台关闭 → state.deactivate() 删除 active.json
控制台被强杀 → 心跳无人刷新 → 20 秒后自动过期 → 视为未运行
```

第三行是关键：**不依赖优雅退出**。即使进程被 taskkill 或崩溃，
最多 20 秒后拦截器自动回到透传状态，不会出现"程序早关了却还在拦"。

### 显式 vs 被动

| 类型 | 入口 | 是否受开关约束 |
|---|---|---|
| **被动** | curl shim、代理、Burp 扩展 | 是（需两个条件） |
| **显式** | `waf-run`、`wafctl check`、自己 import `waf.guard` | 否 —— 主动调用本身就是"我要开启" |

显式路径若也想跟随开关：`install_guard(follow_console=True)`。

### PATH 优先级的坑（必须修）

Windows 组合 PATH 时是 **机器级 + 用户级**，且机器级在前：

```
机器级: ... ; C:\WINDOWS\system32 ; ...        ← 真实 curl.exe 在这里，先命中
用户级: D:\agent-waf\bin ; ...                 ← 只写用户级 = 永远轮不到
```

所以 `install_path` 按通道分别接入，可靠性递减：

| 通道 | 机制 | 覆盖对象 |
|---|---|---|
| **machine** | 机器级 PATH 最前（需管理员） | 所有进程（最可靠） |
| **cmd_autorun** | `HKCU\...\Command Processor\AutoRun` | cmd 窗口；AI 用 `shell=True` 起的 cmd |
| **bash_env** | `BASH_ENV` + `~/.bashrc` | **非交互 Git Bash** —— ZCode / Claude Code / Codex 执行命令的主路径 |
| **powershell** | profile 删 curl 别名 + 前置 PATH | PS 交互式会话（PS5.1 与 PS7 都装） |
| **python_hook** | `PYTHONPATH` 指向 `<root>/hooks`（内有 sitecustomize.py） | **所有 Python 进程** —— AI 写的 requests 脚本 |

`wafctl doctor` 会分别探测 cmd 与 Git Bash 的解析结果，并做路径归一化
（`/d/agent-waf/bin` 与 `D:\agent-waf\bin` 视为同一目录）。

### 为什么必须用 BASH_ENV 而不是 .bashrc

AI 工具执行命令用的是 `bash -c "..."` —— **非交互 shell**。
非交互 bash 不读 `~/.bashrc`，只读 `BASH_ENV`。实测：

```
$ bash -c 'which curl'                              # 默认
/mingw64/bin/curl                                   # 原生 curl，绕过拦截器

$ BASH_ENV=D:\agent-waf\bin\waf-bash-env.sh bash -c 'which curl'
/d/agent-waf/bin/curl                               # 命中拦截器 ✓
```

`waf-bash-env.sh` 的硬性要求：**静默**（输出会污染调用方脚本）、
**幂等**（重复 source 不累积 PATH）、**极快**（每次 bash 启动都跑）。
`bin/curl` 的 bash shim 另有一条快速路径：WAF 关闭时直接 exec 真实
curl，不启动 Python —— 保证"没开就不打扰"。

### 历史：为什么曾经需要 import 钩子兜底（.pth 时代）

`.pth` 在 site 初始化阶段执行，那一刻 `import requests` 可能失败
（依赖尚未就绪）。此时安装会"部分成功"：urllib/subprocess 打上了，
requests 没有 —— 而 guard 的 `_installed` 位已置，后续调用只会返回
`['already']`，requests 的补丁就永远不会生效。

`autohook` 的处理：装完立即自检 `requests.Session.request` 是否真被
替换；没打上就保留 `__import__` 钩子，等宿主真正 import requests 时
再次强制安装，成功后摘掉钩子（不留开销）。

### 装机幂等性

profile 类接入反复安装必须不累积 —— 否则用户跑两次 `install.bat`
就会得到两份区块，PATH 越加越长。`_is_our_profile_line()` 按特征行
识别所有历史形态（标记注释、别名清理行、对应 bin 目录的 PATH 前置行），
先全部剔除再写入唯一区块。有测试守着这条不变量。

### 完全自包含（所有文件都在安装目录内）

早期版本会把文件写到外面：`.pth` 和引导器进系统 site-packages、
PowerShell 逻辑进用户 profile。问题是删掉项目目录后系统里留残留，
别人也搞不清哪些文件是自己装的。现在改成：

| 组件 | 之前 | 现在 |
|---|---|---|
| Python 钩子 | site-packages 里两个文件 | `<root>/hooks/sitecustomize.py` + `PYTHONPATH` 指针 |
| PowerShell 逻辑 | 全部写进用户 profile | `<root>/bin/waf.ps1`，profile 只留一行指针 |
| 调试日志 | `%TEMP%` | `<root>/data/logs/` |

外部只允许存在**指针**（不含逻辑）：

* 三组环境变量：`HUNTGUARD_HOME`（主指针，兼容旧名 `AGENTWAF_HOME`）、
  `BASH_ENV`、`PYTHONPATH`
* 一个注册表值：`HKCU\...\Command Processor\AutoRun`
* PowerShell profile 里的**一行**：`. "$env:HUNTGUARD_HOME\bin\waf.ps1"`
* `~/.bashrc` 里的**一行**：指向 `bin/waf-bash-env.sh`
* （MCP 集成已移除：它是把护栏钥匙交给 AI，见 USAGE.md 对应章节）

`wafctl audit` 把全部足迹列出来，`wafctl uninstall-path` 一键清干净。

### 为什么从 .pth 换成 sitecustomize（现状说明）

Python 启动时会自动 `import sitecustomize`（只要它在 `sys.path` 上），
效果与 `.pth` 相同，但文件可以留在自己的目录里（靠 `PYTHONPATH`
指过去）。

副作用是：我们占用了 `sitecustomize` 这个名字，别人装的同名文件
就轮不到被自动 import。所以钩子里做了**链式调用** —— 先扫描
`sys.path` 找出其它位置的 `sitecustomize` 并执行，再装自己的护栏。
有测试守着这条（`test_hook_chains_other_sitecustomize`）。

### 自动探测：别人的机器上路径不一样

`waf/autodetect.py` 在安装时（以及首次调用 shim 时）探测并缓存：

* Python 解释器（含 `py` 启动器、用户级安装目录）
* **真实 curl** —— 用文件头判断（PE 二进制 vs 我们的 shim 脚本），
  能识别出**其它安装的 shim**，避免探测到自己造成转发递归
* Git Bash（优先 `<Git>\bin\bash.exe`，排除 WSL 的）
* PowerShell / cmd

结果写到 `data/detected.json` + `data/env.cmd` + `data/env.sh`
（后两个是 `set VAR=value` 格式，shim 直接 `call` / `source`，
不需要解析 JSON）。于是**别人不需要填任何路径**。

---

## 4. 数据流（一次拦截是怎么发生的）

```
入口构造 ScanTarget
   ├─ kind=curl  : raw_cmd / method / url / path / query / headers / body
   ├─ kind=request(Burp) : method / url / path / query / headers / body
   ├─ kind=http  : 原始 HTTP 报文 → 解析同上
   └─ kind=text  : 纯文本（测试台 / 脚本片段）
        ↓
state.should_intercept(engine)      # ← 先问"我开了吗"
   ├─ 未开启 → 直接透传（不进入引擎）
   └─ 已开启 ↓
Engine.scan(target)
   1) reload_if_changed()          # rules.json mtime 变了就热重载，UI 改完立即生效
   2) 对每个 source 文本做 normalize.build_variants_with_map()   # 最多 ~8 个变体
   3) 遍历 enabled 规则 → 关键词/正则匹配 → 生成 Hit
      （关键词与正则同时生效：match_mode 只决定关键词的匹配方式）
   4) 命中窗口 ±24 字符内若匹配 rule.exclude → 丢弃该 Hit（误报抑制）
   5) allowlist 命中 → source=url/host 视为请求级放行；其它为字段级跳过
   6) 解锁窗口有效期内的命中 → 降级为 monitor（不拦但仍记录，打 tag=unlocked）
   7) mode=monitor 的规则只记录不拦
        ↓
Verdict{blocked, reason, stage, hits[]}  →  JSON（截图同款）
        ↓
LogStore.add(event)   →  UI 事件流 / 统计
```

### 判定优先级
1. `critical/high` 且 `action=block` 的 Hit → 拦截；
2. 全局 `settings.mode=monitor` → 全部只记录（紧急"只读模式"开关）；
3. 解锁窗口内 → 只记录；
4. 其余 → 放行。

---

## 5. 规则模型（rules.json）

```jsonc
{
  "version": 1,
  "defaults_rev": 4,               // 内置规则版本，用于自动迁移
  "removed_defaults": [],          // 用户删掉的内置规则（不再复活）
  "settings": {
    "enabled": true,               // ★ 总开关（配合心跳决定是否拦截）
    "mode": "block",               // block=拦截  monitor=全局只读
    "case_sensitive": false,
    "normalize": ["url_decode","html_unescape","unicode_unescape",
                  "strip_invisible","collapse_ws","compact","lower"],
    "scan_headers": true,
    "max_scan_bytes": 262144,
    "fail_mode": "closed",         // 引擎异常时：closed=拦截 open=放行
    "log_allowed": false,
    "unlock_until": 0,
    "unlock_reason": ""
  },
  "allowlist": [                   // 放行名单
    { "id":"A-001","enabled":false,"source":"url",
      "pattern":"127\\.0\\.0\\.1[:/].*", "note":"本机靶场（默认关闭）" }
  ],
  "rules": [
    {
      "id": "R-105",
      "name": "短删除指令 del / rm（词边界精确匹配）",
      "enabled": true,
      "severity": "critical",      // critical|high|medium|low|info
      "action": "block",           // block|monitor
      "sources": [],               // 空 = 全部字段（默认）。只有排误报时才缩小
      "match_mode": "word",        // substring|word|regex（只作用于 keywords）
      "keywords": ["del","rm","rmdir","dels","delall","rmall"],
      "regex": [],                 // 与 keywords 同时生效
      "exclude": [],               // 命中点 ±24 字符内的正则 → 丢弃该命中
      "note": "del / rm 是核心删除命令与常见 URL 路径段",
      "_builtin_hash": "a1b2c3d4e5f60718"   // 内容指纹，用于升级时判断用户是否改过
    }
  ]
}
```

匹配语义：
* `match_mode=substring`：归一化后包含关键词即命中（覆盖 `delete.php`、`?delete=`）。
* `match_mode=word`：词边界匹配（`(?<![a-z0-9_])del(?![a-z0-9_])`）。
  让 `del` 命中 `/del/a.txt`、`?op=del`，同时**不**命中 `model`/`delay`/`order`。
* `match_mode=regex`：`regex` 数组里的表达式；`keywords` 仍按 substring 生效。
* **关键词与正则同时参与匹配**，所以"关键词兜底 + 正则精确"可以共存。
* **空 ``sources`` = 全部字段**（URL/路径/参数/请求体/请求头/方法/主机/命令行）。
  这是默认值，也是安全的选择 —— 漏勾字段就是漏拦。留空而非展开成完整列表，
  这样以后新增扫描维度时，老规则自动覆盖到。缩小范围是"排误报"的高级手段。

### 内置规则自动迁移

`data/rules.json` 一旦存在，就不会被新版覆盖。为了把新增/修正的内置规则
送到老用户手里，采用了版本号 + 内容指纹的方案：

| 情况 | 处理 |
|---|---|
| 内置有、文件没有 | 补齐 |
| 内置规则升级，且**用户没改过**（指纹一致） | 用新模板覆盖，保留开关状态 |
| 内置规则升级，但**用户改过**（指纹不一致） | 保留用户版本，不动 |
| 用户删除了某条内置规则 | 记入 `removed_defaults`，不再复活 |

历史文件（无指纹）退化为"子集判断"：若现有内容含模板里没有的关键词，
说明是用户自己加的 → 不覆盖。

---

## 6. 四个入口的接入方式

| 入口 | 接入方式 | 拦截效果 |
|---|---|---|
| **curl** | `wafctl install-path`（cmd AutoRun，免管理员） | 不执行真实 curl，打印截图同款 JSON，退出码 126 |
| **Burp** | ① 首选：Burp 扩展 `burp/burp_waf.py`（Jython）→ 请求发出前返回 403；② 备选：Burp → Upstream Proxy → `127.0.0.1:8899` | 请求根本到不了目标 |
| **AI 脚本** | `waf-run python exp.py`，或脚本内 `import waf.guard; waf.guard.install_guard()` | 命中抛 `WafBlocked` 异常并打印 JSON |
| **代理/其他工具** | `wafctl start --proxy`，工具里设 HTTP 代理 `127.0.0.1:8899`（HTTPS 需 `--mitm` + 导入 CA） | 返回 403 + JSON |

四个入口**共用同一个激活判定**：控制台没开，全都不拦截。

---

## 7. 逃生通道（可控、可审计）

| 机制 | 用途 | 风险控制 |
|---|---|---|
| **总开关** | 整体暂停拦截 | UI 一键；透传不记录 |
| 规则开关 | 临时停用某条规则 | UI 一键，写回 rules.json |
| 放行名单 | 靶场域名/`deleted_at` 参数放行 | 正则 + source 维度 |
| 全局只读模式 | 需要观察全部流量时 | 仍记录但全不拦 |
| `wafctl unlock --minutes 10 --reason "..."` | 明确要测 `delete` 接口时的限时解锁 | 到期自动恢复；事件打 `unlocked` 标记；UI 顶部倒计时横幅 |

> 定位说明：这是**护栏**（防手滑、防 AI 误操作），不是安全沙箱。AI 仍可绕过
> （删注册表项、`WAF_DISABLE=1`）；但绕过需要显式的、被记录的、多步的操作 ——
> 这正是"控制风险"要的效果。

---

## 8. 实施阶段（本次已实现 / 后续可扩展）

* P0（已实现）：引擎 + 规则 + curl shim + Burp 扩展 + API/UI + 日志 + 解锁 + 测试
* P1（已实现）：代理模式（HTTP 全量检测、CONNECT 透传、可选 MITM + CA 签发）+ Python guard
* P2（已实现）：**激活态心跳**（"我开了才生效"）、**PATH 接入管理**
  （cmd AutoRun / 机器级 PATH）、**内置规则版本迁移**（内容指纹保用户定制）、
  **删除变种规则扩展**（R-105/R-106）
* P3（路线图）：Shell（PowerShell/cmd）命令包装、规则导入导出、按 host 的规则组、
  请求速率熔断、AI 会话级审计报告
