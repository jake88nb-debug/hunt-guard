# HuntGuard

**An outbound guardrail for authorized security testing.**
It blocks irreversible operations — `delete`, `remove`, `del`, `rm -rf`, `drop`,
`truncate` — before they reach the target, so a typo or a misbehaving AI agent
can't destroy the thing you're testing.

> Works out of the box: download, double-click `start.bat`, done.
> No path configuration, no `pip install`, no admin rights, **stdlib only**.
> **Nothing runs unless you start it** — close the console and every command
> passes straight through, unchecked and unlogged.

```
1. install.bat    one-time setup (auto-detects Python / curl / Git Bash)
2. start.bat      console opens, interception goes live
3. stop.bat       interception is off again — curl back to normal
```

---

给你自己用的**出站护栏**。挖洞时拦住 `delete` / `remove` / `drop` / `rm -rf` 这类
不可逆动作，防止手滑或 AI 误操作把目标打坏、把本地删干净。

命中后行为和你截图里完全一致：

```json
{
  "success": false,
  "blocked": true,
  "reason": "命中敏感词，请求已被拦截",
  "stage": "content_scan",
  "hits": [
    {
      "source": "query",
      "keyword": "delete",
      "matched_text": "delete=test.txt",
      "rule_id": "R-101",
      "rule_name": "删除 / 销毁类操作（不可逆）",
      "severity": "critical",
      "action": "block",
      "offset": 23
    }
  ]
}
```

> `matched_text` 给的是**命中点前后各 20 字符**的片段（不是整个 URL），
> 这样一眼能看出是哪个参数触发的；每个命中还带 `source`
> （url / query / body / headers / raw_cmd…）和 `offset`（原文位置）。

---

## 下载后怎么用（三步）

```
方式一：GitHub 页面 → Code → Download ZIP → 解压
方式二：git clone https://github.com/jake88nb-debug/hunt-guard.git
```

解压到**任意目录**都行，文件夹叫什么都不影响 —— 所有路径自动探测。

| 步骤 | 操作 | 说明 |
|---|---|---|
| 1 | 双击 `install.bat` | 自动找一个叫 Python 的解释器 + 探测真实 curl / Git Bash 位置，写入全部接入。**只需一次** |
| 2 | 双击 `start.bat` | 控制台启动、浏览器自动打开，**拦截开始生效** |
| 3 | 双击 `stop.bat` | 停止。拦截立即失效，curl 恢复原样 |

> 第 1 步也可以跳过：直接双击 `start.bat`，它会自动补装。

**唯一前置条件**：装了 Python 3.7+（[下载](https://www.python.org/downloads/)），
安装时**务必勾选 "Add python.exe to PATH"**。没有它 `start.bat` 会明确提示怎么装。

## 环境要求

| 项目 | 要求 |
|---|---|
| 系统 | **Windows 10 / 11**（主力支持）；Linux / macOS / WSL 可用命令行部分，见 [其它平台](#其它平台linux--macos--wsl) |
| Python | **3.7 或更高**（[下载](https://www.python.org/downloads/)；安装时**务必勾选 "Add python.exe to PATH"**） |
| 第三方库 | **无**。只用 Python 标准库，不需要 `pip install` |
| 权限 | **不需要管理员**。只有想让全局所有进程都覆盖时才需要 |
| 磁盘 | 约 1 MB（外加少量运行日志） |

📌 **唯一的前置条件就是 Python。** 没有它 `start.bat` 会明确提示怎么装。
其它路径（真实 curl、Git Bash、PowerShell 的位置）全部自动探测，你不用填。

## 端口

控制台启动后会在窗口里打印地址，默认如下（**固定端口，不改就用这两个**）：

| 用途 | 地址 | 说明 |
|---|---|---|
| 控制台 / 网页界面 | `http://127.0.0.1:8898` | `start.bat` 会自动打开浏览器；手敲也行 |
| 拦截代理 | `127.0.0.1:8899` | 仅当你要代理浏览器等工具时才需要（`start-proxy.bat`） |

两个端口都**只监听本机**（`127.0.0.1`），不对外网开放。

如果 8898 已被占用（比如另一个程序或上一次没关干净），`start.bat` 窗口里会
看到绑定失败提示。改端口两种方式：

```bash
# 方式一：临时（当前这次启动有效）
set HUNTGUARD_PORT=8898
start.bat

# 方式二：永久（写进 data/config.json）
notepad data\config.json      # 改 "api_port" 和 "proxy_port"
```

---

## 第一次跑起来该看到什么

装完 `start.bat` 后，控制台窗口会打印地址（默认 `http://127.0.0.1:8898`），
浏览器自动打开。**重开一个终端**（让 PATH 生效），然后试：

```bash
# 没开控制台时 —— 原样透传
curl http://127.0.0.1/del/a.txt

# 双击 start.bat 后 —— 被拦截
curl http://127.0.0.1/del/a.txt    # exit code 126，打印 JSON

curl http://127.0.0.1/index.php?id=1     # 正常请求照常放行
```

> PowerShell 里 `curl` 是 `Invoke-WebRequest` 的别名，会绕过拦截器。
> 安装时加 `-FixAlias` 可自动处理，或直接用 `curl.exe`。

### 关于 PATH（重要）

Windows 组合 PATH 时是「机器级 + 用户级」且**机器级在前**，而真实
`curl.exe` 在 `C:\Windows\System32`（机器级）。所以只往用户 PATH 里
加目录是**没用的**。更麻烦的是 Git Bash：它把 `/mingw64/bin` 排在最前，
且**完全不受 Windows PATH 顺序影响** —— 调 PATH 对它无效。

因此四通道各用各的机制（见上表）。用 `wafctl doctor` 确认两条解析链：

```
[OK]  cmd 解析顺序       命中拦截器：C:\tools\hunt-guard\bin\curl
[OK]  Git Bash 解析顺序  命中拦截器：/c/tools/hunt-guard/bin/curl
[OK]  已装接入方式       cmd AutoRun、BASH_ENV、PowerShell profile
[OK]  Python 钩子        已生效
```

（路径随你放的地方变，这里只是示例。）

想要**全局**生效（含 `-NoProfile`、直接调 exe、管理员进程），
用管理员权限跑：

```bash
wafctl install-path --machine      # 写机器级 PATH 最前面
```

移除全部接入：

```bash
wafctl uninstall-path
```

---

## 为什么没有 MCP 集成（重要）

早期版本提供过 MCP 服务器，让 AI 能直接调工具改规则。**已移除**，原因是
威胁模型错了：

护栏的钥匙不能交给它约束的对象。MCP 暴露的
`waf_set_enabled(false)` / `waf_unlock` / `waf_add_allowlist` / `waf_delete_rule`
全部写在文档里、全都能被 AI 一条命令触发。它拦得住"AI 手滑"，
拦不住"AI 被提示注入后主动拆护栏"—— 而后者才是"给 AI 装护栏"
唯一值得做的理由。

现在改规则请用：

| 方式 | 怎么做 |
|---|---|
| 控制台界面 | 打开 `http://127.0.0.1:8898`，规则页直接改 |
| 命令行 | `wafctl rules list` / `rules add` / `rules toggle` |
| 直接编辑 | `data/rules.json`，存盘即热重载 |

关开关、解锁这类操作走 CLI 或界面 —— 都需要你本人动手。

**升级提示**：如果你装过 1.0，AI 客户端配置里可能残留
`mcpServers.agent-waf` 条目（指向已删除的文件）。跑 `wafctl audit`
会列出来，手工删掉即可。
---

## 装到别的目录（给别人用）

绿色版，**解压即用**：

1. 把整个文件夹拷到任意位置（`C:\tools\hunt-guard`、`D:\我的工具\waf` 都行）
2. 双击 `install.bat` —— 自动检测 Python/curl/Git Bash 路径，写入全部接入
3. 双击 `start.bat` 开始用（首次会自动补装，不用先跑 install）

零依赖：只用 Python 标准库，不需要 `pip install`，不需要注册服务，
不需要管理员权限（想要全局覆盖才需要）。

> **唯一的例外**：代理的 MITM 模式（`--mitm`，用于检查 HTTPS 内容）
> 需要 `cryptography`（`pip install cryptography`）。不装也能用，
> 只是不能做 MITM —— 其它三个通道（curl / Python 脚本 / Burp）
> 完全不受影响。

### 完全自包含

**所有文件都在这个文件夹里。** 删掉文件夹 = 一切消失，系统里不留残留。

| 组件 | 文件位置 |
|---|---|
| 规则 / 配置 / 日志 / 证书 | `data/` |
| curl 拦截器（cmd / Git Bash） | `bin/` |
| Python 启动钩子 | `hooks/sitecustomize.py` |
| PowerShell 处理逻辑 | `bin/waf.ps1` |
| 调试日志 | `data/logs/` |

外面只留**指针**（不是文件）：

| 指针 | 位置 | 作用 |
|---|---|---|
| `HUNTGUARD_HOME` | HKCU 环境变量 | 主指针，其它机制靠它定位 |
| `AGENTWAF_HOME` | HKCU 环境变量 | 同上（1.0 旧名，兼容保留） |
| `BASH_ENV` / `PYTHONPATH` | HKCU 环境变量 | Git Bash / Python 钩子 |
| `AutoRun` | HKCU 注册表 | cmd 钩子 |
| PowerShell profile | 用户目录，**只一行** | 指向 `bin/waf.ps1` |
| `~/.bashrc` | 用户目录，**只一行** | 指向 `bin/waf-bash-env.sh` |

随时查看外部足迹，或彻底清理：

```bash
wafctl audit            # 列出所有目录外的足迹
wafctl uninstall-path   # 一键清掉全部指针
```

自动探测的结果（Python、真实 curl、Git Bash 的真实路径）写在
`data/env.cmd` 和 `data/env.sh`，shim 直接读，**不需要任何人手工填路径**。
换机器、换安装位置都不用改任何东西。

### 配置（可选）

`data/config.json`：

```jsonc
{
  "api_host": "127.0.0.1",     // 控制台监听地址
  "api_port": 8898,            // 端口冲突时改这里
  "proxy_host": "127.0.0.1",
  "proxy_port": 8899,
  "auth_token": "",            // 填了就要求 API 带 X-Auth-Token
  "rules_file": ""             // 留空 = data/rules.json；可指向团队共享规则集
}
```

也可以用环境变量临时覆盖（优先级高于配置文件）：
`HUNTGUARD_HOST` / `HUNTGUARD_PORT` / `HUNTGUARD_PROXY_PORT` /
`HUNTGUARD_TOKEN` / `HUNTGUARD_RULES_FILE`。

> **兼容性**：1.0 时代这套变量叫 `AGENTWAF_*`，现在仍然认（新名优先）。
> 已装好的机器不用改任何东西 —— 注册表里的指针照旧有效。
> 想彻底换成新名：`wafctl install-path --force`。

---

## AI 工具会话覆盖（ZCode / Claude Code / Codex / WorkBuddy）

你在不同 AI 工具里挖洞时，**这些会话都会被拦**。它们在 Windows 上执行
命令走的是四种通道，`install.bat` 全部装上了：

| 通道 | 谁在用 | 接入机制 | 实测 |
|---|---|---|---|
| **Git Bash（非交互）** | ZCode、Claude Code、Codex 执行 shell 命令 | `BASH_ENV` | ✅ 拦截 |
| **Python 进程** | AI 写的 `exp.py`、requests 脚本 | `PYTHONPATH` + `hooks/sitecustomize.py` | ✅ 拦截 |
| **cmd** | AI 调 `cmd /c`、部分工具 | `HKCU AutoRun` | ✅ 拦截 |
| **PowerShell** | 部分工具、你手敲 | profile（删 curl 别名 + 前置 PATH + 包装 `Invoke-*`） | ✅ 拦截 |

**PowerShell 那条不只是 `curl`**：`Invoke-WebRequest` / `Invoke-RestMethod`
既不经过 curl、也不经过 PATH，所以 profile 会把这两个 cmdlet 包一层
（用 PowerShell 自己的 `ProxyCommand` 从已安装的 cmdlet 生成，参数表
跟着你的 PS 版本走），发出去之前先问一次 `waf/pshook.py`。
`irm -Method Delete -Uri ...` 同样会被拦下。

关键点：**AI 工具的 shell 是"非交互式"的**，它不读 `~/.bashrc`。
所以必须用 `BASH_ENV`（非交互 bash 启动时必读的文件）—— 这是本次
专门补的通道。Python 同理：AI 常直接写 `.py` 打目标，不经 shell，
只有解释器层面的钩子拦得住 —— 我们用 `PYTHONPATH` 指向
`hooks/sitecustomize.py`（不是 `.pth`：那样文件得留在系统
site-packages 里，删项目会留残留）。

### 逃生开关（全部列出，含"一条环境变量就穿透"的）

这东西不是安全边界，是**防手滑的护栏**。下面每一个都能让它失效 ——
完整列出，是因为"以为开了就万无一失"比知道它能被绕过更危险。

| 开关 | 效果 | 谁会用 |
|---|---|---|
| `wafctl off` | 暂停全部拦截（等价于关控制台） | 你本人 |
| `wafctl unlock --minutes N --reason "..."` | N 分钟内全部放行，到期自动恢复 | 你本人 |
| `WAF_DISABLE=1` | 单条命令绕过（设了它 curl shim 直接透传） | 你本人 / 一条 env |
| `WAF_INTERNAL_PROC=1` | 关掉 Python 护栏（`guard` 与 `autohook` 见到就直接返回） | **内部子进程专用**（regexguard 探测用），效果等同 `WAF_DISABLE` |
| `WAF_ALWAYS_OFF=1` | 强制视为"未开启" | 测试用 |
| `WAF_ALWAYS_ON=1` | 强制视为"已开启"（脱离控制台也能拦） | 测试用 |
| `HUNTGUARD_NO_HOOK=1` | 关掉 Python 钩子 | 跑性能测试 |
| `HUNTGUARD_RULES_FILE=<空文件>` | 让规则文件指向一个空文件，等于无规则 | 高级用法（本该用于共享规则集）|
| `WAF_STATE_FILE=<假路径>` | 心跳指向别处，激活判定失效 | 测试隔离用 |
| `WAF_PROXY_INSECURE=1` | 代理连上游不校验证书（默认校验） | 打自签靶场 |
| 直接编辑 `data/rules.json` | 删掉规则 / 把 `enabled` 改 `false` | 任何能写这个文件的进程 |

```bash
# 代理连上游时不校验证书（默认**校验**）。
# 打自签证书的靶场才需要开；开了会在日志里留一行提示。
WAF_PROXY_INSECURE=1
```

（`AGENTWAF_NO_HOOK=1` 等旧名同样有效。）

**所以"护栏的钥匙在谁手上"要诚实回答**：默认情况下，任何能跑命令、
能写 `D:\agent-waf\data\` 的进程都能关掉它 —— 包括被 AI 调用的 shell。
它拦的是"AI 没想到要绕过、只是执行了删除动作"，不是"Ai 处心积虑要
拆护栏"。要收紧的话：

```bash
# 1) 给控制台 API 加 token（UI 已支持，会自动带上）
#    编辑 data/config.json："auth_token": "<随机串>"

# 2) 让 data/ 只对自己可写（去掉其它账户的写权限）
icacls "D:\agent-waf\data" /inheritance:r /grant:r "%USERNAME%:(OI)(CI)F"
```

这两条做不到"绝对拦不住"（同用户进程仍然能改），只是让绕过需要
更明确的动作、更容易在日志里留下痕迹。

### 心跳文件不是"急停按钮"

`data/run/active.json` 是控制台的心跳（每 5 秒刷新）。**删掉它不等于关闭**——
后台线程会在几秒内自动重建（这是刻意的：防止清理工具误删导致
永久失去拦截能力）。

想真的停，用 `wafctl off` 或双击 `stop.bat`（等价于关控制台）。
删文件这种直觉操作在这里是**无效的**，写在这里免得你踩。

### 覆盖不到的情况（诚实说明）

| 场景 | 说明 |
|---|---|
| AI 用工具**内置的 HTTP 客户端**（不走 shell、不走 Python 库、不走 PowerShell） | 需机器级 PATH + 该工具自己支持代理；这是工具内部实现，外部拦不住 |
| 直接调 `curl.exe` 全路径 | PATH 拦截不到明确路径，需机器级 PATH |
| `powershell -NoProfile` | 跳过 profile，需机器级 PATH |
| 管理员权限运行的进程 | 需机器级 PATH |
| **裸 socket 手写报文把 body 拆成两次 `sendall`** | 见下（只影响手写报文，库请求不受影响） |
| **超过 256KB 的请求体尾部** | 见下 |
| **代理模式下的 HTTPS 内容** | 见下 |

**裸 socket 的边界（1.1.6 新增说明）**：传输层只看得到"第一行就是
HTTP 请求行"的字节块。手写报文正常写法是一次 `sendall` 发完（请求行 +
头 + body 在一起，全都扫）；如果你刻意拆成两次发（先头后 body），
第二段没有请求行特征，看不到。库发的请求不受影响 ——
`http.client` 自己会分层发，但那条路径由 `http.client` 补丁覆盖。

**大请求体的边界**：单个字段只扫前 **256KB**（`settings.max_scan_bytes`）。
超出的部分**不检查** —— 把敏感词放在 256KB 之后就能过去。
这是刻意的性能取舍（不截断的话一个几 MB 的上传会把每个请求的判定
拖到秒级），但盲区是真实存在的，所以写在这里。

要收紧的话改 `data/config.json`：`{"max_scan_bytes": 1048576}`
（1MB；注意判定耗时随之上升）。正常挖洞的请求体远小于 256KB。

**代理 + HTTPS 的边界（重要）**：非 MITM 模式下，代理只能看到
`CONNECT host:443` —— 也就是只有主机名，**路径和 body 都看不到**。
而 `delete` 这类语义全在路径/body 里，所以这一模式下 HTTPS 请求
几乎没有内容防护。

需要检查 HTTPS 内容的话有两条路：

```bash
# 1) 开 MITM（能看到完整内容；需要 cryptography，会生成自己的 CA）
start-proxy.bat --mitm        # 或 wafctl proxy start --mitm
#    然后按提示把 CA 导入浏览器/系统信任库
#    注意：CA 私钥就在 data/certs/ 下，读完 certs/SECURITY-README.txt 再决定

# 2) 用 curl / Python 脚本打（这两条通道本来就看得见完整请求）
curl https://target/api?action=delete
```

**不开 MITM 时，HTTPS 只拦得住"主机名里就带敏感词"的情况**
（比如 `https://del.example.com/`）。这是代理架构的固有限制，
不是 bug —— 写在这里是因为"以为装了 WAF 就都拦住了"比不知道更危险。

要覆盖这些边角，用管理员跑一次：

```bash
wafctl install-path --machine      # 写机器级 PATH，全局生效
```

---

## 拦截开关（"我开了才生效"）

拦截生效需要**两个条件同时满足**：

| 条件 | 怎么控制 | 说明 |
|---|---|---|
| 控制台在运行 | 双击 `start.bat` / `wafctl on` | 写心跳文件，每 5 秒刷新 |
| 用户开关是开的 | 控制台首页那个大开关 / `wafctl on` | 存 `settings.enabled` |

控制台首页顶部有个醒目的**总开关**，一眼就能看到当前是否在拦截：

- **绿色「拦截已开启」** —— 命中敏感词会被拦下
- **黄色「拦截已暂停」** —— 所有请求直接透传

界面每 5 秒自动刷新状态，所以你能立刻看到自己在什么状态。

心跳机制的意义：即使控制台被强杀（来不及清理），最多 **20 秒**后
心跳过期，拦截器自动失效 —— 不会出现"程序早关了却还在拦"的情况。

命令行控制：

```bash
wafctl on           # 开启拦截
wafctl off          # 暂停拦截（恢复纯透传）
wafctl intercept    # 看当前开关状态
wafctl status       # 完整状态
```

---

## 四个入口，按需启用

| 入口 | 怎么接 | 拦截效果 |
|---|---|---|
| **curl** | `install.bat` 已自动装好 | 命令不执行，打印 JSON，退出码 126 |
| **Burp Suite** | Extensions → Add → Python → `burp\burp_waf.py` | 请求改写到本地沉洞，返回 403，目标收不到 |
| **AI 写的 Python 脚本** | `waf-run python exp.py` | 命中抛 `WafBlocked` 异常 |
| **浏览器 / 其他工具** | 双击 `start-proxy.bat`，工具里设代理 `127.0.0.1:8899` | HTTP 返回 403 + JSON |

四个入口**共用同一个开关**。控制台没开，四个入口全都不拦截。

### 界面主题

控制台右上角四个色点，点一下即切换，**记住选择**（刷新、重启都保持）：

| 主题 | 说明 |
|---|---|
| 深色 | 默认。夜间 / 长时间盯屏 |
| 浅色 | 白天、投屏、截图给别人看 |
| 护眼绿 | 低对比绿底，久盯不累 |
| 海洋蓝 | 蓝底，冷静色调 |

第一次打开会**跟随系统**：系统是浅色主题就用浅色。
四套配色都按 WCAG AA 校对过对比度（正文 14:1 以上，次要文字 5:1 以上）。

想加自己的主题：`ui/index.html` 里所有颜色都是 CSS 变量，
照 `[data-theme="ocean"]` 那块复制一份改颜色即可，不用碰任何组件样式。

### curl（已自动）

原理：`bin\curl.cmd` 被放到 PATH 最前面，你敲的 `curl` 实际走的是它。
它先解析参数做检测，命中就打印 JSON 并退出（**不执行真实 curl**）；
没命中才转发给真正的 `C:\Windows\System32\curl.exe`，输出和退出码完全一致。

临时绕过（应急，不推荐）：`set WAF_DISABLE=1`

### Burp Suite

Burp 需要 Jython。步骤：

1. 下载 `jython-standalone-2.7.x.jar`（[jython.org](https://www.jython.org/download)）
2. Burp → Extensions → Extension settings → Python environment 里选中该 jar
3. Burp → Extensions → Installed → Add：
   - Extension type: `Python`
   - Extension file: `<你放 hunt-guard 的目录>\burp\burp_waf.py`
4. 出现 **HuntGuard** 标签页即成功

规则文件路径会自动发现（扩展自己就在安装目录里），**不用手填**。

命中后被拦请求**不会到达目标服务器**。标签页里能看到命中记录、手动重载规则、
切换拦截方式。它读的是同一份 `data\rules.json`，和 curl 共用规则。

> 如果你的 Burp 版本较新、扩展加载报错，用备选方案：把 Burp 的
> **Upstream Proxy** 设为 `127.0.0.1:8899`（先双击 `start-proxy.bat`）。
> 这种方式对 HTTP 明文请求完整生效；HTTPS 因为 Burp 自己完成 TLS，
> WAF 只能看到 CONNECT 的主机名，建议还是用扩展。

### AI 脚本

```bash
waf-run python exp.py
```

`waf-run` 做两件事：给子 Python 进程注入 `sitecustomize.py`（启动即装护栏），
并把 `bin\` 放到子进程 PATH 最前（子进程调 curl 也走 WAF）。

护栏覆盖：`requests` / `urllib` / `httpx` / `aiohttp` / `urllib3` /
`http.client` / 裸 `socket` / `subprocess` / `os.system`。

后两项（`http.client` 与裸 socket）是 1.1.6 补的**传输层兜底**：
按库挂钩总有漏网的（`HTTPConnection(...).request("DELETE", ...)`、
`sendall(b"DELETE /api/x HTTP/1.1...")` 原先一个字都不用混淆就能过），
所以直接挂到标准库最底层。同一请求穿过多层时只扫一次、只记一条事件。

`waf-run` 属于**显式调用** —— 你主动用它，就等于表态"我要护栏"，所以
不受控制台开关限制。想让护栏跟随控制台开关：

```python
import waf.guard
waf.guard.install_guard(follow_console=True)   # 控制台关了就不检查
```

也可以在脚本里显式启用：

```python
import waf.guard
waf.guard.install_guard()
```

### 浏览器 / 其他工具

双击 `start-proxy.bat`，然后在浏览器或工具里设 HTTP 代理 `127.0.0.1:8899`。

- HTTP 请求：完整内容检测
- HTTPS 请求：默认只检查主机名（隧道透传）。要检查内容，在控制台
  「代理/系统」页勾选 MITM 并导入 CA 证书（页面里有导入说明和一键下载）。

---

## 规则怎么加（重点）

打开控制台 → **拦截规则** → **+ 新建规则**。你只需要填三样东西：

| 字段 | 说明 |
|---|---|
| **名称** | 给人看的，比如「删除类关键词」 |
| **关键词** | 每行一个。`delete` 会命中 `delete.php`、`?delete=`、`deleted_at` |
| **匹配方式** | `substring` 包含即命中（最常用）；`word` 词边界；`regex` 正则 |

**默认检查全部字段** —— URL、路径、参数、请求体、请求头、方法、主机、命令行，
一个都不漏。这才安全：只在 URL 上查 `delete`，那 POST 请求体里的删除就漏掉了。

补充字段（都可留空）：
- **正则**：和关键词**同时**生效（关键词兜底 + 正则精确）
- **exclude**：误报抑制，命中点前后 24 字符内匹配则忽略该命中
- **备注**：为什么要拦这条

**改完立即生效**，不用重启（引擎按文件 mtime 热重载）。

### 高级：限定检查范围

只有**排误报**时才需要。展开规则编辑框底部的「高级：限定检查范围 / 字段」，
取消「全部字段」，然后只勾选需要检查的字段。

⚠ 缩小范围会**减少拦截面** —— 漏勾的字段就查不到了。比如只勾 `url`，
那么请求体里的 `action=delete` 不会被拦。

### 几个常用套路

**只拦参数名，不误伤 `deleted_at`**

```
关键词： delete
匹配方式： word            ← 词边界，但会漏掉 deleteFile
```

或保留 `substring` 但加抑制：

```
关键词： delete
exclude： deleted_at
        is_deleted
```

**拦 Windows 删除命令**

```
关键词： del /f
        rd /s
        Remove-Item
        -Recurse -Force
```

**放行某个靶场域名**（放行名单页）

```
source： url
pattern： ^https?://test\.example\.com/
```

---

## 逃生通道（明确要做删除测试时）

不能因为拦得死就影响你挖洞。三条路，都留痕：

**1. 临时解锁**（推荐，有时限、有理由、有记录）

```bash
wafctl unlock --minutes 10 --reason "验证 /api/delete.php 越权删除"
wafctl lock                                          # 立即恢复
```

控制台顶部会显示倒计时横幅，到期**自动上锁**。解锁期间的命中仍会记录，
日志里标注为「解锁放行」。

**2. 全局只读模式**（要观察全部流量时）

控制台 → 代理/系统 → 拦截模式 → `monitor`。全部只记录不拦。

**3. 停用单条规则**：规则列表里的开关，一键切换。

---

## 常用命令

```bash
# 开关（核心）
wafctl on                    # 开启拦截
wafctl off                   # 暂停拦截
wafctl intercept             # 看开关状态

# 日常
wafctl start                 # 启动控制台（= 开启拦截）
wafctl start --proxy         # 顺便启动代理
wafctl stop                  # 停止（= 关闭拦截）
wafctl status                # 状态总览
wafctl doctor                # 环境自检，出问题先跑这个

# 检测 / 规则
wafctl check "http://x/delete.php"     # 单次检测，退出码 126 = 会拦
wafctl rules list                      # 列出所有规则
wafctl mode monitor                    # 切全局模式
wafctl events -n 20 --blocked          # 看拦截日志
wafctl events clear                    # 清空日志（会二次确认）
wafctl events clear --keep-days 7      # 只留最近 7 天

# AI 集成

# 接入管理
wafctl install-path                    # 安装 curl 接入
wafctl install-path --machine          # 机器级（需管理员，全局生效）
wafctl uninstall-path                  # 移除接入

wafctl test                            # 跑自测（279 项）
```

## 规则升级

新增/修正的内置规则会**自动合并**到你已有的 `rules.json`，不用重装：

- 内置规则版本号（`defaults_rev`）变化时触发迁移
- **你自己改过的规则不会被覆盖**（用内容指纹判断）
- **你删掉的默认规则不会复活**（记在 `removed_defaults`）
- 开关状态在任何情况下都保留

所以升级后你既拿到新规则，又不会丢掉自己的定制。

---

## 目录结构

```
hunt-guard\                ← 你解压/克隆出来的目录，名字随意
├── start.bat              ← 双击启动
├── stop.bat               ← 双击停止
├── install.bat            ← 双击安装（首次）
├── start-proxy.bat        ← 带代理启动
├── wafctl / wafctl.cmd    ← 命令行入口
│
├── waf\                   核心
│   ├── state.py           激活态：心跳 + 开关判定（"我开了才生效"）
│   ├── autohook.py        Python 进程引导器（按路径加载，不占包名）
│   ├── engine.py          判定引擎（热重载、多源扫描、白名单、解锁）
│   ├── normalize.py       归一化（URL/HTML/Unicode 解码、全角折叠、去分隔符）
│   ├── rules.py           默认规则、校验、增删改、版本迁移
│   ├── install_path.py    PATH 接入（cmd AutoRun / 机器级 PATH / profile）
│   ├── curlshim.py        curl 拦截器
│   ├── guard.py           Python 运行时护栏
│   ├── runner.py          waf-run 的实现
│   ├── proxy.py           本地代理（含 MITM）
│   ├── certs.py           CA / 证书签发
│   ├── api.py             REST API + UI 服务
│   ├── logstore.py        SQLite 日志
│   └── cli.py             wafctl 的实现
│
├── ui\index.html          单文件控制台（无依赖、无 CDN、离线可用）
├── hooks\sitecustomize.py Python 启动钩子（自包含，不落 site-packages）
├── burp\burp_waf.py       Burp 扩展
├── bin\                   curl 包装 / waf-run / waf.ps1 / python 定位器
├── scripts\
│   ├── install_shim.sh    Linux / macOS / WSL 的接入安装
│   └── make-release.sh    发布打包（强制排除 data/，含敏感文件自检）
├── data\                  规则 / 事件库 / 证书 / 探测缓存（运行时生成）
├── docs\DESIGN.md         框架设计说明
├── CHANGELOG.md           更新记录
├── .github\workflows\     CI（三平台 × 两 Python 版本）
└── tests\                 自测（279 项）
```

---

## 默认拦了什么

### 核心：不可逆破坏（拦截）

| ID | 名称 | 动作 |
|---|---|---|
| R-101 | 删除/销毁类（delete、remove、destroy、unlink、purge、rm -rf、shred…） | **拦截** |
| R-102 | 数据库破坏（drop table、truncate table/**truncate users**、delete from、**flushdb**、**dropDatabase/drop_collection**、shutdown） | **拦截** |
| R-103 | 磁盘破坏（mkfs、dd of=/dev/sda、fork 炸弹） | **拦截** |
| R-104 | 账户删除（userdel、groupdel、net user /delete） | **拦截** |
| R-105 | **短删除指令 del / rm**（词边界精确匹配） | **拦截** |
| R-106 | **删除命令的 Windows/SCM/脚本写法**（rd /s、Remove-Item、os.remove、rimraf、rmtree…） | **拦截** |
| R-107 | **权限变更 / 表结构破坏**（GRANT…TO、REVOKE…FROM、ALTER TABLE…DROP、ALTER USER…PASSWORD） | **拦截** |
| R-203 | 反弹 Shell（/dev/tcp、nc -e、mkfifo 管道） | **拦截** |

### 扩展：与删除同级的高危操作（拦截）

| ID | 名称 | 覆盖内容 |
|---|---|---|
| R-301 | **脱库 / 数据外带** | mysqldump、pg_dump、mongodump、INTO OUTFILE、sqlmap --dump |
| R-302 | **后门 / 持久化** | 写 authorized_keys、一句话木马、crontab -e、计划任务、建账号 |
| R-303 | **痕迹清理 / 日志清除** | history -c、删日志、wevtutil cl、关审计、setenforce 0 |
| R-304 | **云 / 容器 / IaC 删除** | kubectl delete、terraform destroy、docker prune、aws/az/gcloud delete |
| R-305 | **备份 / 快照删除** | vssadmin delete shadows、wbadmin delete、删云快照、lvremove |
| R-306 | **权限 / 账号体系破坏** | 写 sudoers/passwd/shadow、chmod -R 系统目录、加管理员组 |
| R-307 | **防火墙 / 安全组件关闭** | iptables -F、ufw disable、关 Defender、停 sshd/auditd |
| R-308 | **服务中断 / 资源耗尽** | dd 填盘、停数据库、kill -9 -1、hping3 flood |
| R-310 | **Git 历史破坏** | push --force、reset --hard、filter-branch、npm unpublish |
| R-314 | **密码重置 / 账号接管** | reset-password 接口、action=resetpass、ALTER USER、chpasswd |

### 监控：只记录不拦截

挖洞时这些是日常工作，拦了没法干活。记录是为了复盘 AI 跑过什么。

| ID | 名称 | 覆盖内容 |
|---|---|---|
| R-201 | 危险写操作 | update、insert、chmod、reboot（grant/revoke 已移到 R-107 按拦截处理） |
| R-202 | 漏洞利用痕迹 | /etc/passwd、union select、xp_cmdshell |
| R-309 | **凭证转储** | mimikatz、lsass、ntds.dit、dcsync（测生产域建议改 block） |
| R-311 | **扫描器 / 爆破工具** | nmap、sqlmap、hydra、ffuf、gobuster |
| R-312 | **OOB 外带通道** | dnslog、ceye、burpcollaborator、interact.sh |
| R-313 | **批量读敏感表** | SELECT … FROM users/orders 类 |

### 设计原则：只拦"不可逆"，不拦"读取"

这套规则的难点不在拦得住，而在**不误拦**。实测调试过程中抓出并修掉了这些误报：

| 正常动作 | 为什么不能拦 |
|---|---|
| `cat /etc/sudoers`、`grep NOPASSWD /etc/sudoers` | 读配置做提权检查，是常规渗透步骤 |
| `cp /etc/sudoers /tmp/audit/` | 拷出来审计 = 读取，不是破坏 |
| `?file=/var/log/nginx/access.log` | LFI 读日志是正常利用链 |
| `crontab -l`、`iptables -L`、`icacls`、`kubectl get` | 列配置 = 信息收集 |
| `?page=mysqldump-guide`、`?q=pg_dump usage` | 查文档 / 搜索，不是真在跑导出 |
| `sqlmap -u ... --batch` | 常规探测；只有 `--dump/--os-shell` 才拦 |
| `git reset --soft`、`git stash pop` | 正常版本操作 |

判定逻辑上刻意区分：
- **`net user`（列用户）放行，`net user x /add`（建账号）拦截**
- **`iptables -L`（看规则）放行，`iptables -F`（清规则）拦截**
- **`systemctl status`（看状态）放行，`systemctl stop sshd`（停安全组件）拦截**
- **`mysqldump -u root db`（真导出）拦截，`mysqldump-guide`（文档）放行**
- **`?password=123456`（登录/爆破/SQLi）放行，`reset-password`（改密）拦截**

R-314 是这条原则最典型的例子：`password` 作为参数名每天出现几十次，
所以判据要求「**改密动作 + 密码目标**必须同时出现」——
`login?password=x`、`register?password=x`、`password=' OR 1=1--` 全部放行；
`/api/reset-password`、`action=resetpass`、`ALTER USER ... IDENTIFIED BY`
才拦截。`forgot-password`（找回页）、`request-reset`（申请链接）、
`password-policy`（策略查询）等只读接口也在排除名单里。

R-201 / R-202 等监控规则改成 `block` 只需在 UI 里编辑规则、把 action 改掉。

### 删除变种覆盖范围（R-101 / R-105 / R-106）

这些写法都会被拦（`wafctl check` 可逐条验证）：

| 类别 | 覆盖写法 |
|---|---|
| 英文同义词 | `delete` `remove` `destroy` `destruct` `obliterate` `annihilate` `exterminate` |
| 抹除类 | `shred` `wipe` `purge` `erase` `unlink` `nuke` `scour` |
| 短指令（词边界） | `del` `dels` `delall` `rm` `rmall` `rmdir` |
| 文件系统命令 | `rimraf` `deltree` `rm -rf` `rm -fr` `rd /s` `del /f` `del C:\` |
| 编程语言 API | `os.remove` `os.unlink` `shutil.rmtree` `fs.unlink` `fs.rm` `unlink()` |
| 对象/框架方法 | `Remove-Item` `Remove-ItemProperty` `DeleteFile` `RemoveDirectory` `deleteMany` `findByIdAndDelete` `destroy()` |
| SQL | `drop table` `drop database` `truncate table` `delete from` |
| 强删语义 | `force-delete` `hard_delete` `permanent_delete` `bulk_delete` |

**不会误报**的正常词（词边界 + 抑制名单保证）：
`model` `delay` `delta` `delegate` `order` `handler` `border` `deleted_at`
`is_deleted` `soft_delete` `delete_flag` `format=json`

---

## 归一化有多强

这些写法都会被 `delete` 拦下（`wafctl check` 可逐条验证）：

| 绕过写法 | 处理后 |
|---|---|
| `%64%65%6c%65%74%65` | `delete` |
| `%2564%2565lete`（双重编码） | `delete` |
| `de%6cete` | `delete` |
| `d_e_l_e_t_e` | `delete` |
| `de lete` / `de\tlete` | `delete` |
| `delete/**/` | `delete` |
| `ＤＥＬＥＴＥ`（全角） | `delete` |
| `del\u200bete`（零宽字符） | `delete` |
| `\u0064elete` | `delete` |
| `&#100;elete` | `delete` |
| `DELETE` / `Delete` | `delete` |

---

## 定位与边界（重要）

这是**护栏**，不是安全沙箱。目标是让"意外删除"从"敲错一个字就发生"
变成"必须是有意识的、多步的、留记录的操作"。

它挡不住什么：

- 直接 `set WAF_DISABLE=1` 或从 PATH 里移除 shim
- 用非 curl 的 HTTP 客户端且不走 guard / 代理
- 你自己把规则删了

建议配合：重要目标先做快照/备份；对生产环境用只读账号；`wafctl unlock` 用完就锁。

---

## 故障排查

**先跑 `wafctl doctor`**，它会逐项检查 Python、依赖、端口、curl、
**PATH 解析顺序**、接入方式、拦截开关、规则加载。

| 症状 | 处理 |
|---|---|
| **curl 命令完全没被拦** | 看 `wafctl doctor` 的「curl 解析顺序」。若不是拦截器，跑 `wafctl install-path`。**必须新开终端**（AutoRun 只对新 cmd 窗口生效） |
| 开了控制台还是没拦 | `wafctl intercept` 看开关；UI 首页看是否黄色「已暂停」 |
| 关掉控制台还能拦？ | 不会。心跳过期 20 秒后自动失效；若仍异常，`wafctl off` 手动清 |
| PowerShell 里 curl 报错 | 那是 `Invoke-WebRequest` 别名，用 `curl.exe` 或 `wafctl install-path`（已写 profile） |
| Burp 扩展加载失败 | 检查 Jython jar；看 Burp 的 Extender → Errors |
| 控制台打不开 | 8898 端口被占：改 `data\config.json` 的 `api_port` |
| MITM 后浏览器报证书错 | 没导入 CA：控制台「代理/系统」页下载并导入 |
| 规则改了没生效 | 看是否启用；`wafctl status` 确认规则数；点 UI 的刷新 |
| 我改的规则升级后丢了 | 不会 —— 内容指纹会保护你的修改。若真丢了，看 `data\rules.json.broken.*` 备份 |

---

## 其它平台（Linux / macOS / WSL）

Windows 上的 `install.bat` / `start.bat` 是现成的；其它平台用命令行。
功能一样，只是没有双击和注册表那套接入。

```bash
# 1. 探测环境（找 Python、真实 curl、bash）
python3 waf/cli.py detect

# 2. 接入 curl 拦截（当前会话 + 持久化）
source scripts/install_shim.sh              # 当前会话生效
bash   scripts/install_shim.sh --persist    # 持久化（写 .bashrc + .profile + BASH_ENV）

# 3. 启动控制台（拦截开始生效）
python3 waf/cli.py start --no-browser

# 4. 停掉（拦截立即失效）
python3 waf/cli.py stop
```

`--persist` 会同时写 `~/.bashrc` 和 `BASH_ENV`。**两个都要**：
`~/.bashrc` 只管你手敲的交互式终端，而 AI 工具执行命令用的是
`bash -c "..."`（非交互），只有 `BASH_ENV` 管得到它。

平台差异：

| 能力 | Windows | Linux / macOS / WSL |
|---|---|---|
| curl 拦截 | ✅ 四通道（AutoRun / BASH_ENV / profile / Python 钩子） | ✅ PATH + `BASH_ENV` |
| Python 脚本拦截 | ✅ `PYTHONPATH` + `hooks/sitecustomize.py` | ✅ 同上（`export PYTHONPATH=...`） |
| 本地代理 | ✅ | ✅ |
| Burp 扩展 | ✅ | ✅（同样用 Jython） |
| 一键脚本 | `start.bat` / `stop.bat` | `wafctl` / `python3 waf/cli.py` |

---

## 作者

**Jake**

---

## License

[MIT](LICENSE) —— 自由使用、修改、分发。

---

## 更新记录

见 [CHANGELOG.md](CHANGELOG.md)。当前版本 **1.1.6**
（拦截面与安全修复较多，建议升级后跑一次 `wafctl install-path --force`）。
