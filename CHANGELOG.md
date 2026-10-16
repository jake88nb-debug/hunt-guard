# 更新记录

版本号规则：`主.次.修`。拦截面变化、规则集变化、安全相关修复 → 提"次"；
仅文档/文案 → 提"修"。

---

## 1.1.7 — 2026-10-16

### 文档重构（无代码改动）

README 精简成四块：**工具介绍 / 下载与安装 / 作者 / 免责声明**。
原来的完整说明（通道原理、规则怎么写、逃生开关、故障排查、边界与
平台差异）整篇移到 **[USAGE.md](USAGE.md)**，一个字没删。

其它修正：

* README 不再暗示"手敲 `rm` 会被拦"—— 命令行侧拦的是 `curl`，以及
  脚本里 `subprocess` / `os.system` 发起的删除动作；交互式 shell 里
  直接敲 `rm` 不在拦截面内（见 USAGE.md 的"覆盖不到的边界"）。
* 免责声明写明"护栏不是安全沙箱"，并把 MIT 的免责条款写进正文。
* 权限加固示例不再写死开发机的安装路径，改用 `<安装目录>`。
* 代码注释里指向 README 的失效引用改指 USAGE.md。

---

## 1.1.6 — 2026-10-16

这一版把"绕得过去的那几条"补上了。来源是一份实测报告：
用 `http.client`、裸 socket、以及 `urllib` 带 body 的写法发删除请求，
全部原样通过 —— 说明防护挂在"库"上，而不是挂在"传输"上。

### 1. 传输层兜底：http.client 与裸 socket

**绕过**（实测，无需任何混淆）：

```python
http.client.HTTPConnection(host, port).request("DELETE", "/api/users/1")
socket.create_connection((host, port)).sendall(b"DELETE /api/users/1 HTTP/1.1\r\n...")
```

**修法**：新增两个补丁 —— `http.client.HTTPConnection._send_request` /
`putrequest` / `endheaders`，以及 `socket.socket.sendall` / `send`
（只认"第一行就是 `METHOD SP target SP HTTP/x.y`"的字节块，
Redis 内联命令、FTP、SIP 这类协议一个都不会误伤）。

分工：库级钩子看得到 **HTTPS 的明文**（加密前），传输层看得到
**明文 HTTP 的真实字节** —— 两层互补，缺一不可。HTTPS 在 socket 层
是密文，本来也看不懂。

**已知边界**（写在这里，不装作不存在）：裸 socket 手写报文若把
body 拆到第二次 `sendall`（headers 一次、body 一次），第二段看不到。
常见写法是一次发完，那种情况下 body 一起扫。

### 2. `urllib` 的 body 此前完全不检查

**绕过**：`urlopen(Request(url, data=payload))` —— body 挂在 Request
对象上，而旧代码只看 `urlopen` 的 `data` 形参（恒为 None）。
方法查得到、body 查不到，一个字都不用混淆。

**修法**：两处都取（形参 + Request 对象），`get_method()` 也一并尊重。

### 3. 词表补口（删库那几种写法）

| 写法 | 之前 | 现在 |
|---|---|---|
| `TRUNCATE users`（不带 TABLE） | 放行 | 拦截（R-102） |
| `FLUSHDB` | 放行 | 拦截（R-102） |
| `db.dropDatabase()` / `drop_collection` / `collection.drop()` | 放行 | 拦截（R-102） |
| `GRANT ALL ... TO` / `REVOKE ... FROM` | 仅记录（R-201） | **拦截**（新规则 R-107） |
| `ALTER TABLE ... DROP COLUMN` | 仅记录 | **拦截**（R-107） |

误伤控制：`TRUNCATE` 后面跟自然语言词（the / file / string / data…）
仍放行；`grant` 不再当裸词拦 —— OAuth 的 `grant_type`、IAM 里的
`{"permission":"grant"}` 都是正常请求，判据改成 SQL 语句形态
（跟着权限词，或 `GRANT x TO y` 句式）。

### 4. PowerShell 通道补上 `Invoke-*`

**绕过**：`Invoke-RestMethod -Method Delete -Uri ...` —— 它既不走
`curl`，也不在 PATH 上，原先只做了"删 curl 别名 + 前置 PATH"，
这条完全是裸的。

**修法**：profile 指向的 `bin/waf.ps1` 里，用
`ProxyCommand.Create` 从**已安装的 cmdlet 本身**生成包装函数
（参数表跟着对方的版本走，不会因为 PS 版本不同而漏参数），
在 `process` 块开头插一次检查，转给 `Microsoft.PowerShell.Utility\`
模块限定名（避免包住自己）。检查落在 `waf/pshook.py`。
执行策略：Python 起不来 / 检查异常 → 告警并放行（不掐断用户的脚本）；
命中 → 抛错并打印与 curl 通道完全一致的 JSON，退出码 126。

### 5. 顺带修掉的两个隐藏问题

**a) 补丁会叠层。** `autohook._requests_ready()` 检查的是
`requests.Session.request`，而 guard 包的是 `Session.send` ——
判断永远为假，import 钩子摘不掉，每次 import HTTP 库都
`force=True` 重装一遍。实测后果：**一次 `requests.get` 被扫 36 次**，
事件列表里同一条请求重复出现。修法：每个补丁函数幂等
（`_waf_wrapped` 标记）+ `_requests_ready()` 改看真实的补丁点。

**b) 冷启动会栈溢出。** `_check_cmd → _console_gate() → get_engine()`
（引擎首次加载）`→ ReDoS 探测子进程 → guarded_popen → _check_cmd → …`
每层都认为自己该查。触发条件是"引擎冷 + 探测缓存冷"（改规则会换
缓存指纹，第一次必中；全新安装同理）。修法：重入闸提到 `_check_cmd`
最前面 + 探测子进程由调用方显式声明 `internal_call()`。

### 6. 同一请求只扫一次

传输层挂钩装上后，一个 `requests.post` 会穿过多层
（requests → urllib3 → http.client → socket）。飞行指纹
（同调用链 + 同 method/path）保证只扫一次、只记一条事件；
循环里的连续请求不受影响（有回归盯着）。跨 `await` 的隔离用
`contextvars`，避免 aiohttp 并发任务互相误判。

### 7. 自测隔离

`wafctl test` 现在在**子进程 + `HUNTGUARD_NO_HOOK=1`** 里跑：
套件里有大量"故意发破坏性请求"的用例，而只要控制台开着，
本进程就会被注入运行时护栏（socket/subprocess 是进程级的）——
用例自己发的包被护栏先拦掉，结果变成"取决于你此刻开没开控制台"。
实测开着控制台跑，110 项里报 10 项 `WafBlocked`。

自测总数 230 → **279**（新增 `tests/test_transport.py` 49 项：
传输层、urllib body、幂等、递归闸、新规则、PowerShell 钩子）。

### 升级方式

```bash
wafctl stop && wafctl start
```

PowerShell 用户：重启 PowerShell（或 `. $PROFILE`）让新的
`bin/waf.ps1` 生效。

---

## 1.1.5 — 2026-10-15

### 重要修复：Python 通道此前完全失效

**症状**：AI 用 `urllib` / `requests` 发 `DELETE` 删除本地文件，
不被拦截 —— 而同样的动作换成 `curl` 就拦得住。

**根因**：`autohook._guess_root()` 只从 `sys.path` 扫描
`waf/guard.py`，而 `PYTHONPATH` 指向的是 `<安装目录>/hooks`
（里面只有 `sitecustomize.py`，没有 `waf/` 子目录）——
**永远找不到安装根目录**，`_check_active()` 随即返回 False，
护栏一直没装上。

实测链条：`sitecustomize` 确实被加载了，但 `waf.guard` 与 `autohook`
都没进 `sys.modules`，`urlopen` 仍是原版。

**影响面**：Python 进程里的所有请求（urllib / requests / httpx /
aiohttp）与 `subprocess` / `os.system` 命令都不检查。
`curl` 通道正常（走 `bin/curl` shim，不依赖这个函数），
所以缺口只在"AI 写 Python 脚本"时暴露 —— 而这类用法很常见。

**修法**：`_guess_root()` 优先读 `HUNTGUARD_HOME` / `AGENTWAF_HOME`
主指针（安装时已写入用户环境变量），其次才扫 `sys.path`。

**验证**：修复前 `urlopen` 是原版 → DELETE 放行、文件被删；
修复后 `urlopen` 是 `waf.guard.guarded_urlopen` → DELETE 被拦、
文件未被删除。

### 升级方式

```bash
wafctl stop && wafctl start
```

控制台重新读取修复后的模块（正在运行的进程用的是旧代码）。

---

## 1.1.4 — 2026-10-15

### 拦截能力

- **动作位匹配**：`delete` / `remove` / `purge` 等动词在分隔符之后才算
  命中（`item_delete`、`user-remove`、`deleteById` 都覆盖），
  同时放行软删除字段（`deleted_at`、`is_deleted`、`deletedAt`）。
- **忽略大小写**：`deleteDraft`、`DeleteRecord` 等命名形态同样命中。
- **归一化绕过防护**：URL 编码、HTML 实体、Unicode 转义、全角、
  零宽字符、分隔符拆字（`d_e_l_e_t_e`）都会被还原后再判定。
- **全部出现位置**：同一字段里敏感词出现多次时逐个检查，
  不会因为第一个落在白名单语境就漏掉后面的。
- **搜索参数豁免**：`?q=how+to+delete+my+account` 这类自然语言描述
  放行，但搜索参数里出现 SQL 语法（`delete from`、`drop table`）仍然拦。

### 四条接入通道

| 通道 | 覆盖范围 |
|---|---|
| curl shim | cmd AutoRun + PATH，拦截命令行 curl |
| BASH_ENV | Git Bash 非交互会话 |
| PowerShell profile | PS 会话里的 curl 调用 |
| PYTHONPATH 钩子 | 普通 Python 进程的 requests / httpx / urllib3 / aiohttp 请求 |

Python 钩子同时覆盖 `subprocess` / `os.system` 调用破坏性命令的情况。

### 安全设计

- **ReDoS 防护**：病态正则在加载时用子进程探测 + 超时挡住，
  不会让每个请求卡死；allowlist 与 exclude 里的正则同样检查。
- **代理上游 TLS 默认校验**，可用 `WAF_PROXY_INSECURE=1` 关闭（打自签靶场）。
- **MITM 叶私钥用完即删**，CA 私钥落盘后收紧 ACL。
- **`--connect-to` / `--resolve` 改写出的真实主机参与白名单判定**，
  不能借白名单主机名把流量引到别处。
- **跨进程写锁**：控制台与独立 CLI 并发改规则时不会互相覆盖。

### 明确的能力边界

这不是安全边界，是**防手滑的护栏**。使用手册里完整列出了所有逃生开关
（单条环境变量、直接改规则文件等）。用它挡住"AI 顺手执行的不可逆操作"，
不要指望它能拦住有意绕过的对手。

---

## 1.0.0 — 2026-10-13

首个版本：规则引擎 + curl 拦截 + 本地控制台 + 规则热重载。
