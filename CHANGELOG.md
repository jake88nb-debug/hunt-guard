# 更新记录

版本号规则：`主.次.修`。拦截面变化、规则集变化、安全相关修复 → 提"次"；
仅文档/文案 → 提"修"。

---

## 1.1.11 — 2026-10-16

第三轮抽查：7 条准确性问题全部复现并修复，另按性能建议做了两项
**不改变判定结果**的优化（实测 256KB body 从 ~1s 降到 ~0.4s）。

### 1. 命令行 `-H @file` 没读文件

上一版只修了配置文件里的 `header = @file`，命令行的 `-H @file` 仍然
把字面量当头部。本机用 curl 8.18 验证 `-H @file` 会把文件里的头真实
发出，所以是实打实的绕过。现在 `-H @file` / `-b @file` /
`--url-query @file` 统一走 `_read_maybe_file`（超限同样拒绝）。

### 2. 本地输出参数被当成请求内容（纯误报）

`-o` / `-D` / `-w` / `--output-dir` 等不在选项表里，值漏成位置参数：
`curl -o delete.txt http://x/` 直接被拦。现在维护了**本地选项表**
（输出文件 / 计时 / 重试 / 限速 / 范围等），值被消费但不进扫描面；
生成 `raw_cmd` 时这些值替换成 `<local>`（否则 raw_cmd 仍会命中）。
顺带修了 `-o 1.5` 被归一化成 `http://1.5` 影响白名单的问题。

### 3. 配置文件只扫了白名单里的选项

1.1.10 为修注释误报改成"只处理已知 key"，结果 `connect-to` /
`resolve` 这类**改写连接目标**的选项被整个忽略：
`connect-to = good.com:443:evil.com:443` + 白名单命中 good.com →
实际流量去 evil.com 而检测面看不见。现在它们按命令行同等处理，
进 `real_hosts` / `X-WAF-Real-Host`，host 白名单也不会被骗。

### 4. 单标签主机名（`metadata/delete`）不算 URL

`_normalize_url_token` 要求有点 / 端口 / localhost，于是内网单标签名
（SSRF 常用的 metadata、intranet）不进 urls，白名单命中第一条 URL 后
整条放行。现在**位置参数一律按 URL 处理**（选项值已被正确消费，
不会混进来）。

### 5. 超限拒绝不认 unlock / 白名单

错误提示让人去 `wafctl unlock`，但拒绝发生在引擎之前 —— 解锁了照样
被拒，自相矛盾。现在 guard 在拒绝前检查 `unlock_remaining()` 与请求级
白名单（新增 `engine.request_allowed()`），代理在解锁窗口内放宽到
32MB；curl 通道的 `_BODY_LIMIT` 也加了 `strict` 开关。

### 6. 文本模式仍静默截断

`/api/scan` 的 text 模式与 `wafctl check` 的纯文本模式只扫前
`max_scan_bytes` 就报"未命中"，容易误导成"干净"。现在两处超限都
明确拒绝（413 / 退出码 2）。

### 7. 压缩请求体没解压

客户端发 `Content-Encoding: gzip` 时，`action=delete` 压缩后完全看不见，
目标却能解压执行。新增 `waf/bodycodec.py`：gzip / deflate（含裸
deflate）解压后扫描，解压上限 8MB 防 zip bomb；`br` / `zstd` / 损坏 /
膨胀过大 → **拒绝**（guard 抛 `body_encoding`，代理回 415）。

### 性能（实测，不改变判定结果）

- **归一化按需执行**：没有 `%` 就不跑 url_decode，全 ASCII 不跑
  fold_fullwidth，没有分隔符不跑 compact……（每条都是"触发条件不存在
  ⇒ 必然是空操作"的等价变换）
- **上游 TLS 上下文进程内缓存**（原来每请求新建一次）

本机 `engine.scan` 实测：小 GET 5.9→3.2ms，64KB 269→103ms，
256KB 1057→394ms（约 2.6 倍）。**没有**做"正则字面量预筛"——
那需要证明"匹配必然包含某字面量"，一旦判断错就是漏拦，收益不值这个风险。
也没做日志异步批量（会破坏测试里"写完立刻读"的语义）。

### 未改（取舍）

`?q=delete` 这类搜索词仍会拦。改成"按参数名放行"正是本项目反复警告的
可构造豁免（payload 塞进 `q=` 就免检），在"防误报"和"防绕过"之间
选了后者；R-101 已能放过自然语言句子形态。

自测 339 → **360** 项（新增第三轮回归 21 项）。
---

## 1.1.10 — 2026-10-16

第二轮抽查：1.1.9 修的是"单一主路径"，**组合写法**仍有绕过。8 条全部
复现并修复。共同教训：单条路径修好了不等于拦住 —— 要按"组合"写用例。

### 1. 多 URL 时 host 白名单又失效

额外 URL 的判定只查 `source=url` 的条目（`_url_allowed_any`），于是
`curl http://lab.local/a --next http://lab.local/delete` 里 host 白名单
不生效 → 误拦。新增 `_url_or_host_allowed()`：url 条目按整条匹配、
host 条目按主机名匹配，额外 URL 用它判。

顺带补了一个更深的洞：`meta["urls"]` 里的额外 URL 原先**只参与白名单
判定、不参与扫描**（curl 通道靠 raw_cmd 兜住，代理/guard 构造的
target 没有 raw_cmd 就彻底不扫）。现在它们作为 `url` 字段进扫描面。

### 2. 无 scheme 的 URL 不进 urls

`curl` 接受 `victim.local/delete`（默认按 http 处理），而 `_is_url`
只认带 scheme 的 → 该 URL 根本不进 urls。于是
`curl http://127.0.0.1/x --next victim.local/delete` 被白名单整条放行。
新增 `_normalize_url_token()`：无 scheme 但像主机名（有点/端口/localhost）
的统一补 `http://`；`target.url` 也归一化，host 白名单才能匹配。

### 3. 配置文件里的 URL 不参与 urls

`-K cfg` 或默认 `.curlrc` 里的 `url = ...` 只进 `config_urls`，
不进 `info["urls"]` → 白名单命中命令行 URL 后整条放行。
现在配置 URL 同时进 `extra_urls`，并**在收集 urls 之前**吸收
（顺序错了的话加了也没用 —— 第一版就是这么错的）。

### 4. 配置文件引用的文件内容未扫描

`data = "@payload.txt"` / `header = "@hdr.txt"` / 嵌套 `config = other.cfg`
只把**路径字符串**当内容扫，文件内容照样发给目标。
重写 `_absorb_config_text()`：按选项名分派到原有管线
（`_absorb_flag` / `_absorb_config_file`），@file / @- / 递归 config
都真的读，递归深度上限 5，`-K -` 也遵守扫描上限（不再硬编码 262144）。

### 5. 256KB–32MB 仍是盲区

1.1.9 只做到"超过 32MB 不截断"，但引擎每字段只扫 `max_scan_bytes`
（默认 256KB），代理/guard 却把完整 body 转发。
现在统一：**guard 与代理都用同一个 `max_scan_bytes`**，
超出即拒绝（guard 抛 `WafBlocked`、stage=oversize；代理回 413），
和 curl 通道的策略一致。

### 6. `-K -` 静默截断

配置来自 stdin 时硬编码读 262144 字节，超长就截断后交给 curl
（用户的选项被静默丢掉）。改成 `_BODY_LIMIT` + 超限抛 `BodyTooLarge`。

### 7. 回归：`.curlrc` 注释被当请求内容扫

上一版把整份配置文本塞进扫描面，于是 `.curlrc` 里写一句
`# do not remove this` 之后**所有** curl 都被拦。
现在只处理有效选项的值：注释、说明文字、未知选项都不进扫描面。

### 8. 代理 CONNECT 仍是 fail-open

`_scan_connect` 的 `except` 返回 `None`，调用方把 None 当"允许" →
引擎一异常，HTTPS 隧道直接放行。现在与普通请求一致按 `fail_mode`
处理，默认拒绝。

### 测试结构调整（顺带解决本机跑不全的问题）

`tests/test_waf.py`（93KB、满是破坏性载荷）在本机会被安全软件在
Python 读取时隔离（EBADF + 删除），导致本地 `unittest discover`
永远少 110 项。按类边界拆成 `test_waf_core.py` / `test_waf_guard.py` /
`test_waf_rules.py` 三个文件后不再触发（实测可读、可跑）。

自测 304 → **339** 项（新增第二轮回归 17 项，均在 `tests/test_audit_p0.py`）。
---

## 1.1.9 — 2026-10-16

外部审计里 9 条 P0，**逐条复现后全部确认为真**（3 条从代码即可确认，
6 条写了复现脚本），已修 + 回归测试。共同点：都属于"配置/解析说了
一套，实际做的是另一套"。

### 1. `source=host` 白名单实际失效

`_request_level_allow` 不管 source 是 url 还是 host，都拿完整 URL 去
匹配。`{"source":"host","pattern":"^lab\\.local$"}` 配
`http://lab.local/delete` 永远不命中 —— 用户以为放行了本机靶场，
实际照样被拦。现在 host 条目按主机名（含去端口形式）匹配，
url 条目按完整 URL 匹配。

### 2. 多个 `--url` 只保留最后一个

`curl --url A --next --url B` 里 A 被直接丢掉。配合白名单就是：
`--url http://127.0.0.1/x --next --url http://victim/delete`
→ 白名单命中第一条 → 整个请求免检 → victim 上的 delete 不检查。
现在每个 `--url` 都追加进 `extra_urls`，和位置参数一起收全。

### 3. curl 默认配置文件完全没扫

curl 自动读 `~/.curlrc` / `%APPDATA%\_curlrc` / `$CURL_HOME/curlrc` /
`$XDG_CONFIG_HOME/curlrc`，我们只在显式 `-K` 时读。于是把
`url = http://victim/delete` 写进默认配置，再跑一条看起来人畜无害的
curl 就能绕过。现在按 curl 的顺序读这些文件并纳入扫描面；
`-q`/`--disable` 作为首参时跳过（curl 此时也不读）。

### 4. 扫描字节 ≠ 发送字节

- `-d @file` 只扫前 256KB，但原文件**完整发送** → payload 放后面即绕过
- `-d @-` 只读 256KB，然后把截断内容写临时文件交给 curl →
  用户上传的内容被**静默截短**
- 代理 chunked / Content-Length 超 32MB 时 break，按截断长度重写
  Content-Length → 大请求被改坏、解析错位

现在原则统一：**扫描过的字节 = 实际发出去的字节**。超限直接拒绝
（curl 通道退出 126 并说明怎么放行；代理回 413），不再截断后照发。
`-F`/`-T` 的文件上传内容仍是"只扫开头"（二进制载荷），已在 USAGE 写明。

### 5. 代理在引擎异常时 fail-open

`proxy.py` 里 `except Exception` 直接构造 `blocked=False` 的 verdict ——
引擎一出问题，代理就成为纯透传，和 `fail_mode=closed` 的承诺相反。
现在与 guard / curlshim 一致：按 `fail_mode` 决定，默认拒绝。

### 6. 命令门槛词表缓存永不失效

`_GATE_WORDS_CACHE` 算一次用一辈子，而且派生自**内置默认规则**。
用户在 `data/rules.json` 里新增一个破坏性关键词后，已在跑的进程
（长驻 AI 会话、服务进程）永远看不见它，直到重启。
现在按 (路径, mtime, size) 失效，且派生自**生效中的**规则文件。

### 7. settings 校验缺口

只校验了 mode / fail_mode。`max_scan_bytes: "abc"` 能通过校验，
运行时 `int("abc")` 抛异常 → 外层按 fail_mode=closed 处理 →
**所有请求全被拦**。一个笔误把工具变成拒绝服务。
现在逐项校验类型与范围，非法值回落默认值（合法值原样保留），
normalize 过滤未知 op，字符串 "false"/"0" 正确转 bool。

### 8. `strip_sql_comment` 在带映射变体里是空操作

`_strip_with_map` 对**单个字符**跑 `SQL_COMMENT_RE`，而 `/*...*/`
是多字符，永远匹配不上 —— 开了这个归一化选项的规则等于没开。
现在按片段匹配，并把注释替换成**空格**（直接删会得到 `droptable`，
反而匹配不到 `drop table`）。偏移仍映射回原文。

### 9. 自身接口豁免允许空 path

`if path and not (...)` —— path 为空时直接通过路径判据，只要目标在
回环 + 控制台端口，空 path 请求就被当成自身接口跳过检查。
现在要求 path 非空且明确是 `/api/` 路由。

### 回归测试

新增 `tests/test_audit_p0.py` **27 项**：每条 P0 一个可复现的用例
（含代理 413 / fail-closed 的 socket 级测试、host 白名单正反例、
`.curlrc` 端到端拦截、超限拒绝、以及"非法配置不会导致全拦"）。
自测 279 → **304** 项。
---

## 1.1.8 — 2026-10-16

### 一键卸载（双击 `uninstall.bat`）

别人不想用了，得能干干净净地走。新增 `uninstall.bat`：双击 → 回答
两个问题 → 恢复原状。做三件事：

1. 停掉控制台（如果正开着）
2. 撤掉安装时写进系统的全部接入（cmd AutoRun / PowerShell profile 指针 /
   BASH_ENV / PYTHONPATH / `HUNTGUARD_HOME` + `AGENTWAF_HOME` / PATH 条目）
3. **复核**：重新查一遍这些位置，报告"实际还剩什么"

第 3 步是特意加的：`uninstall()` 的返回值说的是"我执行了什么" ——
权限不足、注册表不可用、本来就没装过，三种都是"跳过"，在用户眼里
和"失败"没区别。所以 `wafctl uninstall-path` 现在跑完会调用新的
`install_path.verify_clean()` 逐项复查，有残留就非零退出码。

配套：

* `wafctl uninstall-path --purge-data` —— 顺带删 `data/`
  （拦截记录 / 规则 / CA 证书）。默认不删。
* 无人值守入口（自动化 / AI 用）：`WAF_UNINSTALL=yes|purge|all`。
  为什么不靠 `echo Y | uninstall.bat`：cmd 的 `set /p` 第一次调用会把
  整个重定向缓冲当成一个值吃掉（实测 `_ANS` 变成三行连在一起，
  后面的 `if` 直接语法错），多提问的批处理没法用管道驱动。
* 自删这个文件夹前会**验身**：`waf\cli.py` + `README.md` +
  `uninstall.bat` 三者齐全、且不是盘根才允许；否则提示手动删。
* `data/` 清理有硬闸：盘根一律拒绝，且默认只肯删安装目录内的路径
  （`purge_data_dir` 的 `require_inside_root`）。

### 过程中修掉的两个批处理坑（都是真跑出来的，不是读代码看出来的）

* **块内未转义的括号**：`echo ... (keeping data)...` 写在
  `if ... ( ... ) else ( ... )` 里，cmd 会在第一个未转义的 `)` 处
  提前结束块，后面整行变成 "此时不应有 ..."。选"保留 data"的用户
  一按回车就崩。已改为 `^(` `^)`。
* **提问必须在 `call` 之前**：批处理里 `call` 另一个批处理会吃掉继承
  的 stdin，导致其后的 `set /p` 读不到东西（自动化场景尤其明显）。
  现在所有提问都排在定位 Python 之前 —— 顺带好处是：用户答完 Y 才
  发现没装 Python 时，什么都还没改。

### 自测

新增 `tests/test_uninstall.py`（16 项）：假注册表 + 临时 profile/bashrc/
site-packages 上跑完整的**装 → 卸 → 复核干净**，并断言用户自己的
PATH 条目、profile 内容、PYTHONPATH 一个都没被吃掉；
另含 `data/` 清理的防呆（拒绝盘根、拒绝安装目录外）与
`uninstall.bat` 的静态检查。批处理本身另在沙箱副本里跑过三种无人值守
模式与交互流程（`cli.py` 换桩，不碰本机）。

自测 279 → **295** 项。
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
