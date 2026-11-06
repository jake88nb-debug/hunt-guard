# HuntGuard 使用说明

## 安装

要求 Windows 10 / 11 与 Python 3.7 以上，无第三方依赖。

1. 解压或 `git clone` 到任意目录
2. 双击 `install.bat`，写入 cmd AutoRun、BASH_ENV、PowerShell profile、PYTHONPATH
3. 双击 `start.bat` 启动控制台
4. 双击 `stop.bat` 停止拦截

控制台默认地址 `http://127.0.0.1:8898`，代理默认 `127.0.0.1:8899`，均只监听回环。
修改端口：临时设置 `HUNTGUARD_PORT`，或修改 `data/config.json` 的 `api_port`、`proxy_port`。

拦截需要同时满足：`data/run/active.json` 在 20 秒内更新过，且
`data/rules.json` 的 `settings.enabled` 不为 false。任一不满足即透传。

## 拦截通道

| 通道 | 接入方式 | 覆盖范围 |
|---|---|---|
| curl | `bin\` 前置到 PATH | cmd、Git Bash、PowerShell 中的 `curl` |
| PowerShell | profile 加载 `bin\waf.ps1` | `Invoke-WebRequest`、`Invoke-RestMethod` |
| Python | `PYTHONPATH` 指向 `hooks/sitecustomize.py` | requests、urllib、httpx、aiohttp、urllib3、http.client、socket；subprocess、os.system |
| 代理 | `start-proxy.bat`，客户端设 HTTP 代理 | 任意 HTTP 客户端；HTTPS 需开启 MITM |
| Burp | 加载 `burp\burp_waf.py`（Jython） | Burp 内的请求 |

单次运行带护栏：`waf-run python exp.py`。脚本内启用：

```python
import waf.guard
waf.guard.install_guard()
```

## 开关与放行

| 方式 | 作用 | 范围 |
|---|---|---|
| `wafctl on` / `wafctl off` | 开启 / 暂停拦截 | 全局，持久 |
| `wafctl unlock --minutes N --reason "..."` | N 分钟内放行，到期恢复 | 全局，定时 |
| `WAF_DISABLE=1` | 跳过检查 | 当前进程 |
| `HUNTGUARD_NO_HOOK=1` | 不装 Python 钩子 | 当前进程 |
| `WAF_ALWAYS_ON=1` / `WAF_ALWAYS_OFF=1` | 忽略控制台状态 | 当前进程，测试用 |
| `WAF_PROXY_INSECURE=1` | 代理不校验上游证书（默认校验） | 当前进程 |

控制台 API 默认无鉴权，可设置 `data/config.json` 的 `auth_token`。

## 规则

在控制台「拦截规则」页编辑，或直接修改 `data/rules.json`，改动即时生效。

| 字段 | 说明 |
|---|---|
| `id` / `name` | 编号与名称 |
| `severity` | critical / high / medium / low |
| `action` | block 拦截，monitor 仅记录 |
| `match_mode` | substring（默认）/ word / regex |
| `keywords` / `regex` | 关键词与正则同时生效 |
| `exclude` | 命中点前后 24 字符内出现即忽略该命中 |
| `sources` | 限定检查字段，默认全部 |
| `enabled` / `note` | 是否启用 / 备注 |

```json
{
  "id": "R-900",
  "name": "删除类接口",
  "enabled": true,
  "severity": "critical",
  "action": "block",
  "match_mode": "substring",
  "keywords": ["delete", "remove"],
  "regex": ["(?:^|[=/._-])delete(?![a-zA-Z0-9_])"],
  "exclude": ["deleted_at", "is_deleted"],
  "note": ""
}
```

放行名单同样写在 `data/rules.json`：

```json
{"id": "A-100", "source": "host", "pattern": "^lab\\.local$", "enabled": true}
```

`source` 取 `url`、`host` 或 `any`；`url` 匹配完整 URL，`host` 匹配主机名。

内置规则按 `defaults_rev` 迁移：新增默认规则自动补齐，用户修改过的规则
不会被覆盖，删除的默认规则不会恢复。

## 命令

```bash
wafctl on | off | intercept
wafctl start [--proxy] | stop | status | doctor
wafctl check "http://x/delete.php"          # 退出码 126 表示会拦
wafctl rules list
wafctl mode monitor
wafctl events -n 20 --blocked
wafctl events clear [--keep-days 7]
wafctl install-path [--machine]
wafctl uninstall-path [--purge-data]
wafctl test
```

## 默认规则

拦截：R-101 删除/销毁、R-102 数据库破坏（drop、TRUNCATE、FLUSHDB、
dropDatabase）、R-103 磁盘破坏、R-104 账户删除、R-105 短删除指令、
R-106 删除命令的 Windows/脚本写法、R-107 权限与表结构破坏、
R-203 反弹 Shell、R-301 脱库、R-302 后门持久化、R-303 痕迹清理、
R-304 云/容器/IaC 删除、R-305 备份删除、R-306 权限体系破坏、
R-307 安全组件关闭、R-308 服务中断、R-310 Git 历史破坏、R-314 密码重置。

仅记录：R-201 危险写操作、R-202 漏洞利用痕迹、R-309 凭证转储。

## 边界

- 交互式 shell 直接输入的 `rm`、`Remove-Item` 不拦；脚本经 subprocess / os.system 执行的命令会拦
- 其它语言的 HTTP 客户端需经代理接入
- `curl.exe` 全路径、`powershell -NoProfile`、管理员进程需 `install-path --machine`
- 未开 MITM 的 HTTPS 只能看到主机名
- `-F` / `-T` 上传文件只扫开头
- 请求体超过 `max_scan_bytes`（默认 256KB）拒绝发送；`unlock` 窗口内放行但不完整检查
- `br` / `zstd` 压缩请求体无法解码，拒绝
- 裸 socket 分两次发送的 body 第二段不检查
- Base64、UTF-16、二进制、加密载荷不在关键词模型覆盖范围内
- 控制台启动前已 import 请求库的长驻进程不会补装钩子
- 控制台卡顿超过 20 秒（GC、调试断点、IO 阻塞）等同于未开启，期间请求透传；
  需要更长的判定窗口就保持它在运行，不要把它挂在断点上调试
- `data/events.db` 与其 `-wal` 文件明文保存拦截记录（完整 URL 与 payload），
  需要清除时运行 `wafctl events clear`

## 卸载

双击 `uninstall.bat`，撤销 cmd AutoRun、BASH_ENV、PowerShell profile、
PYTHONPATH、`HUNTGUARD_HOME` / `AGENTWAF_HOME` 与相关 PATH 条目，并逐项复核。

```bat
set WAF_UNINSTALL=yes   && uninstall.bat   :: 仅撤销接入
set WAF_UNINSTALL=purge && uninstall.bat   :: 撤销接入并删除 data
set WAF_UNINSTALL=all   && uninstall.bat   :: 全部删除
```

等价的命令行方式：`wafctl uninstall-path [--purge-data]`。
机器级 PATH 需要管理员权限移除。

## 故障排查

先运行 `wafctl doctor`。

| 现象 | 处理 |
|---|---|
| curl 没被拦 | 查看解析顺序，运行 `wafctl install-path` 后新开终端 |
| 控制台开着仍不拦 | `wafctl intercept` 查看开关 |
| PowerShell 中 curl 报错 | 那是 `Invoke-WebRequest` 别名，用 `curl.exe` |
| 端口占用 | 修改 `data/config.json` 的 `api_port` |
| MITM 后证书报错 | 在控制台「代理/系统」页下载并导入 CA |
| 自测缺少用例 | 安全软件隔离了测试文件，加白名单后 `git checkout -- tests/` |

## 其它平台

Linux / macOS / WSL：

```bash
bash scripts/install_shim.sh
export PYTHONPATH="<安装目录>/hooks:$PYTHONPATH"
```

## 自测

```bash
wafctl test
```

约 365 项，在独立子进程中运行。
