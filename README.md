# HuntGuard

**给授权安全测试用的出站护栏。** 在请求 / 命令真正发出去之前，
拦住 `delete` / `remove` / `del` / `rm -rf` / `drop` / `truncate`
这类**不可逆**动作 —— 手滑或 AI 误操作，都不会把你在测的东西删掉。

> 下载解压、双击 `start.bat` 就能用：不用配路径、不用 `pip install`、
> 不需要管理员权限、**只依赖 Python 标准库**。
> 而且**你没打开它就不生效** —— 关掉控制台，所有命令原样放行、不留记录。

---

## 它拦什么

命中后会打印结构化 JSON，请求**不会**发到目标：

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

覆盖面（Windows）：

| 通道 | 说明 |
|---|---|
| **curl** | cmd / Git Bash / PowerShell 里敲的 `curl` 都经过拦截器 |
| **AI 工具会话** | ZCode / Claude Code / Codex 等执行 shell、以及它们现场写的 Python 脚本 |
| **Python 脚本** | `requests` / `urllib` / `httpx` / `aiohttp` / `urllib3` / `http.client` / 裸 `socket` 发出的请求；`subprocess` / `os.system` 执行的删除命令 |
| **PowerShell** | `Invoke-WebRequest` / `Invoke-RestMethod` |
| **Burp Suite** | 官方扩展（Jython），命中请求不到达目标 |
| **HTTP 代理** | 浏览器 / 其它工具设 `127.0.0.1:8899` 即可 |

默认规则里"拦截"档覆盖：删除/销毁、数据库破坏（`drop table`、
`TRUNCATE`、`FLUSHDB`、`dropDatabase`…）、磁盘破坏、账户删除、
权限变更与表结构破坏、脱库外带、后门持久化、痕迹清理、
云/容器/IaC 删除、备份快照删除、防火墙关闭、Git 历史破坏、密码重置。
另有"只记录不拦截"的监控档，用来复盘 AI 跑过什么。

---

## 下载与安装

**环境要求**：Windows 10 / 11 + Python 3.7 以上（其余零依赖）

**方式一：下载 ZIP**

1. 页面右上角 **Code → Download ZIP**，解压到任意目录
   （建议路径里别带中文和空格）
2. 双击 **`install.bat`** —— 一次性配置（自动探测 Python / curl / Git Bash，
   把拦截接入四个通道；**所有文件都留在解压目录里**，删目录即卸载）
3. 双击 **`start.bat`** —— 控制台打开，拦截生效
4. 验证一下：

   ```bat
   curl "http://127.0.0.1/1.php?delete=test.txt"
   ```

   看到上面那段 JSON 就是生效了。

**方式二：git clone**

```bash
git clone https://github.com/jake88nb-debug/hunt-guard.git
cd hunt-guard
```

然后同样双击 `install.bat` → `start.bat`。

**关掉**：双击 `stop.bat`，或 `wafctl off` —— 之后一切回到原样。

**要用删除类请求测漏洞时**：`wafctl unlock --minutes 10 --reason "..."`
临时放行，到点自动恢复。

> 完整说明（通道原理、规则怎么写、逃生开关、故障排查、Linux/macOS）
> 见 **[USAGE.md](USAGE.md)**；版本变化见 [CHANGELOG.md](CHANGELOG.md)。

---

## 作者

**Jake** —— [@jake88nb-debug](https://github.com/jake88nb-debug)

---

## 免责声明

本工具**仅用于你自己拥有、或已获得明确书面授权的安全测试**。
用它去测你没权限的系统，可能违法，后果自负。

它是**护栏，不是安全沙箱**：目的是把"意外删除"从"敲错一个字就发生"
变成"必须是有意识的、多步的、留记录的操作"。它挡不住刻意的绕过
（改环境变量、换客户端、改规则都能让它失效），也不提供任何安全保证。

软件按 **MIT 许可**（见 [LICENSE](LICENSE)）以"现状"提供，
不附带任何明示或暗示的担保；因使用本工具造成的任何损失，
作者不承担责任。

用之前请对重要目标做好快照 / 备份，对生产环境使用只读账号。
