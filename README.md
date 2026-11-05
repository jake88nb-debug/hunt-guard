# HuntGuard

给授权安全测试用的出站护栏。在请求或命令发出前拦住 `delete`、`remove`、
`rm -rf`、`drop`、`truncate` 这类不可逆动作。

覆盖 Windows 上的 `curl`、PowerShell（`Invoke-WebRequest` / `Invoke-RestMethod`）、
Python 请求库与 `subprocess`、Burp 扩展、HTTP 代理。只依赖 Python 标准库。

命中时输出：

```json
{"success": false, "blocked": true, "reason": "命中敏感词，请求已被拦截",
 "stage": "content_scan", "hits": [{"source": "query", "keyword": "delete",
 "matched_text": "delete=test.txt", "rule_id": "R-101"}]}
```

只有打开控制台才生效；关掉后所有命令原样放行。

## 下载与安装

环境：Windows 10 / 11，Python 3.7 以上。

1. 下载 ZIP（Code → Download ZIP）解压，或 `git clone https://github.com/jake88nb-debug/hunt-guard.git`
2. 双击 `install.bat`，写入各通道接入
3. 双击 `start.bat`，控制台打开，拦截生效
4. 验证：`curl "http://127.0.0.1/1.php?delete=test.txt"`，输出 `"blocked": true` 即生效

关闭：双击 `stop.bat` 或 `wafctl off`。
卸载：双击 `uninstall.bat`，撤销全部接入并复核结果（`data/` 与目录默认保留）。
临时放行删除类请求：`wafctl unlock --minutes 10 --reason "..."`。

完整说明见 [USAGE.md](USAGE.md)，版本记录见 [CHANGELOG.md](CHANGELOG.md)。

## 作者

Jake — [@jake88nb-debug](https://github.com/jake88nb-debug)

## 免责声明

仅用于你自己拥有或已获得书面授权的安全测试。未授权测试可能违法，后果自负。

本工具是护栏，不是安全沙箱：它挡不住刻意绕过（修改环境变量、更换客户端、
修改规则均可使其失效），也不提供任何安全保证。软件按 MIT 许可（见
[LICENSE](LICENSE)）以现状提供，不附带任何担保，因使用造成的损失作者不承担责任。

使用前请对重要目标做好快照或备份，对生产环境使用只读账号。
