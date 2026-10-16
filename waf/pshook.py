# -*- coding: utf-8 -*-
"""PowerShell 通道：Invoke-WebRequest / Invoke-RestMethod 的出站检查。

谁调用这个（正常无需手动跑）：
    bin/waf.ps1 里的包装函数 —— 它由 PowerShell profile 加载，
    把 ``Invoke-RestMethod`` / ``Invoke-WebRequest`` 这两个 cmdlet
    挡在前面，先问这里一句再放行。

为什么需要单独的入口（实测缺口）：
    PowerShell 通道原先只做了两件事 —— 删掉内置的 curl 别名、
    把 <安装目录>\\bin 前置到 PATH。于是 ``curl`` 走 shim 被拦，
    但 **Invoke-RestMethod 完全没人管**：它是 PowerShell 自己实现
    的 HTTP 客户端，既不过 curl，也不在 PATH 上，AI 写的 PS 脚本
    （``irm -Method Delete``、``iwr -Method POST -Body '{"sql":...}'``）
    一个字都不用混淆就能把删除请求发出去。

输入（stdin，JSON）：
    {"method": "DELETE", "uri": "http://x/y", "body": "...",
     "headers": {"k": "v"}}

输出与退出码（与 curl 通道完全一致，方便调用方统一处理）：
    0    放行
    126  命中 —— 结构化的拦截 JSON 已打到 stderr
    其它 检查过程本身出错（调用方按"放行 + 告警"处理，不让
         工具自身的故障掐断用户的脚本）

环境变量：
    WAF_DISABLE=1      完全绕过（应急）
    WAF_ALWAYS_ON=1    强制视为已开启（脱离控制台使用 / 测试）
    WAF_ALWAYS_OFF=1   强制视为未开启
    WAF_QUIET=1        拦截时不打印 JSON
"""

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import config, logstore, state               # noqa: E402
from waf.config import BLOCK_EXIT_CODE                # noqa: E402
from waf.engine import get_engine                     # noqa: E402
from waf.models import ScanTarget                     # noqa: E402

# stdin 的读取上限。正常调用方只会塞 method/uri/body/headers，
# 但 stdin 是外部输入，得有个上限（超出的部分截断并保留标记）。
MAX_STDIN = 4 * 1024 * 1024
MAX_BODY = 1024 * 1024


def _read_payload():
    raw = sys.stdin.buffer.read(MAX_STDIN + 1)
    if not raw:
        return {}
    if len(raw) > MAX_STDIN:
        raw = raw[:MAX_STDIN]
    try:
        data = json.loads(raw.decode("utf-8", "replace"))
    except Exception:
        # 拿不到结构就当裸文本扫 —— 宁可扫一段原文，也不要静默放行
        return {"body": raw.decode("utf-8", "replace")}
    return data if isinstance(data, dict) else {}


def _text(value, limit=MAX_BODY):
    """把任意 JSON 值变成可扫的文本（hashtable / 数组 / 数字都见过）。"""
    if value is None:
        return ""
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, (int, float, bool)):
        return str(value)
    try:
        return json.dumps(value, ensure_ascii=False)[:limit]
    except Exception:
        return str(value)[:limit]


def _headers(value):
    if isinstance(value, dict):
        out = {}
        for key, item in list(value.items())[:200]:
            out[_text(key, 512)] = _text(item, 4096)
        return out
    if isinstance(value, list):
        # PowerShell 的 -Headers 也接受 "K: V" 形式的字符串数组
        out = {}
        for item in value[:200]:
            line = _text(item, 4096)
            if ":" in line:
                name, _, rest = line.partition(":")
                out[name.strip()] = rest.strip()
        return out
    return {}


def main():
    if os.environ.get("WAF_DISABLE") == "1":
        return 0

    payload = _read_payload()

    config.ensure_dirs()
    logstore.init_db()
    engine = get_engine()

    # 与控制台开关联动 —— "没打开就不生效"这条规则对所有通道一视同仁。
    active, reason = state.should_intercept(engine)
    if not active:
        if os.environ.get("WAF_VERBOSE") == "1":
            sys.stderr.write("[agent-waf] 未拦截（%s），放行\n" % reason)
        return 0

    from urllib.parse import urlsplit

    uri = _text(payload.get("uri"), 8192)
    method = _text(payload.get("method"), 32).strip().upper()
    body = _text(payload.get("body"))
    headers = _headers(payload.get("headers"))
    if not method:
        # PowerShell 的默认：带 Body 时 Invoke-RestMethod 发 POST，
        # 否则 GET。这里跟着走，避免 method 字段空着被当成 GET 漏判。
        method = "POST" if body else "GET"

    host = path = query = ""
    try:
        parts = urlsplit(uri)
        host, path, query = parts.netloc, parts.path, parts.query
    except Exception:
        pass

    target = ScanTarget(kind="request", method=method, url=uri, host=host,
                        path=path, query=query, headers=headers, body=body,
                        tool="powershell")
    verdict = engine.scan(target, log=os.environ.get("WAF_NO_LOG") != "1")
    if verdict.blocked:
        if os.environ.get("WAF_QUIET") != "1":
            sys.stderr.write(verdict.to_json(
                indent=2,
                include_meta=os.environ.get("WAF_VERBOSE") == "1") + "\n")
        return BLOCK_EXIT_CODE
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:                     # noqa: BLE001
        sys.stderr.write("[agent-waf] PowerShell 通道检查失败：%r\n" % (exc,))
        sys.exit(1)                              # 调用方会告警并放行
