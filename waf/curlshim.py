# -*- coding: utf-8 -*-
"""curl 包装器：拦截命中敏感词的 curl 调用。

用法（正常无需手动调用，由 bin/curl.cmd | bin/curl 自动转发）:
    python -m waf.curlshim [原始 curl 参数...]

行为:
    * 拦截器未开启 → 直接转发给真实 curl（不做任何检查）
    * 已开启 → 解析 curl 参数并扫描
        - 命中 → 打印 JSON（同截图结构）→ 退出码 126，**不执行真实 curl**
        - 未命中 → 原样转发给真实 curl，退出码与输出完全一致

"已开启" = 控制台正在运行（心跳文件新鲜）且 settings.enabled 不为 false。

环境变量:
    WAF_DISABLE=1      完全绕过（不推荐，仅应急）
    WAF_ALWAYS_ON=1    强制视为已开启（脱离控制台使用）
    WAF_ALWAYS_OFF=1   强制视为未开启
    WAF_VERBOSE=1      输出诊断字段（target/tool/duration）
    WAF_QUIET=1        拦截时不打印 JSON
    WAF_REAL_CURL=path 指定真实 curl
    WAF_NO_LOG=1       不写入事件库
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import config, logstore, state               # noqa: E402
from waf.config import BLOCK_EXIT_CODE                # noqa: E402
from waf.engine import get_engine                     # noqa: E402
from waf.models import ScanTarget                     # noqa: E402

# 参数解析表
_VALUE_FLAGS_METHOD = ("-X", "--request")
_VALUE_FLAGS_URL = ("--url",)
_VALUE_FLAGS_HEADER = ("-H", "--header")
_VALUE_FLAGS_BODY = ("-d", "--data", "--data-raw", "--data-binary",
                     "--data-ascii", "--data-urlencode", "--json")
_VALUE_FLAGS_FILE = ("-F", "--form", "--form-string", "-T", "--upload-file")
_VALUE_FLAGS_UA = ("-A", "--user-agent", "-e", "--referer")
_VALUE_FLAGS_COOKIE = ("-b", "--cookie", "-c", "--cookie-jar")
_VALUE_FLAGS_AUTH = ("-u", "--user", "--proxy-user")
_VALUE_FLAGS_PROXY = ("-x", "--proxy")
_VALUE_FLAGS_MISC = ("--connect-to", "--resolve", "--interface", "--cert",
                     "--key", "--cacert", "--capath", "--oauth2-bearer",
                     "--aws-sigv4", "--url-query", "--hsts")
# 配置文件：内容里可以藏任意 URL / --data / -H，必须读进来一起扫。
# 早先 -K 出现在 SHORT_WITH_INLINE 却不在 ALL_VALUE_FLAGS，于是它的值
# 没人消费 —— 整份配置对检测完全不可见，光靠 `curl -K cfg` 就能绕过。
_VALUE_FLAGS_CONFIG = ("-K", "--config")

ALL_VALUE_FLAGS = (set(_VALUE_FLAGS_METHOD) | set(_VALUE_FLAGS_URL) |
                   set(_VALUE_FLAGS_HEADER) | set(_VALUE_FLAGS_BODY) |
                   set(_VALUE_FLAGS_FILE) | set(_VALUE_FLAGS_UA) |
                   set(_VALUE_FLAGS_COOKIE) | set(_VALUE_FLAGS_AUTH) |
                   set(_VALUE_FLAGS_PROXY) | set(_VALUE_FLAGS_MISC) |
                   set(_VALUE_FLAGS_CONFIG))

# 短选项可以连写取值：-XPOST / -dabc
SHORT_WITH_INLINE = {"-X", "-H", "-d", "-F", "-T", "-A", "-e", "-b", "-c",
                     "-u", "-x", "-o", "-w", "-K", "-E", "-m", "-U", "-Q"}


def _is_url(token):
    low = token.lower()
    if low.startswith(("http://", "https://", "ftp://", "ftps://",
                       "sftp://", "scp://", "file://", "smb://",
                       "ldap://", "gopher://", "dict://", "tftp://",
                       "ws://", "wss://")):
        return True
    return False


def parse_curl_args(argv):
    """把 curl 参数解析成 (ScanTarget, 解析出的字典)。

    入口处顺带清一次**上次运行**遗留的 stdin/cfg 临时文件。

    为什么挂在这里而不是 main()：`_cleanup_stdin_temps()`（清理本轮
    创建的临时文件）只挂在 main 的 finally 上，而这个函数也被别处
    调用 —— 控制台的 `/api/scan` curl 模式、测试、Burp 扩展。
    那些路径走不到 finally，也没有别的清理时机，临时文件会一直积累
    （实测 data/run/ 残留 9 个）。
    """
    try:
        _cleanup_stale_stdin_temps()
    except Exception:
        pass
    info = {
        "method": "GET",
        "url": "",
        "headers": [],
        "body_parts": [],
        "form_parts": [],
        "cookie": "",
        "user_agent": "",
        "referer": "",
        "user": "",
        "proxy": "",
        "upload": "",
        "has_body": False,
        # 以下收集"从文件读进来的内容"，供扫描面使用
        "upload_parts": [],
        "config_parts": [],
        "config_urls": [],
        "config_files": [],
        # MISC 组：值以前被消费掉就丢了（见 _absorb_flag 里的说明）
        "misc_values": [],
        "extra_query": [],
        "target_overrides": [],
    }
    positional = []
    idx = 0
    total = len(argv)
    while idx < total:
        token = argv[idx]
        if token == "--":
            positional.extend(argv[idx + 1:])
            break
        if token.startswith("-") and token != "-":
            flag = token
            inline = None
            if token.startswith("--"):
                if "=" in token:
                    flag, inline = token.split("=", 1)
            else:
                # 短选项连写
                base = token[:2]
                if len(token) > 2 and base in SHORT_WITH_INLINE:
                    flag, inline = base, token[2:]

            if flag in ALL_VALUE_FLAGS:
                if inline is not None:
                    value = inline
                    slot = idx                      # 值与 flag 同一个 token
                    # 改写 argv 时要还原出**原样的前缀**：
                    #   长选项 --config=-   → 前缀 "--config="（带等号）
                    #   短选项 -d@file      → 前缀 "-d"（不带等号）
                    # 早先一律用 prefix=flag，于是 --config=- 被改写成
                    # "--configD:\...\cfg-x.txt" —— curl 报 unknown option，
                    # **正常命令被弄坏**（fail-closed 方向不漏拦，但破坏了
                    # 可用性，实测发现）。等号在 split 时被吃掉了，
                    # 这里补回来。
                    prefix = flag + "=" if token.startswith("--") else flag
                elif idx + 1 < total:
                    value = argv[idx + 1]
                    slot = idx + 1
                    prefix = ""
                    idx += 1
                else:
                    value = ""
                    slot = None
                    prefix = ""
                # `-d @-` / `-K -` / `-T -`：内容来自 stdin，必须在这里
                # 接管。我们若不读走，curl 会读走、而我们没扫过 → 直接绕过。
                # 做法：读进内存扫一遍，落成临时文件，把**参数改写成指向
                # 该文件**（argv[slot]），这样 curl 拿到的内容与用户原意一致。
                #
                # 三种写法的前缀不同，回写时要还原：
                #   -d @-        body：值本身是 "@-"      → 回写 "@<tmp>"
                #   -K -         config：值就是路径       → 回写 "<tmp>"
                #   -T -         upload：值就是路径       → 回写 "<tmp>"
                # 踩过：早先只对 _VALUE_FLAGS_CONFIG 走 _take_config_stdin，
                # 其余都走 _take_stdin_value —— 而 -T - 的裸 "-" 不匹配
                # 后者的任何分支，于是"读不到内容"+"argv 不回写"。
                # 后者更严重：stdin 被 _read 消费后 curl 拿到空内容，
                # 用户上传的东西静默变空（实测发现）。
                taken = None
                if flag in _VALUE_FLAGS_CONFIG:
                    taken = _take_config_stdin(value)
                else:
                    taken = _take_stdin_value(value)
                    if taken is None and flag in ("-T", "--upload-file"):
                        # -T 接受裸 "-" 表示 stdin（不接受 @- 写法）
                        if (value or "").strip() in ("-", "<-"):
                            taken = _take_stdin_value("@-")
                            if taken:
                                # -T 要的是路径本身，不要 @ 前缀
                                taken = taken.lstrip("@")
                if taken is not None and slot is not None:
                    value = taken
                    argv[slot] = prefix + taken
                _absorb_flag(info, flag, value)
            idx += 1
            continue
        positional.append(token)
        idx += 1

    if not info["url"]:
        for token in positional:
            if _is_url(token):
                info["url"] = token
                break
    if not info["url"] and positional:
        info["url"] = positional[0]

    # 收集全部 URL（含 --next 之后的、以及多个位置参数）。
    #
    # 为什么必须全部收（实测发现的绕过）：
    #     curl <白名单URL> --next http://victim/delete
    # 请求级白名单命中**第一个** URL 后整个请求免检，第二个 URL 上的
    # delete 就看不见了。多 URL 是 curl 的正常能力（--next 分隔多组
    # 参数），不是刻意构造。这里把每个 URL 都记下来，交给引擎逐个判定。
    if not info.get("urls"):
        seen = []
        for token in positional:
            if _is_url(token) and token not in seen:
                seen.append(token)
        if info["url"] and info["url"] not in seen:
            seen.insert(0, info["url"])
        info["urls"] = seen

    if info["has_body"] and info["method"] == "GET":
        info["method"] = "POST"          # curl 的隐式行为

    target = _build_target(argv, info)
    return target, info


def _parse_target_override(flag, value):
    """解析 --connect-to / --resolve 的"真实连接目标"。

    curl 语法：
        --connect-to <HOST1>:<PORT1>:<HOST2>:<PORT2>
            连接 HOST1:PORT1 时改连 HOST2:PORT2
        --resolve <HOST>:<PORT>:<ADDR>
            把 HOST:PORT 解析到 ADDR

    为什么要单独抽出来：这两个参数会**改写实际连接目标**，
    而 ScanTarget.host 显示的是 URL 里的主机名。于是
        curl --connect-to good.com:443:evil.com:443 https://good.com/x
    在检测视角是 good.com、真实流量去了 evil.com ——
    host 级白名单（比如"本机靶场放行"）会被骗过去。

    返回 {"kind": ..., "alias": ..., "real_host": ..., "real_port": ...}
    或 None（解析不出来就不记，交给 raw_cmd 兜底）。
    """
    if not isinstance(value, str):
        return None
    parts = value.split(":")
    try:
        if flag == "--connect-to" and len(parts) >= 4:
            return {"kind": "connect-to",
                    "alias": parts[0], "alias_port": parts[1],
                    "real_host": parts[2], "real_port": parts[3]}
        if flag == "--resolve" and len(parts) >= 3:
            return {"kind": "resolve",
                    "alias": parts[0], "alias_port": parts[1],
                    "real_host": parts[2], "real_port": parts[1]}
    except (IndexError, AttributeError):
        return None
    return None


def _absorb_flag(info, flag, value):
    if flag in _VALUE_FLAGS_METHOD:
        info["method"] = (value or "GET").upper()
    elif flag in _VALUE_FLAGS_URL:
        info["url"] = value
    elif flag in _VALUE_FLAGS_HEADER:
        info["headers"].append(value)
        lowered = (value or "").lower()
        if lowered.startswith("cookie:"):
            info["cookie"] += ";" + value.split(":", 1)[1]
    elif flag in _VALUE_FLAGS_BODY:
        # -d @body.json 必须真的去读文件。早先只把 "@body.json" 这个
        # 字符串当 body 扫 —— 长 body 写文件是打接口的常规写法（不是
        # 刻意绕过），于是最正常的用法反而绕过了检查。
        content, is_file = _read_maybe_file(value)
        info["body_parts"].append(content)
        info["has_body"] = True
        if is_file:
            info["file_backed"] = True
    elif flag in ("-T", "--upload-file"):
        # 必须在 _VALUE_FLAGS_FILE 之前判断：-T 同时出现在那张表里，
        # 落到那里会被当成表单字段（只存路径、不读内容）。
        info["upload"] = value
        content, is_file = _read_maybe_file(value)
        if not is_file:
            # `-T -`：上传内容来自 stdin（裸 -，-T 不接受 @ 前缀）。
            # 与 -d @- 同理：不接管的话 curl 读走、我们没扫过。
            raw_value = (value or "").strip()
            if raw_value in ("-", "<-"):
                # _take_stdin_value 认的是 @- / <- / name@- 这些写法；
                # 裸 "-" 要转成 "@-" 才能进它的判定。
                # 踩过：直接拼 "-" + "-" 得到 "--"，不匹配任何分支，
                # 于是静默不接管 —— 测试里表现为 upload_parts=['-']。
                taken = _take_stdin_value("@-")
                if taken:
                    # taken 形如 @<tmp>；-T 要的是路径本身
                    path = taken[1:] if taken.startswith("@") else taken
                    info["upload"] = path
                    try:
                        with open(path, "r", encoding="utf-8",
                                  errors="replace") as fh:
                            info["upload_parts"].append(fh.read(262144))
                    except (OSError, ValueError):
                        pass
                    info["has_body"] = True
                    return
            # 不带 @ 的 -T 也是从文件读（curl 的 -T 本来就是上传文件）
            try:
                p = value.strip().strip('"')
                if os.path.isfile(p):
                    with open(p, "r", encoding="utf-8",
                              errors="replace") as fh:
                        content = fh.read(262144)
                    is_file = True
            except (OSError, ValueError):
                pass
        info["upload_parts"].append(content if is_file else value)
        info["has_body"] = True
    elif flag in _VALUE_FLAGS_FILE:
        content, is_file = _read_maybe_file(value)
        info["form_parts"].append(content if is_file else value)
        info["has_body"] = True
    elif flag in _VALUE_FLAGS_UA:
        if flag in ("-e", "--referer"):
            info["referer"] = value
        else:
            info["user_agent"] = value
    elif flag in _VALUE_FLAGS_COOKIE:
        info["cookie"] += ";" + (value or "")
    elif flag in _VALUE_FLAGS_AUTH:
        info["user"] = value
    elif flag in _VALUE_FLAGS_PROXY:
        info["proxy"] = value
    elif flag in _VALUE_FLAGS_MISC:
        # MISC 组的值以前被解析器消费掉就丢了（实测发现）：
        # 进不了任何结构化字段，只有 raw_cmd 文本兜底能挡关键词。
        # 但 --connect-to / --resolve 会**改写连接目标** ——
        #     --connect-to good.com:443:evil.com:443
        # 时 ScanTarget.host 显示 good.com、实际连 evil.com，
        # host 级白名单就被骗了。这类必须进结构化字段。
        info["misc_values"].append(value or "")
        if flag == "--url-query":
            # --url-query 的语义就是"追加到 URL 的查询串上"，
            # 所以真实地拼进 extra_query —— _build_target 会把它
            # 合并进 target.query，让 query 源的规则/白名单都看得到。
            # （早先只写不读，是死代码；虽然 misc_values 兜住了扫描面，
            #  但注释承诺了拼接却没做，属于误导。）
            if value:
                info["extra_query"].append(value)
        elif flag in ("--connect-to", "--resolve"):
            # 目标改写：解析出"真实连接目标"并记下来
            real = _parse_target_override(flag, value)
            if real:
                info["target_overrides"].append(real)
    elif flag in _VALUE_FLAGS_CONFIG:
        # -K cfg：配置里可能有 url= / data= / header=，逐行当内容扫。
        # 不读的话整份配置对检测不可见（可被用来绕过）。
        #
        # **不要在这里再调 _take_config_stdin**：stdin 已经由 parse 循环
        # 接管过（它负责把 argv 改写成临时文件路径），这里再调一次拿到的是
        # 空的 stdin、返回 None，于是 config_files 退回字面量 "-" ——
        # 真正的配置内容反而丢了（踩过：表现为 config_files=['-']）。
        # 这里只管读 value 指向的文件 / 临时文件。
        info["config_files"].append(value)
        _absorb_config_file(info, value)


def _take_stdin_value(value, limit=262144):
    """碰到 `@-` / `<-`（body 来自 stdin）时接管 stdin。

    返回改写后的参数值（`@<临时文件>`），不需要接管时返回 None。

    为什么必须接管：`curl -d @- <<< 'action=delete'` 是完全正常的用法，
    而 body 走 stdin —— 我们不读的话 curl 读走，我们就永远看不到内容，
    等于给了一条"把 payload 塞进管道就绕过"的路子（实测发现）。
    读进来落成临时文件后把参数改写回去，curl 的行为不变。
    """
    if not isinstance(value, str) or not value:
        return None
    raw = value.strip()
    # 支持 @- / <- / name=@- / name<- （--data-urlencode 的等号可省）
    path = None
    prefix = ""
    if raw in ("@-", "<-"):
        path = "-"
    elif "=" in raw:
        head, tail = raw.split("=", 1)
        if tail.strip() in ("@-", "<-"):
            path = "-"
            prefix = head + "="
    elif raw.endswith(("@-", "<-")):
        # --data-urlencode q@- （无等号，curl 的 name@file 语法）
        prefix = raw[:-2]
        path = "-"
    if path != "-":
        return None

    try:
        data = sys.stdin.buffer.read(limit)
    except (OSError, ValueError, AttributeError):
        return None
    if not data:
        return None
    try:
        config.ensure_dirs()
        fd, tmp_path = tempfile.mkstemp(prefix="stdin-", suffix=".dat",
                                        dir=config.RUN_DIR)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except OSError:
        return None
    if not hasattr(_take_stdin_value, "_tmp"):
        _take_stdin_value._tmp = []
    _take_stdin_value._tmp.append(tmp_path)
    return prefix + "@" + tmp_path


def _cleanup_stdin_temps():
    """清理 _take_stdin_value 落下的临时文件（正常/异常退出都要跑）。"""
    for path in getattr(_take_stdin_value, "_tmp", []) or []:
        try:
            os.remove(path)
        except OSError:
            pass
    _take_stdin_value._tmp = []


def _cleanup_stale_stdin_temps(max_age=3600):
    """清理**上次运行**遗留的 stdin/cfg 临时文件。

    为什么需要（实测发现）：`_cleanup_stdin_temps()` 只挂在
    ``main()`` 的 finally 上 —— 而 `parse_curl_args` 也被别处调用：
    控制台的 `/api/scan` curl 模式、测试、Burp 扩展。那些路径走不到
    finally，临时文件就一直躺在 ``data/run/`` 里（实测残留 9 个）。

    处理方式与 proxy._cleanup_stale_leaves 一致：在入口处扫一遍目录，
    删掉超过 ``max_age`` 秒的同类文件 —— 不删新鲜的，
    可能有另一个进程正在用它。
    """
    try:
        names = os.listdir(config.RUN_DIR)
    except OSError:
        return 0
    now = time.time()
    removed = 0
    for name in names:
        if not (name.startswith("stdin-") or name.startswith("cfg-")):
            continue
        if not (name.endswith(".dat") or name.endswith(".txt")):
            continue
        path = os.path.join(config.RUN_DIR, name)
        try:
            if now - os.path.getmtime(path) < max_age:
                continue
            os.remove(path)
            removed += 1
        except OSError:
            continue
    return removed


def _read_maybe_file(value, limit=262144):
    """把 curl 的 @file / <file 语法解析出来并读内容。

    curl 的约定（**每种都要支持，漏一种就是一条绕过路径**）：
        -d @body.json        从文件读 body
        -d <body.json        `<` 是 @ 的等价写法
        -d @-                从 stdin 读（由 _take_stdin_value 接管）
        -F file=@a.txt       表单文件字段
        -F "file=@a.txt;type=text/plain;filename=x"   带分号参数
        --data-urlencode q@payload.txt   **name@file 无等号**
        --data-urlencode q=@payload.txt  name=@file

    最后那个 name@file 是缺过的（实测发现）：curl 手册里
    --data-urlencode 支持 `name@file`（把文件内容 URL 编码后作为
    name 的值），而我们只认 `@file` 和 `name=@file`。实测绕过：
        curl --data-urlencode q@payload.txt http://t/api
    body 里只剩字面量 'q@payload.txt'，文件里的 action=delete 看不见。

    读不到就退回原字面量 —— 绝不能因为读文件失败而漏掉检查。
    """
    if not isinstance(value, str) or not value:
        return value, False
    raw = value.strip()
    path = None

    if raw.startswith("@"):
        path = raw[1:]
    elif raw.startswith("<"):
        path = raw[1:]
    elif "=" in raw:
        # -F / --form 的 name=@file（或 name=<file）
        _head, tail = raw.split("=", 1)
        if tail.startswith("@"):
            path = tail[1:]
        elif tail.startswith("<"):
            path = tail[1:]
    elif "@" in raw:
        # --data-urlencode q@file（无等号）与 -F name@file
        # 取最后一个 @ 之后那段当路径（名字里可能含 @）
        _head, tail = raw.rsplit("@", 1)
        if tail:
            path = tail
    elif "<" in raw:
        _head, tail = raw.rsplit("<", 1)
        if tail:
            path = tail

    if not path:
        return value, False

    # 分号后的参数（;type=text/plain;filename=x）不是路径的一部分。
    # 不剥掉的话 os.path.isfile 永远为假，等于这个文件根本没被读 ——
    # 实测 `-F "f=@a.txt;type=text/plain"` 就是这么漏的。
    path = path.split(";", 1)[0]
    path = path.strip().strip('"').strip("'")
    if not path or path == "-":
        return value, False                 # stdin 由 _take_stdin_value 处理
    try:
        if not os.path.isfile(path):
            return value, False
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read(limit)
        return content, True
    except (OSError, ValueError):
        return value, False


def _absorb_config_file(info, path):
    """把 curl 配置文件的内容也纳入扫描面。

    格式是每行 `option = value`（或 `option value`），注释以 # 开头。
    我们不需要正确解析它，只要把整份文本当额外内容扫一遍 ——
    攻击者可能把 delete 藏在 url= 或 data= 里。

    **`-K -`（配置来自 stdin）必须接管 stdin**（实测发现）：
    `echo "url=http://x/delete" | curl -K -` 是完全正常的用法，
    而配置走 stdin —— 我们不读的话 curl 读走，config_parts 永远是空，
    等于给了一条绕过。读进来落临时文件后把参数改写成 `-K <file>`，
    curl 的行为不变（见 _take_config_stdin）。
    """
    if not isinstance(path, str):
        return
    p = path.strip().strip('"').strip("'")
    if p == "-":
        return                       # stdin 由 _take_config_stdin 处理
    try:
        if not os.path.isfile(p):
            return
        with open(p, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read(262144)
    except (OSError, ValueError):
        return
    _absorb_config_text(info, text)


def _absorb_config_text(info, text):
    """把一份配置文本纳入扫描面（文件与 stdin 两条路共用）。"""
    if not text:
        return
    info["config_parts"].append(text)
    # 尽量把 url=/data= 也提取出来，让 URL 规则能命中
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" in line:
            key, val = line.split("=", 1)
        else:
            parts = line.split(None, 1)
            if len(parts) != 2:
                continue
            key, val = parts
        key = key.strip().lstrip("-")
        val = val.strip().strip('"')
        if key in ("url", "data", "data-raw", "data-binary", "data-ascii",
                   "json", "upload-file", "request-target", "url-query",
                   "data-urlencode"):
            if key in ("url", "request-target"):
                info["config_urls"].append(val)
            else:
                info["body_parts"].append(val)
                info["has_body"] = True


def _take_config_stdin(value, limit=262144):
    """`-K -`：配置来自 stdin。读进来落临时文件，返回改写后的参数值。

    返回 None 表示不需要接管（不是 -K -）。
    """
    if not isinstance(value, str) or value.strip() not in ("-", "<-"):
        return None
    try:
        data = sys.stdin.buffer.read(limit)
    except (OSError, ValueError, AttributeError):
        return None
    if not data:
        return None
    try:
        config.ensure_dirs()
        fd, tmp_path = tempfile.mkstemp(prefix="cfg-", suffix=".txt",
                                       dir=config.RUN_DIR)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
    except OSError:
        return None
    if not hasattr(_take_stdin_value, "_tmp"):
        _take_stdin_value._tmp = []
    _take_stdin_value._tmp.append(tmp_path)
    return tmp_path


def _split_url(url):
    """拆出 host / path / query。host 不含 scheme。"""
    host = path = query = ""
    rest = url
    if "://" in rest:
        _scheme, rest = rest.split("://", 1)
    if "/" in rest:
        authority, tail = rest.split("/", 1)
        host = authority
        if "?" in tail:
            path, query = tail.split("?", 1)
        else:
            path = tail
    else:
        if "?" in rest:
            host, query = rest.split("?", 1)
        else:
            host = rest
    return host, "/" + path if path else "", query


def _build_target(argv, info):
    url = info["url"] or ""
    host, path, query = _split_url(url)

    # --connect-to / --resolve 会把**真实连接目标**改到别处，
    # 而 URL 里写的还是原来那个主机名。不处理的话：
    #     curl --connect-to good.com:443:evil.com:443 https://good.com/x
    # ScanTarget.host 显示 good.com、真实流量去 evil.com ——
    # host 级白名单（"本机靶场放行"那种）就被骗过去了。
    #
    # 处理方式：
    #   * 把改写后的真实主机写成 X-WAF-Real-Host 头（进扫描面）
    #   * 若别名与当前 host 匹配，target.host 直接换成真实主机 ——
    #     这样 host 级规则/白名单看到的是"实际会连的那个"
    for override in (info.get("target_overrides") or []):
        alias = (override.get("alias") or "").strip().lower()
        real = (override.get("real_host") or "").strip()
        if not real:
            continue
        info.setdefault("real_hosts", []).append(real)
        # 别名匹配要同时容忍"带端口"与"不带端口"两种写法：
        #   --connect-to 127.0.0.1:8898:evil.com:443  别名含端口
        #   --connect-to 127.0.0.1:::evil.com:443     curl 允许端口留空
        # 只比主机名部分，避免因端口写法差异而漏改写。
        host_name = (host or "").split(":")[0].lower()
        alias_name = alias.split(":")[0]
        if alias_name and alias_name == host_name:
            host = real

    headers = {}
    for raw in info["headers"]:
        if ":" in raw:
            key, val = raw.split(":", 1)
            headers[key.strip()] = val.strip()

    body_parts = list(info["body_parts"])
    body_parts.extend(info["form_parts"])
    # 上传文件内容与配置文件内容也并入 body 一起扫：
    # 它们都是"用户实际发出去的内容"，藏敏感词的地方。
    body_parts.extend(info.get("upload_parts") or [])
    body_parts.extend(info.get("config_parts") or [])
    # MISC 组的值也并入（--connect-to / --resolve 等）。
    # 它们改写连接目标或参与请求构造，必须进扫描面 ——
    # 以前被解析器消费掉就丢了，只有 raw_cmd 文本兜底。
    body_parts.extend(info.get("misc_values") or [])
    body = "\n".join(p for p in body_parts if p)
    if info["cookie"]:
        headers.setdefault("Cookie", info["cookie"].strip(";"))
    if info["user_agent"]:
        headers.setdefault("User-Agent", info["user_agent"])
    if info["referer"]:
        headers.setdefault("Referer", info["referer"])
    if info["user"]:
        headers.setdefault("Authorization", "Basic " + info["user"])
    if info["upload"]:
        # 只留文件名，不把内容混进 header（内容已在 body 里扫）
        headers.setdefault("X-WAF-Upload-File", os.path.basename(info["upload"]))
    # 被 --connect-to / --resolve 改写出的真实主机：写进扫描面，
    # 让 host/url 类规则和白名单也能看到它（见上面 _build_target 的说明）
    # 多个 --connect-to 时每个真实主机都要进扫描面。
    # 早先用 setdefault 只留第一个（实测发现）——
    # 第二个改写目标就看不见了。这里合并成一个逗号分隔的头，
    # 并**逐个**再写一遍独立头（HTTP 允许重复头字段）。
    real_hosts = [h for h in (info.get("real_hosts") or []) if h]
    if real_hosts:
        headers["X-WAF-Real-Host"] = ", ".join(real_hosts)

    # 配置文件里写的 url= 也要参与 URL 规则匹配
    config_urls = info.get("config_urls") or []
    if not url and config_urls:
        url = config_urls[0]
        host, path, query = _split_url(url)

    # --url-query 的值按 curl 语义追加到查询串上。
    # 拼进 query 字段（而不只是 misc_values）才能让 query 源的
    # 规则、白名单、以及任何按字段判定逻辑看到它。
    extra_query = info.get("extra_query") or []
    if extra_query:
        joined = "&".join(x for x in extra_query if x)
        if joined:
            query = (query + "&" + joined) if query else joined

    # URL 里的用户信息也算敏感面
    if "@" in host:
        userinfo, real_host = host.rsplit("@", 1)
        headers.setdefault("X-WAF-Userinfo", userinfo)
        host = real_host

    raw_cmd = "curl " + " ".join(_quote_if_needed(a) for a in argv)

    return ScanTarget(
        kind="curl",
        method=info["method"],
        url=url,
        host=host,
        path=path,
        query=query,
        headers=headers,
        body=body,
        raw_cmd=raw_cmd,
        tool="curl",
        # urls：命令里出现的全部 URL（含 --next 之后的）。
        # 引擎靠它判断"是不是所有 URL 都在白名单里"——
        # 只看 target.url 的话，`curl <白名单> --next <攻击URL>` 会绕过
        # （命中第一条白名单就整个请求免检）。
        meta={"original_argv": list(argv),
              "urls": list(info.get("urls") or []),
              # 被 --connect-to / --resolve 改写出的真实主机。
              # 引擎要拿它判断"白名单是否真的覆盖了实际目标"。
              "real_hosts": list(info.get("real_hosts") or [])},
    )


def _quote_if_needed(token):
    if token == "" or any(ch in token for ch in ' \t"\'&|<>()$`;'):
        return '"' + token.replace('"', '\\"') + '"'
    return token


# ---------------------------------------------------------------- 真实 curl

def find_real_curl():
    """找到真实 curl 的路径（跳过我们自己的 shim 目录）。

    三级查找，越靠前越快：
      1. 环境变量 WAF_REAL_CURL（用户显式指定，最高优先）
      2. data/detected.json 缓存（安装时自动探测写入，热路径）
      3. 动态搜 PATH + 常见位置（缓存缺失或失效时兜底）
    """
    override = os.environ.get("WAF_REAL_CURL")
    if override and os.path.exists(override):
        return override

    # 缓存路径：把"下载即用"变成 O(1) 读文件
    try:
        from waf import autodetect
        cached = autodetect.cached_curl()
        if cached:
            return cached
    except Exception:
        pass

    shim_dir = os.path.join(ROOT, "bin").lower()
    candidates = []
    path_env = os.environ.get("PATH", "")
    for folder in path_env.split(os.pathsep):
        if not folder:
            continue
        try:
            if os.path.normcase(os.path.abspath(folder)).lower() == shim_dir:
                continue                              # 跳过自己的 shim 目录
        except OSError:
            continue
        for name in ("curl.exe", "curl"):
            candidate = os.path.join(folder, name)
            if os.path.isfile(candidate):
                candidates.append(candidate)

    preferred = [
        r"C:\Windows\System32\curl.exe",
        r"C:\Program Files\Git\mingw64\bin\curl.exe",
        r"C:\Program Files\Git\usr\bin\curl.exe",
        r"C:\Program Files (x86)\Git\mingw64\bin\curl.exe",
        "/usr/bin/curl",
        "/bin/curl",
        "/usr/local/bin/curl",
    ]
    for want in preferred:
        for candidate in candidates:
            if os.path.normcase(candidate).lower() == os.path.normcase(want).lower():
                # 顺手把探测结果记下来，下次直接命中缓存
                _remember_curl(candidate)
                return candidate
    if candidates:
        _remember_curl(candidates[0])
        return candidates[0]
    return None


def _remember_curl(path):
    """把找到的 curl 路径写进缓存（失败不影响主流程）。"""
    try:
        from waf import autodetect
        data = autodetect.read_cache()
        if data.get("curl") != path:
            data["curl"] = path
            autodetect.write_cache(data)
    except Exception:
        pass


def forward(real_curl, argv):
    """转发给真实 curl，保持 stdio 与退出码。"""
    try:
        proc = subprocess.Popen([real_curl] + list(argv))
        return proc.wait()
    except KeyboardInterrupt:
        try:
            proc.terminate()
        except Exception:
            pass
        return 130
    except OSError as exc:
        sys.stderr.write("[agent-waf] 无法执行真实 curl (%s): %s\n" % (real_curl, exc))
        return 127


# ---------------------------------------------------------------- 主流程

def emit_block(verdict, verbose=False):
    if os.environ.get("WAF_QUIET") == "1":
        return
    text = verdict.to_json(indent=2, include_meta=verbose)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    try:
        return _main_inner(argv)
    finally:
        # -d @- 接管 stdin 时会落临时文件，退出前必须清掉
        # （无论正常结束、被拦、还是异常）
        _cleanup_stdin_temps()


def _main_inner(argv):
    if os.environ.get("WAF_DISABLE") == "1":
        real = find_real_curl()
        return forward(real, argv) if real else 127

    if not argv:
        real = find_real_curl()
        return forward(real, argv) if real else 127

    config.ensure_dirs()
    logstore.init_db()

    # 首次运行自引导：没有探测缓存就自动探一次。
    # 这是"下载即用"的落地点 —— 别人解压后即使没跑过安装脚本，
    # 第一次调用 curl 也会把本机路径摸清楚并记下。
    try:
        from waf import autodetect
        autodetect.refresh_if_missing()
    except Exception:
        pass

    # 拦截器没开启就直接透传 —— 不检查、不记录、不打扰。
    # 判定：控制台在运行 且 用户没有主动暂停（见 waf/state.should_intercept）
    engine = get_engine()
    active, reason = state.should_intercept(engine)
    if not active:
        if os.environ.get("WAF_VERBOSE") == "1":
            sys.stderr.write("[agent-waf] 未拦截（%s），直接转发\n" % reason)
        real = find_real_curl()
        return forward(real, argv) if real else 127

    try:
        target, _info = parse_curl_args(argv)
    except Exception as exc:
        sys.stderr.write("[agent-waf] 参数解析失败，放行给真实 curl：%s\n" % exc)
        real = find_real_curl()
        return forward(real, argv) if real else 127

    verbose = os.environ.get("WAF_VERBOSE") == "1"
    no_log = os.environ.get("WAF_NO_LOG") == "1"

    try:
        verdict = engine.scan(target, log=not no_log)
    except Exception as exc:
        # 引擎彻底不可用：按 fail_mode 决定
        fail_closed = str(engine.settings.get("fail_mode", "closed")).lower() != "open"
        sys.stderr.write("[agent-waf] 引擎异常：%s\n" % exc)
        if fail_closed:
            sys.stderr.write("[agent-waf] fail_mode=closed，已阻止本次命令。"
                             "如需临时放行：set WAF_DISABLE=1\n")
            return BLOCK_EXIT_CODE
        real = find_real_curl()
        return forward(real, argv) if real else 127

    if verdict.blocked:
        emit_block(verdict, verbose=verbose)
        sys.stderr.write(
            "[agent-waf] 已拦截（rule=%s）。"
            "确需执行：wafctl unlock --minutes 10 --reason \"...\"\n"
            % ",".join(sorted({h.rule_id for h in verdict.hits if h.rule_id})) or ""
        )
        return BLOCK_EXIT_CODE

    real = find_real_curl()
    if not real:
        sys.stderr.write("[agent-waf] 未找到真实 curl（可用 WAF_REAL_CURL 指定）\n")
        return 127
    return forward(real, argv)


if __name__ == "__main__":
    sys.exit(main())
