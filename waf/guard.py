# -*- coding: utf-8 -*-
"""Python 运行时护栏：给 requests / urllib / httpx 出站请求加 WAF 检查。

用法一（推荐，自动给子进程装）：
    waf-run python exp.py

用法二（脚本内显式启用）：
    import waf.guard
    waf.guard.install_guard()      # 之后所有 requests 请求都会先过 WAF

用法三（局部保护）：
    from waf.guard import guarded_request
    guarded_request("GET", "http://x/delete.php")

被拦截时抛出 waf.models.WafBlocked。
"""

import os
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import config, logstore                      # noqa: E402
from waf.engine import get_engine                     # noqa: E402
from waf.models import ScanTarget, WafBlocked         # noqa: E402

_installed = False
_lock = threading.RLock()
_follow_console = False
_stats = {"checked": 0, "blocked": 0, "skipped": 0}

# 重入闸。
#
# 为什么需要（实测复现，不是理论问题）：
# regexguard 的探测子进程 argv 形如
#
#     python -c "<1024 字符探测源码>" '["(a+)+$","drop table"]' '[...]' '3.0'
#
# 里面**带着正在被探测的正则文本**。而 _needs_cmd_scan 认破坏性动词，
# `drop` / `truncate` 这些样本词正好命中 → 判定"需要扫描" →
# _check_cmd → get_engine() → 引擎加载 → check_patterns() →
# 又起一个探测子进程 …… 每层都认为自己该拦，stderr 里刷满
# "engine_error"（冷缓存时 100% 复现；缓存热了就看不出来，
# 因为不再起子进程）。
#
# 两层防护：
#   1. 本闸 —— 线程本地标志，扫描自身的调用栈一律不再进扫描逻辑。
#   2. regexguard 给探测子进程带上 WAF_INTERNAL_PROC=1（见那边），
#      子进程里的 guard 一看就退出，连引擎都不加载。
_scannable = threading.local()


def _enter_scan():
    """进入扫描逻辑；返回 False 表示已在扫描中（重入），跳过。

    这里的"跳过"是 **fail-open**，与护栏"偏保守"的整体取向相反 ——
    实测发现过这点，结论是必须保持 fail-open，理由：

    ``_scannable`` 是**线程本地**的（threading.local）。唯一能让
    depth > 0 的情况，是本线程**正在** ``engine.scan()`` 里面。
    而扫自身这条路上，被扫的"命令"就是引擎内部的调用（规则加载、
    ReDoS 探测起子进程等）—— 对这些再判一次毫无意义（它们不是用户
    执行的危险命令），却会：

      * 无限递归（就是修这个闸的原因，冷缓存时实测复现）
      * 若改成 fail-closed（重入即拦截），引擎第一次扫描就会拦掉
        自己的内部子进程 → 引擎永远拿不到探测结果 → 整个护栏瘫痪

    换句话说 fail-closed 在这里不是"更安全"，而是"直接把自己锁死"。
    真正防自激的三层闸是：
      1. 本闸（线程本地，挡同线程重入）
      2. ``WAF_INTERNAL_PROC``（挡子进程，见 is_internal_process）
      3. ``_is_own_tooling``（挡显式调用自家 CLI/脚本）
    漏拦风险由第 2、3 层覆盖，不靠本闸。
    """
    if getattr(_scannable, "depth", 0) > 0:
        return False
    _scannable.depth = 1
    return True


def _exit_scan():
    _scannable.depth = 0


def is_disabled():
    return os.environ.get("WAF_DISABLE") == "1"


def is_internal_process():
    """是不是我们自己起的内部子进程（regexguard 探测等）。

    这类进程的 argv 里带着规则文本／样本，被当成"待检命令"扫会
    自激（见 _scannable 的说明）。所以它们一律不装护栏。
    """
    return os.environ.get("WAF_INTERNAL_PROC") == "1"


def _console_gate():
    """follow_console=True 时，跟随控制台开关；否则始终检查。

    返回 (是否继续检查, 原因)。
    """
    if not _follow_console:
        return True, "显式启用"
    from waf import state
    try:
        return state.should_intercept(get_engine())
    except Exception:
        return state.is_active(), "心跳判定"


def _print_block(verdict):
    sys.stderr.write(verdict.to_json(indent=2,
                                     include_meta=os.environ.get("WAF_VERBOSE") == "1") + "\n")


def check_request(method="GET", url="", headers=None, body="", params=None,
                  tool="python", log=True):
    """检查一个出站请求；命中则抛 WafBlocked，否则返回 Verdict。"""
    if is_disabled():
        from waf.models import Verdict
        return Verdict(blocked=False, reason="WAF_DISABLE=1", stage="bypass")

    active, reason = _console_gate()
    if not active:
        from waf.models import Verdict
        _stats["skipped"] += 1
        return Verdict(blocked=False, reason="拦截器未开启：%s" % reason,
                       stage="inactive")

    from urllib.parse import urlencode, urlsplit

    if params:
        try:
            joined = urlencode(params, doseq=True)
            url = url + ("&" if "?" in url else "?") + joined
        except Exception:
            pass

    host = path = query = ""
    try:
        parts = urlsplit(url)
        host = parts.netloc
        path = parts.path
        query = parts.query
    except Exception:
        pass

    target = ScanTarget(
        kind="request",
        method=(method or "GET").upper(),
        url=url,
        host=host,
        path=path,
        query=query,
        headers=dict(headers or {}),
        body=body if isinstance(body, str) else _safe_body(body),
        tool=tool,
    )
    config.ensure_dirs()
    logstore.init_db()
    engine = get_engine()
    verdict = engine.scan(target, log=log)
    _stats["checked"] += 1
    if verdict.blocked:
        _stats["blocked"] += 1
        _print_block(verdict)
        raise WafBlocked(verdict)
    return verdict


def _safe_body(body):
    try:
        if isinstance(body, bytes):
            return body.decode("utf-8", "replace")
        return str(body)
    except Exception:
        return ""


# ---------------------------------------------------------------- requests

def _patch_requests():
    """给 requests 打补丁。

    只在 **Session.send** 上检查 —— 它是所有请求的真正汇聚点
    （get/post/put/Session.request 最终都走到这里）。

    早先 request 和 send 都打了补丁，同一个请求被扫两次、日志里出现
    两条一模一样的记录（实测发现）。重复扫描除了浪费，
    还会让"拦截统计"翻倍，失去参考价值。

    send 的信息量足够：拿到的 PreparedRequest 上有完整的
    method / url / headers / body（body 已序列化，比原始 data= / json=
    更接近实际发出的内容）。
    """
    try:
        import requests
    except ImportError:
        return False

    original_send = requests.Session.send

    def guarded_send(self, request, **kwargs):
        body = request.body
        check_request(method=request.method, url=request.url,
                      headers=dict(request.headers or {}),
                      body=_safe_body(body) if body else "",
                      tool="requests")
        return original_send(self, request, **kwargs)

    requests.Session.send = guarded_send

    def _api_call(method, url, **kw):
        session = requests.Session()
        return session.request(method, url, **kw)

    requests.request = _api_call

    # requests.api 顶层函数的绑定
    try:
        import requests.api as api
        for name in ("get", "post", "put", "delete", "patch", "head", "options"):
            setattr(api, name,
                    (lambda m: lambda url, **kw: _api_call(m, url, **kw))(
                        name.upper()))
    except Exception:
        pass
    return True


def _patch_urllib():
    try:
        import urllib.request as urlreq
    except ImportError:
        return False

    original_open = urlreq.OpenerDirector.open
    original_urlopen = urlreq.urlopen

    def guarded_open(self, fullurl, data=None, timeout=None):
        if hasattr(fullurl, "full_url"):
            url = fullurl.full_url
            method = getattr(fullurl, "get_method", lambda: "GET")() or "GET"
            headers = dict(getattr(fullurl, "headers", {}) or {})
        else:
            url = str(fullurl)
            method = "GET"
            headers = {}
        check_request(method=method, url=url, headers=headers,
                      body=_safe_body(data) if data else "", tool="urllib")
        return original_open(self, fullurl, data, timeout)

    def guarded_urlopen(url, data=None, timeout=None, **kwargs):
        check_request(method="POST" if data else "GET", url=str(url),
                      body=_safe_body(data) if data else "", tool="urllib")
        return original_urlopen(url, data=data, timeout=timeout, **kwargs)

    urlreq.OpenerDirector.open = guarded_open
    urlreq.urlopen = guarded_urlopen
    # install_opener 之后仍走 OpenerDirector.open，因此已覆盖
    return True


def _patch_httpx():
    """httpx 补丁：同步 Client 与**异步 AsyncClient**。

    异步漏掉过（实测发现的缺口）：早先只补 httpx.Client.request，
    而 AsyncClient 是独立的类，不走 Client 的方法解析 ——
    于是 `async with httpx.AsyncClient() as c: await c.get(url)`
    完全不被检查。AI 写的异步爬虫/并发脚本恰恰常用它。
    """
    try:
        import httpx
    except ImportError:
        return False

    def _make_guard(original):
        def guarded(self, method, url, **kwargs):
            data = kwargs.get("data")
            if data is None:
                data = kwargs.get("json")
            check_request(method=method, url=str(url),
                          headers=kwargs.get("headers") or {},
                          body=_safe_body(data) if data is not None else "",
                          tool="httpx")
            return original(self, method, url, **kwargs)
        return guarded

    if hasattr(httpx, "Client") and hasattr(httpx.Client, "request"):
        httpx.Client.request = _make_guard(httpx.Client.request)
    # AsyncClient 是协程方法，同样签名的 wrapper 直接可用
    # （我们只做同步检查，然后返回原始协程）
    if hasattr(httpx, "AsyncClient") and hasattr(httpx.AsyncClient, "request"):
        httpx.AsyncClient.request = _make_guard(httpx.AsyncClient.request)
    return True


def _patch_urllib3():
    """urllib3 补丁 —— requests 底座，也是很多爬虫的直接依赖。

    实测发现这层完全没覆盖：requests 我们补了 Session.send，
    但直接 `urllib3.PoolManager().request(...)`、
    或 httpx 底层走 urllib3 的路径都绕过了检查。
    urllib3 是所有请求的真正落点之一（ConnectionPool.urlopen），
    补这里覆盖面最广。
    """
    try:
        import urllib3
    except ImportError:
        return False

    try:
        from urllib3 import connectionpool as _cp
    except Exception:
        return False

    if not hasattr(_cp, "HTTPConnectionPool"):
        return False

    original = _cp.HTTPConnectionPool.urlopen

    def guarded_urlopen(self, method, url, body=None, headers=None, **kwargs):
        try:
            host = getattr(self, "host", "") or ""
            port = getattr(self, "port", None)
            scheme = getattr(self, "scheme", "http") or "http"
            full = url if str(url).lower().startswith(("http://", "https://")) \
                else "%s://%s%s%s" % (scheme, host,
                                      ":%s" % port if port else "", url)
        except Exception:
            full = str(url)
        check_request(method=method, url=full,
                      headers=dict(headers or {}),
                      body=_safe_body(body) if body else "",
                      tool="urllib3")
        return original(self, method, url, body=body, headers=headers, **kwargs)

    _cp.HTTPConnectionPool.urlopen = guarded_urlopen
    return True


def _patch_aiohttp():
    try:
        import aiohttp
    except ImportError:
        return False

    original_request = aiohttp.ClientSession._request

    def guarded_request(self, method, str_or_url, **kwargs):
        data = kwargs.get("data")
        if data is None:
            data = kwargs.get("json")
        check_request(method=method, url=str(str_or_url),
                      headers=kwargs.get("headers") or {},
                      body=_safe_body(data) if data is not None else "",
                      tool="aiohttp")
        return original_request(self, method, str_or_url, **kwargs)

    aiohttp.ClientSession._request = guarded_request
    return True


def _patch_subprocess():
    """拦截 AI 脚本里 os.system / subprocess 调 curl 的情况。"""
    import subprocess

    original_popen = subprocess.Popen
    original_system = os.system

    def guarded_popen(args, *rest, **kwargs):
        cmd = _cmd_text(args)
        if cmd:
            _check_cmd(cmd, "subprocess")
        return original_popen(args, *rest, **kwargs)

    def guarded_system(command):
        _check_cmd(str(command), "os.system")
        return original_system(command)

    subprocess.Popen = guarded_popen
    os.system = guarded_system
    return True


def _cmd_text(args):
    try:
        if isinstance(args, (list, tuple)):
            return " ".join(str(a) for a in args)
        return str(args)
    except Exception:
        return ""


# 我们自己"独有名字"的启动器 —— 出现在可执行文件名上就可以放心豁免。
# 注意不包含裸的 "curl"：那个名字和真实 curl 二进制重名，无法区分；
# 而 guard 对 curl 命令的检查本身就是 shim 之外的**第二道防线**
# （PATH 没被接管的场景），漏掉它反而危险。
_SELF_LAUNCHERS = {
    "wafctl", "wafctl.cmd", "waf-run", "waf-run.cmd",
    "curl.cmd",                      # Windows 批处理 shim（真实的是 curl.exe）
}
_SCRIPT_INTERPRETERS = {
    "python", "python.exe", "python3", "python3.exe", "py", "py.exe",
    "bash", "bash.exe", "sh", "sh.exe",
    "cmd", "cmd.exe", "powershell", "powershell.exe", "pwsh", "pwsh.exe",
}
# 我们的脚本路径（用正斜杠比较，大小写不敏感）
_SELF_SCRIPTS = (
    "waf/cli.py", "waf/curlshim.py", "waf/runner.py",
    "bin/curl", "bin/curl.cmd", "bin/waf.ps1", "bin/waf-run",
    "wafctl", "wafctl.cmd",
)


def _basename(token):
    """取一个 token 的文件名部分（去掉引号、按 / 和 \\ 切）。"""
    text = (token or "").strip().strip('"').strip("'")
    text = text.replace("\\", "/").rstrip("/")
    return text.rsplit("/", 1)[-1].lower()


def _is_own_tooling(cmd):
    """命令行是不是在调用本工具自己的组件。

    必须豁免，否则会自己拦自己：

    * ``python waf/cli.py`` —— 本工具的服务进程 / 测试
    * ``bash bin/curl ...`` —— 拦截器自身（它内部会做检查）
    * ``wafctl check "http://x/delete.php"`` —— 只做规则检测，不发请求

    实际踩过：测试进程装了钩子后，再用 subprocess 调 ``waf/cli.py``
    当场被拦，整个测试套件跑不完。

    判定方式（实测发现过绕过）：
    旧版是 ``any(marker in 整条命令)`` —— 于是

        curl http://target/delete?id=1 -H "Referer: x/agent-waf/"

    也会被豁免：只要在任意参数里塞个特征词，护栏就整个失效。

    现在只看**前几个 token 的"可执行文件 / 脚本路径"**，参数一律不参与：
      * 第一个 token 的文件名是"我们独有的启动器名" → 豁免
      * 前三个 token 里既有解释器、又有我们的脚本路径 → 豁免
    """
    if not cmd or not isinstance(cmd, str):
        return False
    try:
        tokens = cmd.split()[:3]
    except Exception:
        return False
    if not tokens:
        return False

    names = [_basename(t) for t in tokens]
    # 1) 直接调用我们独有的启动器
    if names and names[0] in _SELF_LAUNCHERS:
        return True
    # 2) 解释器 + 我们的脚本（python waf/cli.py / bash bin/curl）
    if any(n in _SCRIPT_INTERPRETERS for n in names):
        flat = " ".join(tokens).replace("\\", "/").lower()
        if any(script in flat for script in _SELF_SCRIPTS):
            return True
    return False


# 手写的基础词表 —— **永远与派生结果取并集**。
#
# 为什么保留它：改成"纯派生"之后，`shutdown` 从词表里消失了
# （根因是 _regex_literals 把 `\bshutdown\b` 切成 "bshutdown" ——
# `\b` 的 b 是字母，被当成字面量的一部分），于是护栏跳过检查，
# 破坏性命令不会被拦。
#
# 结论：派生只能**做加法**。基础词表兜底那些"无论如何都该扫"的
# 系统级破坏动作；派生负责把规则里新增的词自动带进来。
# 这样两套清单的漂移问题解决了（派生会补齐），又不会因为派生逻辑
# 的 bug 而**减少**覆盖（并集保证了这一点）。
_BASE_GATE_WORDS = frozenset([
    "rm", "rmdir", "del", "erase", "unlink", "shred", "sdelete",
    "mkfs", "dd", "shutdown", "reboot", "halt", "poweroff",
    "drop", "truncate", "userdel", "groupdel", "taskkill",
    "diskpart", "format", "fdisk", "wipe", "purge",
    # 本轮实测列出的 22 条里、原词表漏掉的那些
    "remove", "delete", "rd", "deltree", "clean", "destroy",
    "prune", "uninstall", "pkill", "kill", "lvremove", "wipefs",
    "rb", "sudoers", "chpasswd", "net", "zfs", "helm",
    "terraform", "docker", "kubectl", "aws", "git",
])


def _gate_words():
    """门槛词表 —— 规则集派生 **并集** 手写基础词表。

    背景（实测发现）：
    门槛原是一份手写的 22 动词小词表，而规则集有 200+ 关键词。
    两套清单必然漂移，且漂移方向是**门槛更窄、规则更宽** —— 实测
    19 条命令规则能拦、门槛却放行：

        Remove-Item C:\\important -Recurse -Force
        shutil.rmtree('D:/data')          npx rimraf dist
        kubectl delete ns prod            rd /s /q C:\\data
        deltree C:\\x                     git clean -fdx
        git push --force                  terraform destroy -auto-approve
        docker system prune -a            find . -name '*.log' -delete
        kill -9 1                         pkill -f python
        Remove-ItemProperty -Path ...     zfs destroy pool/data
        lvremove /dev/vg0/lv0             > /etc/sudoers
        aws s3 rb s3://bucket             helm uninstall release

    这些都是 R-101 / R-106 / R-304 / R-305 / R-306 / R-310 里明确
    写了的 —— 规则在源码和测试里都"存在"，实际却空转。比少拦几条更糟。

    修法：派生 ∪ 基础词表（见 _BASE_GATE_WORDS 的说明 —— 纯派生
    曾经把 shutdown 弄丢，后果是测试真的关了机）。

    门槛只用于"值不值得扫"这个**粗筛**，判定仍由引擎做，所以宁可
    多收（多扫几次，实测 1.5-8ms），不可漏收。

    取不到规则时返回基础词表（**不是缩小，而是保底**）—— 门槛放宽
    只影响扫几次，漏收才致命。
    """
    try:
        from waf import rules as _rules
        doc = _rules.default_document()
    except Exception:
        return set(_BASE_GATE_WORDS)     # 取不到规则也不能放宽

    words = set()
    for rule in doc.get("rules") or []:
        if not isinstance(rule, dict):
            continue
        if str(rule.get("action") or "") != "block":
            continue              # monitor 类（R-2xx 观测）不该放宽门槛
        if not rule.get("enabled", True):
            continue

        for kw in (rule.get("keywords") or []):
            k = str(kw).strip().lower()
            if len(k) >= 3:
                words.add(k)

        for pattern in (rule.get("regex") or []):
            words.update(_regex_literals(str(pattern)))

    # **并集**：派生负责补齐规则里新增的词，基础词表兜底系统级动作。
    # 只做加法 —— 派生逻辑出 bug 时不会减少覆盖。
    return words | set(_BASE_GATE_WORDS)


# 从正则里抠字面量：把非字母数字当分隔符切开。不求精确解析正则，
# 只求"别把规则里写了的词漏掉"。
#
# 踩过的严重 bug：`\bshutdown\b` 被切成 "bshutdown" —— 因为分隔符集合
# 只有 [^a-z0-9]，而 `\b` 里的 b 是字母，被当成字面量的一部分。
# 结果 shutdown 反而**没进词表**，护栏跳过检查 —— 破坏性命令
# 会被直接放行。
#
# 修法：先把正则转义（\b \s \d \w 等）剥掉再切。
# 注意这仍然不是正则解析器，只是"别把 \b 当字母"。
_REGEX_SPLIT = None
_REGEX_ESCAPES = None


def _regex_literals(pattern):
    """从正则里抠出长度 >= 2 的字面量小写片段。

    阈值比关键词低一个字符：关键词里 2 字符的多是噪声，但**正则里的**
    2 字符片段往往是命令名本身 —— ``rd\\s+/[sq]`` 的 "rd"、
    ``rm\\s+-`` 的 "rm"。实测按 >= 3 过滤时 ``rd /s /q C:\\data``
    仍然过不了门槛。

    多收几个短词只会让门槛宽一点点（多扫几次，每次 1.5-8ms），
    漏收才是真漏 —— 漏收的代价是真实破坏被放行，不是"少拦一条"。
    """
    global _REGEX_SPLIT, _REGEX_ESCAPES
    if _REGEX_SPLIT is None:
        import re as _re
        _REGEX_SPLIT = _re.compile(r"[^a-z0-9]+")
        # 正则里的转义序列：\b \s \d \w \S \D \W \A \Z \. \\ 等。
        # 必须在切分前剥掉，否则 \b 的 b 会被当成字面量的一部分
        # （就是 shutdown 消失的原因）。
        _REGEX_ESCAPES = _re.compile(r"\\([a-zA-Z])")
    lowered = _REGEX_ESCAPES.sub(" ", pattern.lower())
    out = set()
    for piece in _REGEX_SPLIT.split(lowered):
        if len(piece) >= 2 and not piece.isdigit():
            out.add(piece)
    return out


_GATE_WORDS_CACHE = None


def _gate_words_cached():
    global _GATE_WORDS_CACHE
    if _GATE_WORDS_CACHE is None:
        _GATE_WORDS_CACHE = _gate_words()
    return _GATE_WORDS_CACHE


def _needs_cmd_scan(cmd):
    """这条命令行值不值得扫（**粗筛**；判定仍由引擎做）。

    判据不能只看网络工具（实测发现的缺口）：
    早先是 ``"curl" not in cmd and "http" not in cmd and "wget" not in cmd``
    就跳过 —— 于是

        subprocess.run(["rm", "-rf", "/"])

    完全不被检查（实测 NOT_BLOCKED）。而"拦住删除/销毁"正是这个工具的
    核心目的，本地文件被 AI 一条 subprocess 清掉和在目标上删库一样不可逆。

    第一版修复把词表从 curl/http/wget 扩成 22 个破坏动词 —— 但那是
    **手写的第二份清单**，很快漂移成"门槛比规则窄"（见 _gate_words）。
    根因不是少几个词，而是同一语义有两份清单。现在词表从规则集派生，
    两套不可能再漂移。

    为什么保留门槛（而不是全扫）：全扫会让
    ``npm run remove-unused``、``git commit -m 'remove old comment'``、
    ``rm -rf node_modules`` 这类正常开发命令被误拦（实测 40 条常见
    命令里 12 条中招）。门槛负责"明显无关的命令直接跳过"，
    剩下的交给规则里更精确的动作位判据。
    """
    lowered = cmd.lower()
    if any(tool in lowered for tool in ("curl", "http://", "https://", "wget")):
        return True

    words = _gate_words_cached()
    if words is None:
        return True                    # 词表不可用 → 保守扫描

    # 词匹配：单独成词才算。分隔符集合要够宽 —— 实测漏过两个：
    #   shutil.rmtree(...)   点号在 "rmtree" 前面
    #   rd /s /q C:\data     斜杠在 "rd" 前面
    # 早先集合是 [\\/\s\"'(=:_-]，缺了点号与方括号/花括号/分号/逗号，
    # 于是库函数调用（os.remove、fs.unlink、shutil.rmtree）常被跳过。
    import re as _re
    for word in words:
        if word not in lowered:
            continue                   # 快速子串预筛，省掉正则
        if _re.search(r"(?:^|[\\/\s\"'(=:,_;\-\.\[\{<>|&])" + _re.escape(word)
                      + r"(?![a-z0-9_])", lowered):
            return True
    return False


def _check_cmd(cmd, tool):
    """命令行类：把整条命令当 raw_cmd 扫描。"""
    if is_disabled():
        return
    if is_internal_process():
        return                          # 我们自己的探测子进程
    if _is_own_tooling(cmd):
        return                                       # 自己的工具，豁免
    active, reason = _console_gate()
    if not active:
        _stats["skipped"] += 1
        return
    if not _needs_cmd_scan(cmd):
        return                                       # 既不联网也没破坏动作
    # 重入闸放在最内层：上面几步都很便宜，真正贵的是下面
    # get_engine()（首次要跑 ReDoS 探测）。扫描自身触发的扫描
    # 在第一次就返回，不会无限套娃。
    if not _enter_scan():
        _stats["skipped"] += 1
        return
    try:
        config.ensure_dirs()
        logstore.init_db()
        engine = get_engine()
        target = ScanTarget(kind="curl", method="CLI", raw_cmd=cmd, tool=tool)
        verdict = engine.scan(target)
    except Exception as exc:
        # Guard path must fail closed. Keep exception from escaping as an
        # unrelated UnboundLocalError when verdict was never assigned.
        from waf.models import Verdict
        _stats["blocked"] += 1
        raise WafBlocked(Verdict(
            blocked=True,
            reason="WAF 引擎异常，按 fail_mode=closed 处理",
            stage="engine_error",
            hits=[],
            mode="block",
            tool=tool,
        ))
    finally:
        _exit_scan()
    _stats["checked"] += 1
    if verdict.blocked:
        _stats["blocked"] += 1
        _print_block(verdict)
        raise WafBlocked(verdict)


def install_guard(patch_subprocess=True, force=False, follow_console=False):
    """安装所有可用的补丁，幂等。返回已启用的目标列表。

    说明：``install_guard()`` 是**显式**调用 —— 你主动 import 本身就是
    "我要开启"的意思，所以不检查控制台心跳。如果你希望护栏跟随控制台
    开关，用 ``install_guard(follow_console=True)``。
    """
    global _installed, _follow_console
    with _lock:
        if is_disabled():
            return []
        if _installed and not force:
            return ["already"]
        _follow_console = bool(follow_console)
        enabled = []
        if _patch_requests():
            enabled.append("requests")
        if _patch_urllib():
            enabled.append("urllib")
        if _patch_httpx():
            enabled.append("httpx")
        if _patch_urllib3():
            enabled.append("urllib3")
        if _patch_aiohttp():
            enabled.append("aiohttp")
        if patch_subprocess:
            try:
                if _patch_subprocess():
                    enabled.append("subprocess")
            except Exception:
                pass
        _installed = True
        if os.environ.get("WAF_GUARD_VERBOSE") == "1":
            sys.stderr.write("[agent-waf] guard installed: %s\n" % ", ".join(enabled))
        return enabled


def stats():
    return dict(_stats)
