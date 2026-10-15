# -*- coding: utf-8 -*-
"""由 .pth 钩子自动加载的引导模块。

目的
----
让"普通 python 进程"里的 HTTP 请求也受 WAF 约束。AI 工具
（ZCode / Claude Code / Codex / WorkBuddy 等）经常直接写 Python 脚本
打目标，这些脚本不走 curl shim，需要在这一层接住。

三条硬性约束
------------
1. **WAF 没开就什么都不做** —— 先看心跳文件；未开启时不导入任何 WAF
   模块、不打任何补丁，只留一个极轻的 import 钩子。
2. **不拖慢启动** —— 不在 site 阶段 import requests 这类重库。
3. **绝不弄崩宿主进程** —— 所有异常都吞掉。设 ``AGENTWAF_NO_HOOK=1``
   可整体关闭（比如跑基准测试时）。

关键时序问题（踩过的坑）
------------------------
``.pth`` 是在 site 初始化阶段执行的。那一刻 ``import requests`` 可能
失败（依赖尚未就绪）。此时安装会"部分成功"：urllib / subprocess 打上了，
requests 没有 —— 而 guard 的 ``_installed`` 位已置，后续调用只会返回
``['already']``，requests 的补丁就**永远不会生效**。

所以本模块的做法是：装完立刻自检，若 requests 没打上，就保留 import
钩子；等宿主真正 ``import requests`` 时再强制重装一次。
"""

import json
import os
import sys
import threading
import time

# 这些模块被 import 就说明程序要做 HTTP 了
_ROOTS = frozenset(("requests", "httpx", "aiohttp", "urllib3"))

# 心跳超过这个秒数就视为控制台已停止（与 waf/state.py 保持一致）
STALE_AFTER = 20.0

_state = {"patched": False, "installing": False, "wrapped": False,
          "attempts": 0}
_lock = threading.Lock()


def _debug(message):
    """安装诊断。默认静默，设 AGENTWAF_HOOK_DEBUG=1 才写文件。

    日志写在**安装目录内**的 data/logs/hook.log —— 不在 TEMP 留东西，
    整个工具的外部足迹只有几个环境变量指针。
    """
    if not (os.environ.get("HUNTGUARD_HOOK_DEBUG") == "1"
            or os.environ.get("AGENTWAF_HOOK_DEBUG") == "1"):
        return
    try:
        root = os.environ.get("WAF_ROOT") or _guess_root()
        if not root:
            return
        log_dir = os.path.join(root, "data", "logs")
        os.makedirs(log_dir, exist_ok=True)
        with open(os.path.join(log_dir, "hook.log"), "a",
                  encoding="utf-8") as fh:
            fh.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), message))
    except Exception:
        pass


def _guess_root():
    """从 sys.path 里找带 waf/guard.py 的目录。"""
    for entry in list(sys.path):
        if entry and os.path.isfile(os.path.join(entry, "waf", "guard.py")):
            return entry
    return ""


def _ensure_path(root):
    if root and root not in sys.path:
        sys.path.insert(0, root)


def _heartbeat_path(root):
    """心跳文件路径。纯标准库计算，**不 import waf**。

    支持 ``WAF_STATE_FILE`` 覆盖（与 waf/state.py 一致）：测试和多实例
    场景下把心跳指到别处，就不会误判成"控制台在运行"。

    为什么不 import waf：曾经这里用 ``from waf import state`` 判断是否
    开启，结果在解释器启动时就把 ``waf`` 模块名**绑死在当前安装目录**。
    之后同一台机器上运行另一份拷贝（比如把绿色版解压到别处），
    ``from waf import ...`` 永远拿到旧那份 —— 代码、规则、配置全错位。
    """
    override = os.environ.get("WAF_STATE_FILE")
    if override:
        return override
    return os.path.join(root, "data", "run", "active.json")


def _check_active():
    """心跳检查：WAF 控制台是否在跑。任何异常都当作"没开"。

    刻意不 import waf —— 见 _heartbeat_path 的说明。
    """
    try:
        root = os.environ.get("WAF_ROOT") or _guess_root()
        if not root or not os.path.isdir(root):
            return False
        hb = _heartbeat_path(root)
        age = time.time() - os.path.getmtime(hb)
        if age > STALE_AFTER:
            return False
        # 用户开关也要看：settings.enabled=false 时不该装护栏
        enabled = _read_setting_enabled(root)
        return enabled
    except Exception:
        return False


def _read_setting_enabled(root):
    """直接从 rules.json 读 settings.enabled。

    为什么不用 waf 模块读：同上 —— 避免绑定模块名。
    用最小化 JSON 解析，任何异常都返回 True（保守放行）。

    环境变量要认全三个名字（顺序即优先级）：
        HUNTGUARD_RULES_FILE   现在的正式名
        AGENTWAF_RULES_FILE    1.0 时代的名，用户可能已经写进环境
        WAF_RULES_FILE         更早的写法，只为兼容

    这里绝不能少认名字 —— 早先只读 WAF_RULES_FILE（谁都不认的名字），
    用户按文档设了 AGENTWAF_RULES_FILE 指向共享规则集时，引擎读新文件、
    这里还在读 data/rules.json，两边开关状态会打架（该拦不拦）。
    """
    try:
        path = (os.environ.get("HUNTGUARD_RULES_FILE")
                or os.environ.get("AGENTWAF_RULES_FILE")
                or os.environ.get("WAF_RULES_FILE"))
        if not path:
            path = os.path.join(root, "data", "rules.json")
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        settings = data.get("settings") or {}
        value = settings.get("enabled", True)
        if isinstance(value, str):
            return value.strip().lower() not in ("0", "false", "no", "off", "")
        return bool(value)
    except Exception:
        return True


def _requests_ready():
    """requests 是否已经被真正打过补丁。"""
    try:
        import requests
    except ImportError:
        return False
    except Exception:
        return False
    try:
        marker = getattr(requests.Session.request, "_agentwaf_patched", False)
        if marker:
            return True
        return requests.Session.request.__name__ == "guarded_request"
    except Exception:
        return False


def _install(reason=""):
    """装护栏。可重复调用；装不全就留着钩子等下次。"""
    if _state["patched"] or _state["installing"]:
        return
    with _lock:
        if _state["patched"] or _state["installing"]:
            return
        _state["installing"] = True
        try:
            root = os.environ.get("WAF_ROOT") or _guess_root()
            _ensure_path(root)
            from waf import guard

            _state["attempts"] += 1
            # 第二次以后强制重装：第一次可能因为 requests 尚不可用、
            # 只装上了 urllib/subprocess，而 _installed 位已置。
            force = _state["attempts"] > 1
            enabled = guard.install_guard(patch_subprocess=True,
                                          follow_console=True, force=force)

            if _requests_ready():
                _state["patched"] = True
                _debug("[hook] installed (%s) -> %s" % (reason, enabled))
            else:
                # 还没打上 —— 保留 import 钩子，等 requests 被 import 时重试
                _debug("[hook] requests 尚未就绪 (%s) -> %s；保留钩子等待"
                       % (reason, enabled))
        except Exception as exc:
            import traceback
            _debug("[hook] install failed (%s): %r\n%s"
                   % (reason, exc, traceback.format_exc()))
        finally:
            _state["installing"] = False


def _root_of(name):
    dot = name.find(".")
    return name if dot < 0 else name[:dot]


def _hook_import():
    """包一层 __import__：等宿主真的用到 HTTP 库时再装补丁。

    只在需要时才挂（WAF 未开、或 requests 还没就绪）。装成功后立刻
    摘钩子，不给后续 import 留任何开销。
    """
    if _state["wrapped"]:
        return
    import builtins

    original = builtins.__import__

    def _hooked(name, globals=None, locals=None, fromlist=(), level=0):
        module = original(name, globals, locals, fromlist, level)
        try:
            if _root_of(name) in _ROOTS and not _state["patched"]:
                if _check_active():
                    _install(reason="import:%s" % name)
                if _state["patched"]:
                    builtins.__import__ = original      # 摘钩子
                    _state["wrapped"] = False
        except Exception:
            pass
        return module

    builtins.__import__ = _hooked
    _state["wrapped"] = True


def bootstrap():
    """入口：由 .pth 调用。"""
    if (os.environ.get("HUNTGUARD_NO_HOOK") == "1"
            or os.environ.get("AGENTWAF_NO_HOOK") == "1"):
        return
    # 自己起的内部子进程（regexguard 探测）不装护栏。
    #
    # 那些进程的 argv 里就带着规则/样本文本（含 drop / truncate 等
    # 破坏性动词），一旦装上护栏就会把自己当"待检命令"去扫，
    # 而扫描又要起探测子进程 —— 无限递归，实测冷缓存时 stderr
    # 刷满 engine_error。guard._check_cmd 与 regexguard._run_probe
    # 两侧也各有一道闸，这里是第三道（最早，连 guard 都不 import）。
    if os.environ.get("WAF_INTERNAL_PROC") == "1":
        return
    try:
        if _check_active():
            _install(reason="startup")
        if not _state["patched"]:
            # WAF 这会儿没开，或 requests 还没就绪 —— 两种情况下都
            # 需要钩子：前者等 WAF 开启后宿主首次 import HTTP 库，
            # 后者等 requests 真正可用的那一刻。
            _hook_import()
    except Exception:
        pass


bootstrap()
