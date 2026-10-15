# -*- coding: utf-8 -*-
"""wafctl —— HuntGuard 命令行入口。

    wafctl start [--proxy] [--mitm] [--no-browser]   启动控制台（可带代理）
    wafctl stop                                      停止控制台与代理
    wafctl status                                    查看状态
    wafctl doctor                                    环境自检
    wafctl check <URL|命令>                           单次检测
    wafctl unlock --minutes 10 --reason "..."         临时解锁
    wafctl lock                                      立即上锁
    wafctl mode block|monitor                        切换全局模式
    wafctl rules list|test|add                       规则操作
    wafctl events [-n 20] [--blocked]                查看日志
    wafctl proxy start|stop [--mitm] [--upstream H:P] 代理控制
    wafctl ca [--path]                               生成/查看 CA
    wafctl test                                      运行自测
"""

import argparse
import json
import os
import sys
import time
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import config, logstore, rules as rules_mod, state   # noqa: E402
from waf.engine import get_engine                          # noqa: E402
from waf.models import ScanTarget                          # noqa: E402

PID_FILE = os.path.join(config.RUN_DIR, "api.pid")


# ---------------------------------------------------------------- 工具

def out(text=""):
    sys.stdout.write(str(text) + "\n")


def _api_url(path=""):
    cfg = config.load_config()
    return "http://%s:%d%s" % (cfg["api_host"], cfg["api_port"], path)


def _http_json(path, method="GET", payload=None, timeout=6):
    """用 stdlib 调本地 API（不依赖 requests）。"""
    import urllib.error
    import urllib.request

    url = _api_url(path)
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    cfg = config.load_config()
    if cfg.get("auth_token"):
        headers["X-Auth-Token"] = cfg["auth_token"]
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8"))
        except Exception:
            raise RuntimeError("HTTP %s" % exc.code)
    except Exception as exc:
        raise RuntimeError("无法连接控制台（%s）：%s" % (url, exc))


def _write_pid(pid):
    config.ensure_dirs()
    with open(PID_FILE, "w", encoding="utf-8") as fh:
        fh.write(str(pid))


def _read_pid():
    try:
        with open(PID_FILE, "r", encoding="utf-8") as fh:
            return int(fh.read().strip())
    except (OSError, ValueError):
        return None


def _pid_alive(pid):
    if not pid:
        return False
    if os.name == "nt":
        import subprocess
        try:
            out_text = subprocess.check_output(
                ["tasklist", "/FI", "PID eq %d" % pid, "/NH"],
                stderr=subprocess.DEVNULL).decode("utf-8", "replace")
            return str(pid) in out_text
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _process_command_line(pid):
    """取某进程的命令行文本；拿不到返回 ""。"""
    import subprocess
    try:
        if os.name == "nt":
            # wmic 在部分系统上已弃用，优先用 PowerShell 的 CIM
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-CimInstance Win32_Process -Filter 'ProcessId=%d')"
                 ".CommandLine" % pid],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
            text = (result.stdout or b"").decode("utf-8", "replace").strip()
            if text:
                return text
            # 回退到 wmic
            result = subprocess.run(
                ["wmic", "process", "where", "ProcessId=%d" % pid,
                 "get", "CommandLine"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
            return (result.stdout or b"").decode("utf-8", "replace")
        # POSIX：/proc 里直接读
        with open("/proc/%d/cmdline" % pid, "rb") as fh:
            return fh.read().decode("utf-8", "replace").replace("\x00", " ")
    except Exception:
        return ""


def _is_our_console_process(pid):
    """这个 PID 真的是本工具的控制台进程吗？

    为什么不能只比对 PID：pid 文件可写，值还可能被系统回收复用 ——
    直接 taskkill /F 有可能打到用户的其它进程上（正在编辑的文档、
    正在跑的数据库），那是不可逆的伤害。

    判据（任一成立即可）：
      1. 命令行里出现 waf/cli.py（或 waf\\cli.py）—— 本工具的入口脚本
      2. 命令行里出现本安装目录

    注意**不能要求"路径是绝对路径"**：start.bat 里先 cd 到安装目录
    再用相对路径启动，命令行实际是 `python waf\\cli.py start`
    （实测如此）。所以判据只认入口脚本名 + 安装目录任一，
    并且校验进程 cwd 是否等于安装目录。

    拿不到命令行信息时返回 False —— 宁可少杀，不可错杀：
    没杀掉最多让用户手动关个窗口。
    """
    cmdline = _process_command_line(pid)
    if not cmdline:
        return False
    flat = cmdline.replace("/", "\\").lower()
    root = config.ROOT.replace("/", "\\").lower().rstrip("\\")

    # 入口脚本名是最可靠的标志：只有我们的控制台会跑 waf\cli.py
    entry_ok = ("waf\\cli.py" in flat) and ("start" in flat)
    if entry_ok:
        return True

    # 退一步：命令行里出现完整安装目录，且是本工具的入口
    if root and root in flat and "waf\\cli.py" in flat:
        return True

    return False


def _console_alive():
    try:
        _http_json("/api/health", timeout=2)
        return True
    except Exception:
        return False


# ---------------------------------------------------------------- 命令

def cmd_start(args):
    config.ensure_dirs()
    rules_mod.write_defaults_if_missing()
    logstore.init_db()

    out("")
    out("  " + "=" * 52)
    out("   HuntGuard 控制台")
    out("  " + "=" * 52)

    if _console_alive():
        out("  控制台已在运行：%s" % _api_url("/"))
    else:
        from waf import api as api_mod
        import threading

        def _run():
            api_mod.serve(open_browser=not args.no_browser)

        thread = threading.Thread(target=_run, daemon=False)
        thread.start()
        _write_pid(os.getpid())

    if args.proxy or args.mitm:
        time.sleep(0.6)
        try:
            result = _http_json("/api/proxy", "POST", {
                "action": "start", "mitm": bool(args.mitm),
                "upstream": args.upstream_host,
                "upstream_port": args.upstream_port,
            })
            status = result.get("status", {})
            out("  代理已启动：%s:%s%s" % (
                status.get("host"), status.get("port"),
                "（MITM）" if status.get("mitm") else ""))
        except RuntimeError as exc:
            out("  代理启动失败：%s" % exc)

    if not _console_alive():
        out("  控制台启动失败，请检查端口占用：%s" % _api_url("/"))
        out("  排查：wafctl doctor")
        return 1

    out("")
    out("  控制台地址 : %s" % _api_url("/"))
    out("  规则文件   : %s" % config.rules_path())
    out("")
    out("  拦截器状态 : %s" % ("已启用" if get_engine().enabled() else "已暂停"))
    out("  保持本窗口开着；关闭窗口 = 停止拦截。")
    out("  按 Ctrl+C 也可以停止。")
    out("")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        out("")
        out("  正在关闭…")
        try:
            _http_json("/api/shutdown", "POST", {})
        except Exception:
            pass
        return 0


def cmd_stop(args):
    stopped = False
    if _console_alive():
        try:
            _http_json("/api/shutdown", "POST", {}, timeout=3)
            out("  已请求控制台关闭")
            stopped = True
        except Exception as exc:
            out("  关闭请求失败：%s" % exc)
    else:
        out("  控制台未运行")

    # 无论控制台是否响应，都清掉激活态：拦截器立即失效
    try:
        state.deactivate()
        out("  拦截器已停用（curl 恢复透传）")
    except Exception:
        pass

    pid = _read_pid()
    if pid and _pid_alive(pid) and pid != os.getpid():
        # 杀之前先确认这个 PID 真的是我们的控制台。
        #
        # 为什么必须验证：pid 文件（data/run/console.pid）是可写的，
        # 伪造/残留/被回收复用都会让 taskkill /F 打到无关进程上 ——
        # 强杀用户正在编辑的文档、正在跑的数据库，都是不可逆的伤害。
        # 判据：进程命令行里要同时出现本安装目录和 waf/cli.py。
        # 拿不到命令行信息时（权限不足等）**不杀**，只提示手动处理。
        if _is_our_console_process(pid):
            try:
                if os.name == "nt":
                    import subprocess
                    subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                else:
                    import signal
                    os.kill(pid, signal.SIGTERM)
                out("  已结束进程 %d" % pid)
                stopped = True
            except Exception as exc:
                out("  结束进程 %d 失败：%s" % (pid, exc))
        else:
            out("  跳过进程 %d：无法确认它是本工具的控制台"
                "（PID 可能已被回收或 pid 文件被改动）" % pid)
            out("  如果控制台仍在运行，请手动关闭它的窗口")
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except OSError:
        pass
    return 0 if stopped or not _console_alive() else 1


def cmd_on(args):
    """开启拦截：先激活拦截器，再确保控制台在跑。"""
    config.ensure_dirs()
    engine = get_engine()
    engine.set_enabled(True)

    if _console_alive():
        try:
            _http_json("/api/intercept", "POST", {"action": "on"})
        except Exception:
            pass
        out("  拦截器已开启（控制台运行中）")
    else:
        state.activate()
        out("  拦截器已开启（独立模式，无控制台）")
        out("  提示：控制台未运行，可在其启动后到网页里管理规则")

    st = state.status()
    out("  状态 : %s" % ("已启用" if st["active"] and engine.enabled() else "未生效"))
    out("  说明 : curl 命中敏感词将被拦截（退出码 126）")
    out("  关闭 : wafctl off   或双击 stop.bat")
    return 0


def cmd_off(args):
    """关闭拦截：拦截器立即失效，curl 恢复透传。"""
    engine = get_engine()
    engine.set_enabled(False)
    if _console_alive():
        try:
            _http_json("/api/intercept", "POST", {"action": "off"})
        except Exception:
            pass
    state.deactivate()
    out("  拦截器已停用 —— 所有请求直接透传，不检查、不记录")
    out("  重新开启 : wafctl on   或双击 start.bat")
    return 0


def cmd_intercept_status(args):
    """拦截器开关状态。"""
    st = state.status()
    engine = get_engine()
    enabled = engine.enabled()
    live = st["active"] and enabled

    out("=" * 62)
    out("拦截器状态")
    out("=" * 62)
    out("是否生效     : %s" % ("已启用 —— 请求会被检查" if live
                              else "未启用 —— 请求直接透传"))
    out("用户开关     : %s" % ("开启" if enabled else "已暂停"))
    out("控制台运行   : %s" % ("是" if st["active"] else "否"))
    if st["age_sec"] is not None:
        out("心跳时间     : %.1f 秒前" % st["age_sec"])
    if st.get("pid"):
        out("控制台 PID   : %s" % st["pid"])
    if st.get("hint"):
        out("提示         : %s" % st["hint"])
    out("")
    out("  开启 : wafctl on     关闭 : wafctl off")
    out("=" * 62)
    return 0


def cmd_status(args):
    alive = _console_alive()
    st = state.status()
    engine = get_engine()
    live = st["active"] and engine.enabled()

    out("=" * 62)
    out("HuntGuard 状态")
    out("=" * 62)
    out("拦截器      : %s" % ("已启用 —— 请求会被检查" if live
                              else "未启用 —— 请求直接透传"))
    out("控制台      : %s" % ("运行中 " + _api_url("/") if alive else "未运行"))
    out("用户开关    : %s" % ("开启" if engine.enabled() else "已暂停"))
    if alive:
        try:
            data = _http_json("/api/status")
            out("模式        : %s" % data.get("mode"))
            out("故障策略    : fail_mode=%s" % data.get("fail_mode"))
            out("规则        : %s 启用 / %s 总" % (data.get("rules_enabled"), data.get("rules_total")))
            unlock = data.get("unlock_remaining") or 0
            if unlock > 0:
                out("解锁窗口    : 剩余 %.0f 秒（%s）" % (unlock, data.get("unlock_reason", "")))
            else:
                out("解锁窗口    : 未开启")
            proxy = data.get("proxy") or {}
            out("代理        : %s" % ("%s:%s%s" % (proxy.get("host"), proxy.get("port"),
                                                  " MITM" if proxy.get("mitm") else "")
                                      if proxy.get("running") else "未启动"))
            stats = data.get("stats") or {}
            out("今日请求    : %s（拦截 %s）" % (stats.get("today"), stats.get("today_blocked")))
            out("累计        : %s（拦截 %s）" % (stats.get("total"), stats.get("blocked")))
        except RuntimeError as exc:
            out("查询失败    : %s" % exc)
    else:
        out("规则（离线）: %s 启用 / %s 总" % (
            len([r for r in engine.rules if r.get("enabled", True)]), len(engine.rules)))
        if st.get("hint"):
            out("提示        : %s" % st["hint"])
    out("规则文件    : %s" % config.rules_path())
    out("日志库      : %s" % config.DB_FILE)
    out("")
    out("  开启拦截 : wafctl on    关闭拦截 : wafctl off")
    out("=" * 62)
    return 0


def cmd_mcp(args):
    """已移除：MCP 集成会让 AI 能直接改规则 / 关开关。

    这也是实测发现的最要命问题之一：护栏的钥匙不能交给被护栏
    约束的对象。AI 一旦被提示注入操纵，可以自己调 MCP 工具把护栏
    拆掉 —— 而"给 AI 装护栏"的价值恰恰是防这个。
    相关模块（mcp_server.py / mcp_register.py）已删除。
    """
    out("")
    out("  MCP 集成已移除。")
    out("")
    out("  原因：MCP 让 AI 能直接调用 waf_set_enabled(false) / waf_unlock /")
    out("        waf_add_allowlist 来解除防护。护栏不该把钥匙交给它约束的对象 ——")
    out("        被提示注入的 AI 可以自己把护栏拆掉。")
    out("")
    out("  需要改规则时请用控制台界面，或命令行：")
    out("    wafctl rules list / wafctl rules add / wafctl rules toggle")
    out("    wafctl on / wafctl off / wafctl unlock --minutes 10 --reason \"...\"")
    out("")
    return 0



def cmd_detect(args):
    """环境探测：找出 curl / Python / Git Bash 等真实路径并缓存。

    这是"下载即用"的关键一步 —— 别人的机器上这些工具装在哪完全不可知，
    与其让用户手工填（多数人填不对），不如全自动探测后缓存。
    """
    from waf import autodetect

    quiet = getattr(args, "quiet", False)
    if not quiet:
        out("=" * 62)
        out("环境探测")
        out("=" * 62)

    data = autodetect.write_cache()

    if quiet:
        # 只报错，不报成功（安装脚本里用）
        missing = [k for k in ("python", "curl") if not data.get(k)]
        if missing:
            out("  未找到：%s" % "、".join(missing))
        return 0 if not missing else 1

    for label, value, ok in autodetect.summary(data):
        mark = "[OK]  " if ok else "[--]  "
        out("%s%-16s %s" % (mark, label, value or "未找到"))
    out("")
    out("  缓存文件 : %s" % autodetect.cache_path())
    out("  shim 用  : data\\env.cmd（cmd） / data\\env.sh（Git Bash）")
    out("")
    missing = [k for k in ("python", "curl") if not data.get(k)]
    if missing:
        out("  缺少关键项：%s —— 拦截器可能无法工作" % "、".join(missing))
        out("  curl 可以手动指定：set WAF_REAL_CURL=<路径>")
        out("=" * 62)
        return 1
    out("  结论：一切就绪（别人下载后跑一次安装即可，无需手工填路径）")
    out("=" * 62)
    return 0


def _find_stale_mcp_entries():
    """找出 AI 客户端配置里残留的本工具 MCP 注册（1.0 版写过）。

    MCP 集成已移除（护栏不该把钥匙交给它约束的对象），但用户机器上的
    客户端配置里可能还留着 `mcpServers.agent-waf` 条目 —— 那些条目指向
    已被删除的 mcp_server.py，留着只会报错。这里只报告、不自动改，
    因为那属于用户自己的配置文件，删之前应该让人看一眼。
    """
    import glob as _glob
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, ".claude.json"),
        os.path.join(home, ".codex", "config.toml"),
        os.path.join(home, ".zcode", "mcp.json"),
        os.path.join(home, ".cursor", "mcp.json"),
        os.path.join(home, ".codeium", "windsurf", "mcp_config.json"),
    ]
    found = []
    for path in candidates:
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        if "agent-waf" not in text and "mcp_server.py" not in text:
            continue
        found.append((os.path.basename(path), path))
    return found


def cmd_audit(args):
    """审计：本工具在安装目录之外留下了什么。

    设计目标是**完全自包含** —— 所有文件都在安装目录内，外部只允许
    存在"指针"（注册表值、一行 profile 引用、AI 客户端配置里的条目）。
    这个命令把外部足迹全部列出来，方便确认和清理。
    """
    from waf import install_path

    out("=" * 62)
    out("外部足迹审计（安装目录：%s）" % ROOT)
    out("=" * 62)
    out("")
    out("  原则：文件全部在目录内，外部只留指针。删目录 = 外部仅剩几条")
    out("        可被『wafctl uninstall-path』清掉的注册表值。")
    out("")

    # ---- 目录内的关键文件 ----
    out("  [目录内文件]")
    internal = [
        ("规则", config.rules_path()),
        ("事件库", config.DB_FILE),
        ("环境探测缓存", os.path.join(config.DATA_DIR, "detected.json")),
        ("shim 用 env", os.path.join(config.DATA_DIR, "env.cmd")),
        ("Python 钩子", os.path.join(ROOT, "hooks", "sitecustomize.py")),
        ("PowerShell 脚本", os.path.join(ROOT, "bin", "waf.ps1")),
        ("调试日志", os.path.join(config.DATA_DIR, "logs")),
    ]
    for label, path in internal:
        exists = os.path.exists(path)
        out("    %s %-14s %s" % ("[有]" if exists else "[无]", label, path))
    out("")

    # ---- 外部指针（注册表）----
    out("  [外部指针 · 注册表]（不是文件，指向上面目录）")
    if os.name == "nt":
        rows = [
            ("HUNTGUARD_HOME", "主指针（其它机制靠它定位）",
             "HKCU\\Environment"),
            ("AGENTWAF_HOME", "主指针（1.0 旧名，兼容保留）",
             "HKCU\\Environment"),
            ("BASH_ENV", "Git Bash 钩子", "HKCU\\Environment"),
            ("PYTHONPATH", "Python 钩子", "HKCU\\Environment"),
            ("AutoRun", "cmd 钩子", "HKCU\\Software\\Microsoft\\Command Processor"),
        ]
        for name, desc, where in rows:
            out("    %-14s %-26s %s" % (name, desc, where))
    else:
        out("    非 Windows，无注册表指针")
    out("")

    # ---- 外部指针（文件）----
    out("  [外部指针 · 文件]（只有几行，指向上面目录）")
    ps_targets = install_path.powershell_profile_paths()
    ps_shown = False
    for path in ps_targets:
        if os.path.isfile(path):
            out("    PowerShell profile  %s" % path)
            ps_shown = True
    if not ps_shown:
        out("    PowerShell profile  未安装")
    bashrc = install_path.user_bashrc_path()
    if os.path.isfile(bashrc):
        out("    ~/.bashrc           %s" % bashrc)
    else:
        out("    ~/.bashrc           未安装")

    mcp_stale = _find_stale_mcp_entries()
    for name, path in mcp_stale:
        out("    MCP 旧条目（建议删除）%s" % path)
    out("")

    # ---- 旧版遗留检查 ----
    legacy = []
    site_dir = install_path.python_user_site()
    if site_dir:
        for name in install_path.LEGACY_HOOK_FILES:
            if os.path.isfile(os.path.join(site_dir, name)):
                legacy.append(os.path.join(site_dir, name))
    tmp_log = os.path.join(os.environ.get("TEMP", ""), "agent_waf_hook.log")
    if os.path.isfile(tmp_log):
        legacy.append(tmp_log)
    if legacy:
        out("  [旧版遗留 · 建议清理]")
        for path in legacy:
            out("    %s" % path)
        out("    运行『wafctl install-path』会自动清理")
        out("")
    else:
        out("  [旧版遗留] 未发现 ✓")
        out("")

    out("  完全卸载：wafctl uninstall-path")
    out("=" * 62)
    return 0


def cmd_doctor(args):
    """环境自检：把接入相关的关键条件都验一遍。"""
    out("=" * 62)
    out("HuntGuard 环境自检")
    out("=" * 62)
    ok = True

    def line(name, good, detail=""):
        nonlocal ok
        mark = "[OK]  " if good else "[!!]  "
        if not good:
            ok = False
        out("%s%s %s" % (mark, name.ljust(22), detail))

    def optional(name, present, detail_present="", detail_missing=""):
        """可选项：缺失用 [--] 标记，但**不判为故障**。

        用于 cryptography / requests 这类"没有也能用"的依赖 ——
        它们缺失只会少一个功能（MITM / requests 补丁），
        而 doctor 把它们报成 [!!] 会让用户以为环境坏了（实测发现）。
        """
        if present:
            out("[OK]  %s %s" % (name.ljust(22), detail_present))
        else:
            out("[--]  %s %s" % (name.ljust(22), detail_missing))

    line("Python 版本", sys.version_info >= (3, 6),
         "%s.%s.%s" % sys.version_info[:3])
    # 这两个是可选依赖：缺了不影响拦截功能，只是少一项能力 ——
    # 用 [--] 标记，不参与"是否一切就绪"的判定
    optional("cryptography",
             _importable("cryptography"),
             "已安装（MITM 可检查 HTTPS 内容）",
             "未安装（可选；只有 MITM 需要，其余功能不受影响）")
    optional("requests",
             _importable("requests"),
             "已安装（guard 会补丁它）",
             "未安装（可选；只在 AI 脚本用 requests 时才有意义）")
    line("规则文件", os.path.exists(config.rules_path()), config.rules_path())
    line("UI 文件", os.path.exists(os.path.join(config.UI_DIR, "index.html")),
         os.path.join(config.UI_DIR, "index.html"))
    cfg = config.load_config()
    port_free = _port_free(cfg["api_port"])
    line("控制台端口 %d" % cfg["api_port"], port_free or _console_alive(),
         "空闲" if port_free else ("已被 HuntGuard 占用" if _console_alive() else "被其他程序占用"))
    line("代理端口 %d" % cfg["proxy_port"], _port_free(cfg["proxy_port"]),
         "空闲" if _port_free(cfg["proxy_port"]) else "被占用")

    from waf.curlshim import find_real_curl
    real = find_real_curl()
    line("真实 curl", bool(real), real or "未找到（设置 WAF_REAL_CURL）")
    line("bin/curl shim", os.path.exists(os.path.join(ROOT, "bin", "curl")),
         os.path.join(ROOT, "bin"))

    # PATH 优先级：这是最关键的检查项。Windows 把机器级 PATH 排在
    # 用户级前面，而 Git Bash 又是独立的一套解析顺序 —— 两个都要查。
    from waf import install_path
    pstatus = install_path.status(path_probe=True)

    resolved = pstatus.get("resolved") or []
    if pstatus.get("shim_wins"):
        line("cmd 解析顺序", True, "命中拦截器：%s" % resolved[0])
    elif resolved:
        line("cmd 解析顺序", False,
             "命中 %s（不是拦截器）—— 运行 wafctl install-path"
             % resolved[0])
    else:
        line("cmd 解析顺序", False, "未找到 curl")

    bash_resolved = pstatus.get("resolved_bash")
    if bash_resolved:
        if pstatus.get("shim_wins_bash"):
            line("Git Bash 解析顺序", True, "命中拦截器：%s" % bash_resolved[0])
        else:
            line("Git Bash 解析顺序", False,
                 "命中 %s（不是拦截器）—— AI 工具走这条路，务必安装"
                 % bash_resolved[0])
    else:
        line("Git Bash 解析顺序", True, "未检测到 Git Bash（跳过）")

    if os.name == "nt":
        methods = []
        if pstatus.get("machine_path_ok"):
            methods.append("机器级PATH")
        if pstatus.get("cmd_autorun"):
            methods.append("cmd AutoRun")
        if pstatus.get("bash_env"):
            methods.append("BASH_ENV")
        if pstatus.get("powershell_profile"):
            methods.append("PowerShell profile")
        line("已装接入方式", bool(methods),
             "、".join(methods) if methods else
             "未安装：运行 wafctl install-path（或 install.bat）")
        if not pstatus.get("is_admin"):
            out("       %s机器级 PATH 需管理员；AutoRun 与 BASH_ENV 不需要"
                % (" " * 6,))

    # Python 钩子：覆盖 AI 写的 requests 脚本（不经 shell，shim 拦不到）
    if pstatus.get("python_hook"):
        effective = pstatus.get("python_hook_effective")
        line("Python 钩子", bool(effective),
             "已生效：新起的 Python 进程自动装护栏" if effective
             else "已装但新进程未加载 —— 检查 %s" % pstatus.get("python_hook_file"))
    else:
        line("Python 钩子", False,
             "未安装：install-path 可覆盖 AI 写的 Python 脚本")

    engine = get_engine()
    line("引擎可用", True, "%d 条规则已加载" % len([r for r in engine.rules if r.get("enabled")]))

    probe = engine.scan(ScanTarget(kind="request", method="GET",
                                   url="http://selftest.invalid/delete.php?x=1",
                                   tool="doctor"), log=False)
    line("拦截功能", probe.blocked, "探针 %s" % ("已拦截" if probe.blocked else "未拦截（规则被停用？）"))

    st = state.status()
    line("拦截器开关", True,
         "已启用" if (st["active"] and engine.enabled())
         else ("未开启 —— 双击 start.bat 或 wafctl on" if not st["active"]
               else "已在控制台内暂停"))
    out("=" * 62)
    out("结论：" + ("一切就绪" if ok else "存在问题，见上面 [!!] 项"))
    return 0 if ok else 1


def cmd_install_path(args):
    """安装 PATH 接入，让 curl 真正走到拦截器。

    顺带做一次环境探测（写 data/env.cmd / env.sh）—— shim 依赖这些
    文件找 Python 和真实 curl。别人装到任意位置都能自动适配。
    """
    from waf import install_path, autodetect

    out("=" * 62)
    out("安装 curl 拦截接入")
    out("=" * 62)
    out("")

    # 先探测环境：不论哪个平台都要，shim 靠它定位 Python/curl
    try:
        data = autodetect.write_cache()
        if data.get("python"):
            out("  环境探测 : Python  %s" % data["python"])
        if data.get("curl"):
            out("  环境探测 : curl    %s" % data["curl"])
        if not data.get("curl"):
            out("  [!!] 未找到真实 curl —— shim 可能无法转发，"
                "可设 WAF_REAL_CURL 指定")
        out("")
    except Exception as exc:
        out("  [!!] 环境探测失败：%s（继续安装，shim 会动态搜索）" % exc)

    if os.name != "nt":
        out("  非 Windows 平台，请用：source scripts/install_shim.sh")
        return 0

    before = install_path.status(path_probe=True)
    if before.get("shim_wins") and not args.force:
        out("  已生效：curl 解析到 %s" % (before["resolved"] or ["?"])[0])
        out("  如需重装：wafctl install-path --force")
        return 0

    results = install_path.install(machine=bool(args.machine))

    for name, (ok, msg) in results.items():
        label = {"machine_path": "机器级 PATH",
                 "cmd_autorun": "cmd AutoRun",
                 "powershell": "PowerShell profile"}.get(name, name)
        mark = "[OK]  " if ok else "[!!]  "
        out("%s%s %s" % (mark, label.ljust(18), msg))

    out("")
    after = install_path.status(path_probe=True)
    if after.get("shim_wins") and after.get("shim_wins_bash", True):
        out("  验证：新开的 cmd / Git Bash 窗口里 curl 会先命中拦截器")
    elif after.get("shim_wins"):
        out("  cmd 已生效；但 Git Bash 仍是原生 curl —— 看上面的 Git Bash 项")
    else:
        out("  注意：cmd 未走拦截器。")
        out("  AutoRun / BASH_ENV 只对**新开的**窗口生效。")
        out("  想要全局生效（含 PowerShell -NoProfile、AI 工具直调 exe）：")
        out("    以管理员身份运行： wafctl install-path --machine")
    out("")
    out("  验证方法（各开一个新窗口）：")
    out("    cmd        where curl    第一行应是 %s" %
        os.path.join(install_path.bin_dir(), "curl"))
    out("    Git Bash   which curl    应显示 %s" %
        install_path._to_posix(install_path.bin_dir()))
    out("")
    out("  AI 工具覆盖（ZCode / Claude Code / Codex / WorkBuddy）：")
    out("    Git Bash（执行命令）  BASH_ENV  → 已覆盖")
    out("    Python 脚本           PYTHONPATH + hooks/sitecustomize.py → 已覆盖")
    out("    cmd / PowerShell      AutoRun / profile → 已覆盖")
    out("    直接调 exe、-NoProfile  需机器级 PATH：wafctl install-path --machine")
    return 0


def cmd_uninstall_path(args):
    from waf import install_path
    results = install_path.uninstall()
    for name, (ok, msg) in results.items():
        out("%s %s：%s" % ("[OK]  " if ok else "[!!]  ", name, msg))
    out("")
    out("  已恢复原生 curl 行为。重新安装：wafctl install-path")
    return 0


def _importable(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _port_free(port):
    import socket
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", int(port)))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _shim_in_path():
    bin_dir = os.path.join(ROOT, "bin")
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        if folder and os.path.normcase(os.path.abspath(folder)) == os.path.normcase(bin_dir):
            return True
    return False


def _shim_in_user_registry():
    """检查用户级 PATH 注册表里是否已有 shim（可能只是当前终端未刷新）。"""
    if os.name != "nt":
        return False
    try:
        import subprocess
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "[Environment]::GetEnvironmentVariable('Path','User')"],
            capture_output=True, timeout=15)
        text = result.stdout.decode("utf-8", "replace")
        return "agent-waf" in text.lower() and "bin" in text.lower()
    except Exception:
        return False


def cmd_check(args):
    """单次检测：URL / curl 命令 / 裸文本都能测。

    注意：这里拿到的 target 是 argparse.REMAINDER 原样 token 列表，
    因此 curl 自己的 -X / -H / -d 不会被解析掉。
    """
    tokens = [t for t in (args.target or []) if t != "--no-log"]
    raw = " ".join(tokens)
    if not raw:
        out("用法：wafctl check \"http://x/delete.php\"  或  wafctl check curl -X POST ...")
        return 2

    engine = get_engine()
    lowered = raw.lower()
    if lowered.startswith("curl"):
        from waf.curlshim import parse_curl_args
        argv = _split_args(raw[len("curl"):].strip())
        target, _ = parse_curl_args(argv)
        target.tool = "check"
    elif lowered.startswith(("http://", "https://")):
        from urllib.parse import urlsplit
        parts = urlsplit(raw)
        target = ScanTarget(kind="request", method="GET", url=raw,
                            host=parts.netloc, path=parts.path,
                            query=parts.query, tool="check")
    elif len(tokens) > 1 and tokens[0] in ("-X", "--request", "-H", "--header",
                                           "-d", "--data", "--url"):
        # 用户省略了开头的 curl 字样：仍按 curl 参数解析
        from waf.curlshim import parse_curl_args
        target, _ = parse_curl_args(tokens)
        target.tool = "check"
    else:
        target = ScanTarget(kind="text", method="", body=raw, tool="check")

    verdict = engine.scan(target, log=not args.no_log)
    out(verdict.to_json(indent=2, include_meta=True))
    return 126 if verdict.blocked else 0


def _split_args(text):
    out_list = []
    cur = ""
    quote = None
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
            else:
                cur += ch
        elif ch in "\"'":
            quote = ch
        elif ch.isspace():
            if cur:
                out_list.append(cur)
                cur = ""
        else:
            cur += ch
    if cur:
        out_list.append(cur)
    return out_list


def cmd_unlock(args):
    try:
        result = _http_json("/api/unlock", "POST",
                            {"minutes": args.minutes, "reason": args.reason})
        out("[wafctl] 已解锁 %s 分钟，剩余 %.0f 秒" % (args.minutes, result.get("remaining", 0)))
        out("[wafctl] 理由：%s" % args.reason)
        out("[wafctl] 到期自动上锁；立即上锁：wafctl lock")
        return 0
    except RuntimeError as exc:
        # 控制台没开也能解锁：直接写规则文件
        engine = get_engine()
        engine.set_unlock(args.minutes, args.reason)
        out("[wafctl] 控制台未运行，已直接写入规则文件解锁 %s 分钟" % args.minutes)
        return 0


def cmd_lock(args):
    try:
        _http_json("/api/lock", "POST", {})
        out("[wafctl] 已上锁")
    except RuntimeError:
        get_engine().clear_unlock()
        out("[wafctl] 控制台未运行，已直接写入规则文件上锁")
    return 0


def cmd_mode(args):
    mode = args.value.lower()
    if mode not in ("block", "monitor"):
        out("模式只能是 block 或 monitor")
        return 2
    doc = rules_mod.load_document(config.rules_path())
    doc.setdefault("settings", {})["mode"] = mode
    rules_mod.save_document(doc, config.rules_path())
    get_engine().load(force=True)
    out("[wafctl] 全局模式已切换为 %s" % mode)
    return 0


def cmd_rules(args):
    engine = get_engine()
    if args.action == "list":
        rows = engine.rules
        out("%-8s %-9s %-9s %-6s %s" % ("ID", "级别", "动作", "启用", "名称"))
        out("-" * 78)
        for rule in rows:
            out("%-8s %-9s %-9s %-6s %s" % (
                rule.get("id"), rule.get("severity"), rule.get("action"),
                "是" if rule.get("enabled", True) else "否", rule.get("name")))
        out("")
        out("共 %d 条（启用 %d）" % (len(rows), len([r for r in rows if r.get("enabled", True)])))
        return 0

    if args.action == "test":
        if not args.pattern:
            out("用法：wafctl rules test <内容>")
            return 2
        return cmd_check(argparse.Namespace(target=[args.pattern], no_log=True))

    if args.action == "dump":
        path = config.rules_path()
        with open(path, "r", encoding="utf-8") as fh:
            out(fh.read())
        return 0

    out("未知子命令：%s（可用：list / test / dump）" % args.action)
    return 2


def cmd_events(args):
    action = getattr(args, "action", None) or "list"

    if action == "clear":
        keep = getattr(args, "keep_days", None)
        before = logstore.query_events(limit=1)["total"]
        if before == 0:
            out("没有记录需要清理")
            return 0
        if keep is None:
            out("将清空**全部** %d 条记录（不可恢复）" % before)
        else:
            out("将删除 %s 天前的记录（共 %d 条）" % (keep, before))
        if not getattr(args, "yes", False):
            try:
                answer = input("确认？输入 yes 继续：").strip().lower()
            except (EOFError, KeyboardInterrupt):
                out("已取消")
                return 1
            if answer not in ("yes", "y"):
                out("已取消")
                return 1
        logstore.clear_events(keep_days=keep)
        after = logstore.query_events(limit=1)["total"]
        out("已清理：%d → %d 条" % (before, after))
        return 0

    data = logstore.query_events(limit=args.number, blocked_only=args.blocked)
    out("%-19s %-6s %-7s %-10s %s" % ("时间", "状态", "方法", "规则", "目标"))
    out("-" * 100)
    for item in data["items"]:
        status = "拦截" if item["blocked"] else ("解锁" if item["unlocked"] else "放行")
        target = (item["target"] or "")[:52]
        out("%-19s %-6s %-7s %-10s %s" % (
            item["ts_text"], status, item["method"] or "-",
            ",".join(item["rule_ids"]) or "-", target))
    out("")
    out("共 %d 条（显示 %d）" % (data["total"], len(data["items"])))
    if data["total"]:
        out("清理：wafctl events clear                    （清空全部）")
        out("      wafctl events clear --keep-days 7     （只留最近 7 天）")
    return 0


def cmd_proxy(args):
    if args.action == "status":
        try:
            out(json.dumps(_http_json("/api/proxy"), ensure_ascii=False, indent=2))
        except RuntimeError as exc:
            out("控制台未运行：%s" % exc)
        return 0
    if args.action == "start":
        try:
            result = _http_json("/api/proxy", "POST", {
                "action": "start", "mitm": args.mitm,
                "upstream": args.upstream_host, "upstream_port": args.upstream_port})
            out(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        except RuntimeError as exc:
            out("需要先启动控制台：wafctl start")
            out("（%s）" % exc)
            return 1
    if args.action == "stop":
        try:
            _http_json("/api/proxy", "POST", {"action": "stop"})
            out("代理已停止")
            return 0
        except RuntimeError as exc:
            out("控制台未运行：%s" % exc)
            return 1
    return 2


def cmd_ca(args):
    from waf import certs
    if not certs.available():
        out("需要 cryptography：python -m pip install cryptography")
        return 1
    try:
        paths = certs.ca_paths()
    except Exception as exc:
        out("生成失败：%s" % exc)
        return 1
    if args.path:
        out(paths["cert"])
        return 0
    out("CA 已就绪：")
    for key in ("dir", "cert", "key", "combined"):
        out("  %-9s %s" % (key, paths[key]))
    out("")
    out("导入方法：")
    out("  Windows : 双击 %s → 安装证书 → 本地计算机 → 受信任的根证书颁发机构" % paths["cert"])
    out("  Firefox : 设置 → 隐私与安全 → 证书 → 查看证书 → 导入")
    out("  curl    : curl --cacert \"%s\" https://目标" % paths["cert"])
    return 0


def cmd_test(args):
    """运行内置自测。"""
    import unittest
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    loader = unittest.TestLoader()
    try:
        suite = loader.discover(os.path.join(ROOT, "tests"), pattern="test_*.py")
    except Exception as exc:
        out("无法加载测试：%s" % exc)
        return 1
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return 0 if result.wasSuccessful() else 1


# ---------------------------------------------------------------- 入口

def build_parser():
    parser = argparse.ArgumentParser(
        prog="wafctl", description="HuntGuard 控制台",
        formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__)
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("start", help="启动控制台")
    p.add_argument("--proxy", action="store_true", help="同时启动拦截代理")
    p.add_argument("--mitm", action="store_true", help="代理开启 MITM（拦截 HTTPS 内容）")
    p.add_argument("--upstream", dest="upstream_host", default=None, help="上游代理主机（如 Burp）")
    p.add_argument("--upstream-port", dest="upstream_port", type=int, default=None)
    p.add_argument("--no-browser", action="store_true", help="不自动打开浏览器")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("stop", help="停止控制台")
    p.set_defaults(func=cmd_stop)

    p = sub.add_parser("on", help="开启拦截（打开才生效）")
    p.set_defaults(func=cmd_on)

    p = sub.add_parser("off", help="暂停拦截（恢复纯透传）")
    p.set_defaults(func=cmd_off)

    p = sub.add_parser("intercept", help="查看拦截器开关状态")
    p.set_defaults(func=cmd_intercept_status)

    p = sub.add_parser("status", help="查看状态")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("doctor", help="环境自检")
    p.set_defaults(func=cmd_doctor)

    p = sub.add_parser("detect", help="自动探测 curl/Python/Git Bash 路径并缓存")
    p.add_argument("--quiet", action="store_true",
                   help="只输出问题（安装脚本用）")
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("audit", help="审计：列出安装目录之外的所有足迹")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("install-path", help="安装 PATH 接入（让 curl 走到拦截器）")
    p.add_argument("--machine", action="store_true",
                   help="写入机器级 PATH（需管理员，全局生效）")
    p.add_argument("--force", action="store_true", help="即使已生效也重新安装")
    p.set_defaults(func=cmd_install_path)

    p = sub.add_parser("uninstall-path", help="移除 PATH 接入")
    p.set_defaults(func=cmd_uninstall_path)

    p = sub.add_parser("check", help="单次检测（URL / curl 命令 / 文本）")
    p.add_argument("--no-log", action="store_true", help="不写日志")
    # 注意：curl 自身参数（-X / -H / -d）不能被 argparse 吃掉，
    # 所以这里用 REMAINDER 原样收集，检测时再自行解析。
    p.add_argument("target", nargs=argparse.REMAINDER, help="要检测的内容")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("unlock", help="临时解锁（危险）")
    p.add_argument("--minutes", type=float, default=10)
    p.add_argument("--reason", required=True, help="解锁理由（写入日志）")
    p.set_defaults(func=cmd_unlock)

    p = sub.add_parser("lock", help="立即上锁")
    p.set_defaults(func=cmd_lock)

    p = sub.add_parser("mode", help="切换全局模式 block/monitor")
    p.add_argument("value", choices=["block", "monitor"])
    p.set_defaults(func=cmd_mode)

    p = sub.add_parser("rules", help="规则操作")
    p.add_argument("action", nargs="?", default="list",
                   choices=["list", "test", "dump"])
    p.add_argument("pattern", nargs="?", default=None)
    p.set_defaults(func=cmd_rules)

    p = sub.add_parser("events", help="查看 / 清理日志")
    p.add_argument("action", nargs="?", default="list",
                   choices=["list", "clear"], help="list=查看（默认），clear=清理")
    p.add_argument("-n", "--number", type=int, default=20)
    p.add_argument("--blocked", action="store_true", help="只看拦截")
    p.add_argument("--keep-days", type=float, default=None,
                   help="clear 时只删这个天数之前的记录（不填=全清）")
    p.add_argument("--yes", action="store_true", help="跳过确认（脚本用）")
    p.set_defaults(func=cmd_events)

    p = sub.add_parser("proxy", help="代理控制")
    p.add_argument("action", nargs="?", default="status",
                   choices=["start", "stop", "status"])
    p.add_argument("--mitm", action="store_true")
    p.add_argument("--upstream", dest="upstream_host", default=None)
    p.add_argument("--upstream-port", dest="upstream_port", type=int, default=None)
    p.set_defaults(func=cmd_proxy)

    p = sub.add_parser("ca", help="生成/查看 MITM CA")
    p.add_argument("--path", action="store_true", help="只输出证书路径")
    p.set_defaults(func=cmd_ca)

    # mcp 命令保留但只做说明：MCP 集成已移除（护栏不该把钥匙交给
    # 它约束的对象 —— 被提示注入的 AI 能自己调 MCP 工具关掉护栏）。
    # 保留该子命令是为了让老用户敲 `wafctl mcp` 时能看到解释，
    # 而不是一句 "invalid choice" 让人以为工具坏了。
    p = sub.add_parser("mcp", help="（已移除）MCP 集成说明")
    p.add_argument("action", nargs="?", default="status")
    p.set_defaults(func=cmd_mcp)

    p = sub.add_parser("test", help="运行自测")
    p.set_defaults(func=cmd_test)

    return parser


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)

    # check 命令绕开 argparse：它要接收 curl 的原生参数（-X/-H/-d），
    # argparse 会把这些当成自己的选项而报错。
    if argv and argv[0] == "check":
        rest = argv[1:]
        no_log = "--no-log" in rest
        rest = [t for t in rest if t != "--no-log"]
        if not rest:
            out("用法：wafctl check \"http://x/delete.php\"  或  wafctl check curl -X POST ...")
            return 2
        config.ensure_dirs()
        try:
            return cmd_check(SimpleNamespace(target=rest, no_log=no_log)) or 0
        except KeyboardInterrupt:
            return 130

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    config.ensure_dirs()
    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
