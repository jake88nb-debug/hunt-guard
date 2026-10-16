# -*- coding: utf-8 -*-
"""PATH 接入管理：让 `curl` 真正解析到 HuntGuard 的拦截器。

为什么需要这模块
----------------
Windows 组合 PATH 时是 **机器级 + 用户级**，且机器级排在前面。
`C:\\Windows\\System32` 属于机器级，里面有真的 `curl.exe`，
所以只把 `bin\\` 写进「用户级 PATH」是**无效的** —— 真实 curl 永远先命中。

三种接入方式（按可靠性排序）
--------------------------
1. `machine`  把 bin 写到机器级 PATH 最前面。需要管理员。
              对所有进程生效（cmd / PowerShell / GUI 程序）。
2. `cmd_autorun`  写 HKCU\\Software\\Microsoft\\Command Processor\\AutoRun。
              免管理员，**新开的 cmd 窗口**立即生效。cmd.exe 启动时会执行它。
              附带好处：AI 脚本用 shell=True 起的 cmd 也会被覆盖。
3. `powershell`  写 PowerShell profile，让 PowerShell 会话生效。
"""

import os
import subprocess
import sys

from . import config

MARKER = "AGENT_WAF_HOME"
AUTORUN_KEY = r"Software\Microsoft\Command Processor"
PROFILE_MARK = "# agent-waf"
PROFILE_END_MARK = "# end-agent-waf"
BASHRC_MARK = "# agent-waf curl shim"


# ---------------------------------------------------------------- 基础

def bin_dir():
    return os.path.join(config.ROOT, "bin")


def is_windows():
    return os.name == "nt"


def is_admin():
    if not is_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _try_import_winreg():
    try:
        import winreg
        return winreg
    except ImportError:
        return None


# ---------------------------------------------------------------- 查询

def machine_path():
    if is_windows():
        return os.environ.get("Path", "") or os.environ.get("PATH", "")
    return os.environ.get("PATH", "")


def read_registry_path(scope):
    """scope: 'Machine' | 'User'。"""
    if not is_windows():
        return ""
    winreg = _try_import_winreg()
    if winreg is None:
        return ""
    root = winreg.HKEY_LOCAL_MACHINE if scope == "Machine" else winreg.HKEY_CURRENT_USER
    subkey = (r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
              if scope == "Machine" else "Environment")
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "Path")
            return value or ""
    except (OSError, FileNotFoundError):
        return ""


def _normalize(path):
    """路径归一化，用于比较"是不是同一个目录"。

    空值必须返回空串 —— ``os.path.abspath("")`` 会返回**当前工作目录**，
    而安装脚本恰好就在安装目录里执行（install.bat / wafctl install-path），
    于是 ``_normalize("") == _normalize(ROOT)`` 恒成立，调用方会把
    "注册表里没这个值" 误判成 "值已经对了"：

        install_home_env()  →  报告"已是目标值"，实际一个字节都没写
        → 主指针环境变量永远不存在 → PowerShell profile 的条件行不生效
        → PowerShell 里 curl 仍是 Invoke-WebRequest 别名，静默绕过拦截

    换个目录跑就正常，所以特别难发现。
    """
    if not path:
        return ""
    return os.path.normcase(os.path.abspath(path)).rstrip("\\")


def _to_posix(win_path):
    """D:\\agent-waf\\bin -> /d/agent-waf/bin"""
    text = win_path.replace("\\", "/")
    if len(text) > 1 and text[1] == ":":
        text = "/" + text[0].lower() + text[2:]
    return text


def _same_dir(candidate, target):
    """比较目录是否相同 —— 兼容 Windows 路径与 Git Bash 的 POSIX 路径。

    bash 里 ``which curl`` 返回 ``/d/agent-waf/bin/curl``，
    而 ``bin_dir()`` 是 ``D:\\agent-waf\\bin``。直接 normcase 比会不相等，
    于是把 shim 自己误判成"原生 curl"。
    """
    cand = candidate.replace("\\", "/").rstrip("/").lower()
    targ_win = target.replace("\\", "/").rstrip("/").lower()
    targ_posix = _to_posix(target).rstrip("/").lower()
    return cand in (targ_win, targ_posix)


def path_entries(text):
    return [p for p in (text or "").split(os.pathsep) if p.strip()]


def in_registry_path(scope):
    target = _normalize(bin_dir())
    return any(_normalize(p) == target for p in path_entries(read_registry_path(scope)))


def resolve_curl():
    """模拟新进程的解析结果：机器级 PATH 在前，用户级在后。"""
    if not is_windows():
        return subprocess.run(["which", "curl"], capture_output=True,
                              text=True).stdout.strip().splitlines()
    combined = path_entries(read_registry_path("Machine")) + \
        path_entries(read_registry_path("User"))
    hits = []
    for folder in combined:
        for name in ("curl.exe", "curl.cmd", "curl.bat", "curl"):
            candidate = os.path.join(folder, name)
            if os.path.isfile(candidate):
                hits.append(candidate)
                break
    return hits


def cmd_autorun_value():
    if not is_windows():
        return ""
    winreg = _try_import_winreg()
    if winreg is None:
        return ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0,
                            winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "AutoRun")
            return value or ""
    except (OSError, FileNotFoundError):
        return ""


def has_cmd_autorun():
    return MARKER in cmd_autorun_value()


def powershell_profile_paths():
    """返回所有需要安装的 PowerShell profile 路径。

    Windows 上通常装了两套 PowerShell：
      * Windows PowerShell 5.1 -> ~\\Documents\\WindowsPowerShell\\profile.ps1
      * PowerShell 7 (pwsh)    -> ~\\Documents\\PowerShell\\profile.ps1

    只装 5.1 的话，用 pwsh 的 AI 会话就漏了。
    """
    if not is_windows():
        return []
    home = os.path.expanduser("~")
    targets = [
        os.path.join(home, "Documents", "WindowsPowerShell", "profile.ps1"),
    ]
    # PS7 只在装了 pwsh 时才写，避免给没装的人留下无用文件
    ps7_dir = os.path.join(home, "Documents", "PowerShell")
    if _pwsh_installed() or os.path.isdir(ps7_dir):
        targets.append(os.path.join(ps7_dir, "profile.ps1"))
    return targets


def _pwsh_installed():
    for candidate in (r"C:\Program Files\PowerShell",):
        if os.path.isdir(candidate):
            return True
    return shutil_which("pwsh") is not None


def shutil_which(name):
    try:
        import shutil
        return shutil.which(name)
    except Exception:
        return None


def has_powershell_profile():
    """是否至少有一个 PowerShell profile 装好了接入（一行指针）。"""
    script = os.path.join(bin_dir(), "waf.ps1")
    for path in powershell_profile_paths():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            continue
        if PROFILE_MARK in content and os.path.basename(script) in content:
            return True
    return False


# ---------------------------------------------------------------- 安装

def _autorun_command():
    """AutoRun 要执行的命令：把 bin 前置到 PATH。

    注意两点：
    * 不能用 `rem` 做标记 —— rem 会吞掉同一行 `&` 之后的命令。
      所以用 `set AGENT_WAF_HOME=...` 当标记，它本身也是无害的。
    * `set "PATH=..."` 必须带内层引号，否则 PATH 里的空格
      （如 C:\\Program Files）会让 set 只截取到第一个空格。
    """
    return 'set "%s=%s" & set "PATH=%s;%%PATH%%"' % (
        MARKER, config.ROOT, bin_dir())


def _strip_our_autorun(value):
    """从已有 AutoRun 里移除**所有** agent-waf 写入的片段。

    关键：不能只删"指向当前安装目录"的片段。同一个套件被解压两份
    （或用户挪了文件夹），旧副本的片段也带 MARKER —— 只删自己那份的话
    会留下 `set "PATH=D:\\旧副本\\bin;%PATH%"`，于是 cmd 里 PATH 同时
    前置两个目录：先命中的是**旧副本**，你改了规则、重启控制台，
    却发现自己新装的那份完全不生效。而且卸载时也清不干净。

    我们写进去的是一**对**相邻片段：

        set "AGENT_WAF_HOME=<root>" & set "PATH=<root>\\bin;%PATH%"

    标记只在第一个上，所以必须成对识别：见到带 MARKER 的片段，
    把它和紧随其后的那个 `set "PATH=...;%PATH%"` 一起丢掉。
    否则就会留下一句把旧副本前置进 PATH 的残留（实测踩过）。
    """
    if MARKER not in value:
        return value
    chunks = [c.strip() for c in value.split("&")]
    keep = []
    index = 0
    while index < len(chunks):
        chunk = chunks[index]
        if not chunk:
            index += 1
            continue
        if MARKER in chunk:
            # 带标记的片段：连同紧随其后的 PATH 片段一起跳过。
            # 这里用**结构**判断而不是查目录是否存在 —— 旧副本可能已被
            # 删除（正是要清理的场景），但它那一对片段还在注册表里。
            nxt = chunks[index + 1] if index + 1 < len(chunks) else ""
            if _looks_like_path_prepend(nxt):
                index += 2
                continue
            index += 1
            continue
        # 孤立残留（比如旧版只写了 PATH 段，或手动改过顺序）：
        # 认得出是 agent-waf 的 bin 也删掉
        if _is_our_path_chunk(chunk):
            index += 1
            continue
        keep.append(chunk)
        index += 1
    return " & ".join(keep)


def _looks_like_path_prepend(chunk):
    """是不是 `set "PATH=<某目录>;%PATH%"` 这种"把目录前置"的写法。

    只做结构判断，不碰文件系统 —— 清理残留时旧副本往往已经删掉了。
    """
    text = (chunk or "").strip()
    if not text:
        return False
    lowered = text.lower()
    if not lowered.startswith("set "):
        return False
    body = lowered[4:].lstrip()
    if not body.startswith('"path='):
        return False
    if "%path%" not in body:
        return False
    after = body[len('"path='):]
    return ";" in after and after.split(";", 1)[0].strip('"').strip() != ""


def _is_our_path_chunk(chunk):
    """判断一个 AutoRun 片段是不是我们写的 `set "PATH=<...>\\bin;%PATH%"`。

    只在"孤立残留"（没有配对标记）时用到，这时要更保守：
    既看结构，也看路径特征，避免误删用户自己的 PATH 设置。
    """
    if not _looks_like_path_prepend(chunk):
        return False
    text = (chunk or "").strip()
    lowered = text.lower()[4:].lstrip()
    after = lowered[len('"path='):]
    head = after.split(";", 1)[0].strip('"').strip()
    if not head:
        return False
    head = head.replace("/", "\\").rstrip("\\")
    if os.path.basename(head).lower() != "bin":
        return False
    try:
        if head.upper() == bin_dir().upper():
            return True
    except OSError:
        pass
    parent = os.path.dirname(head)
    if not parent:
        return False
    for marker in ("waf", os.path.join("bin", "curl"), "wafctl.cmd",
                   os.path.join("bin", "waf-bash-env.sh")):
        try:
            if os.path.exists(os.path.join(parent, marker)):
                return True
        except OSError:
            continue
    slim = parent.lower().replace("_", "-")
    return "agent-waf" in slim or "agentwaf" in slim


def install_cmd_autorun():
    """把 AutoRun 写进 HKCU，免管理员。返回 (ok, message)。"""
    if not is_windows():
        return False, "仅 Windows 支持"
    winreg = _try_import_winreg()
    if winreg is None:
        return False, "winreg 不可用"

    existing = cmd_autorun_value()
    cleaned = _strip_our_autorun(existing)
    ours = _autorun_command()
    combined = ours + (" & " + cleaned if cleaned.strip() else "")

    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "AutoRun", 0, winreg.REG_SZ, combined)
    except OSError as exc:
        return False, "写入注册表失败：%s" % exc
    return True, "已写入 HKCU AutoRun（新开的 cmd 窗口生效）"


def uninstall_cmd_autorun():
    if not is_windows():
        return False, "仅 Windows 支持"
    winreg = _try_import_winreg()
    if winreg is None:
        return False, "winreg 不可用"
    existing = cmd_autorun_value()
    if MARKER not in existing:
        return True, "未安装，无需移除"
    cleaned = _strip_our_autorun(existing)
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, AUTORUN_KEY, 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as key:
            if cleaned.strip():
                winreg.SetValueEx(key, "AutoRun", 0, winreg.REG_SZ, cleaned)
            else:
                try:
                    winreg.DeleteValue(key, "AutoRun")
                except OSError:
                    pass
    except OSError as exc:
        return False, "写入注册表失败：%s" % exc
    return True, "已移除 HKCU AutoRun 中的 HuntGuard 配置"


def install_machine_path():
    """把 bin 写到机器级 PATH 最前（需管理员）。"""
    if not is_windows():
        return False, "仅 Windows 支持"
    if not is_admin():
        return False, "需要管理员权限（请以管理员身份运行终端）"
    winreg = _try_import_winreg()
    if winreg is None:
        return False, "winreg 不可用"

    current = read_registry_path("Machine")
    target = _normalize(bin_dir())
    parts = [p for p in path_entries(current) if _normalize(p) != target]
    new_value = os.pathsep.join([bin_dir()] + parts)

    try:
        with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_value)
    except OSError as exc:
        return False, "写入注册表失败：%s" % exc

    _broadcast_environment_change()
    return True, "已写入机器级 PATH 最前（对所有新进程生效）"


def cleanup_legacy_user_path():
    """从**用户级 PATH** 里移除指向本工具 bin 的条目。

    为什么必须清理：
      * 用户级 PATH 排在机器级之后，而真 curl 在 ``C:\\Windows\\System32``
        （机器级）—— 所以这条目**从来没生效过**，留着纯属误导
      * 它和 BASH_ENV 加的那条叠加，会让 Git Bash 的 PATH 出现重复
        （实测：同一目录出现两次）

    新架构改用按通道接入（AutoRun / BASH_ENV / PS profile / PYTHONPATH），
    不依赖用户级 PATH。旧版 ``install_shim.ps1`` 写过这个条目，升级时清掉。
    """
    if not is_windows():
        return True, "非 Windows，跳过"
    winreg = _try_import_winreg()
    if winreg is None:
        return False, "winreg 不可用"

    current = read_registry_path("User")
    target = _normalize(bin_dir())
    parts = path_entries(current)
    kept = []
    for part in parts:
        try:
            if _normalize(part) == target:
                continue
        except OSError:
            pass
        kept.append(part)

    if len(kept) == len(parts):
        return True, "用户级 PATH 无本工具条目"

    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, "Environment", 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ,
                              os.pathsep.join(kept))
    except OSError as exc:
        return False, "写入注册表失败：%s" % exc
    _broadcast_environment_change()
    return True, "已从用户级 PATH 移除冗余条目（共 %d 处）" % (
        len(parts) - len(kept))


def uninstall_machine_path():
    if not is_windows() or not is_admin():
        return False, "需要管理员权限"
    winreg = _try_import_winreg()
    if winreg is None:
        return False, "winreg 不可用"
    current = read_registry_path("Machine")
    target = _normalize(bin_dir())
    parts = [p for p in path_entries(current) if _normalize(p) != target]
    try:
        with winreg.CreateKeyEx(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                0, winreg.KEY_READ | winreg.KEY_WRITE) as key:
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ,
                              os.pathsep.join(parts))
    except OSError as exc:
        return False, "写入注册表失败：%s" % exc
    _broadcast_environment_change()
    return True, "已从机器级 PATH 移除"


def _broadcast_environment_change():
    """通知系统刷新环境变量，让新进程立刻拿到新 PATH。"""
    try:
        import ctypes
        HWND_BROADCAST = 0xFFFF
        WM_SETTINGCHANGE = 0x1A
        SMTO_ABORTIFHUNG = 0x0002
        result = ctypes.c_long()
        ctypes.windll.user32.SendMessageTimeoutW(
            HWND_BROADCAST, WM_SETTINGCHANGE, 0,
            ctypes.c_wchar_p("Environment"), SMTO_ABORTIFHUNG, 3000,
            ctypes.byref(result))
    except Exception:
        pass


# ---------------------------------------------------------------- HOME 指针
#
# 统一的主指针：一个用户级环境变量，指向安装目录。
# 其它机制（PowerShell profile 的一行、MCP 注册、burp 扩展）都用它定位，
# 于是外部不留任何硬编码路径 —— 换目录只要重跑一次安装。
#
# 两个名字都写：
#   HUNTGUARD_HOME  现在的正式名
#   AGENTWAF_HOME   1.0 时代的名 —— 已装好的机器注册表里是它，
#                   不写旧名的话，升级后老机器的 profile 会找不到目录。
# 读的时候优先新名。卸载时两个都清。

HOME_ENV = "HUNTGUARD_HOME"
HOME_ENV_LEGACY = "AGENTWAF_HOME"
HOME_ENVS = (HOME_ENV, HOME_ENV_LEGACY)


def home_dir_from_env():
    """从环境变量取安装目录（新名优先，旧名回退）。没有返回 None。"""
    for name in HOME_ENVS:
        value = os.environ.get(name)
        if value:
            return value
    return None


def install_home_env():
    """写 HUNTGUARD_HOME 与 AGENTWAF_HOME=<安装目录>。"""
    if not is_windows():
        return False, "仅 Windows 支持"
    winreg = _try_import_winreg()
    if winreg is None:
        return False, "winreg 不可用"
    changed = []
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, "Environment", 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as key:
            for name in HOME_ENVS:
                current = ""
                try:
                    current, _ = winreg.QueryValueEx(key, name)
                except OSError:
                    current = ""
                if _normalize(current) == _normalize(config.ROOT):
                    continue                      # 已是目标值，不重复写
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, config.ROOT)
                changed.append(name)
    except OSError as exc:
        return False, "写入 %s 失败：%s" % (HOME_ENV, exc)
    if not changed:
        return True, "%s 已是目标值" % HOME_ENV
    _broadcast_environment_change()
    return True, "%s 已写入：%s" % ("、".join(changed), config.ROOT)


def uninstall_home_env():
    if not is_windows():
        return True, "非 Windows，跳过"
    winreg = _try_import_winreg()
    if winreg is None:
        return False, "winreg 不可用"
    removed = []
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, "Environment", 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as key:
            for name in HOME_ENVS:
                try:
                    current, _ = winreg.QueryValueEx(key, name)
                except OSError:
                    continue
                # 指向别处的不动（可能是另一份安装，或用户自己设的）
                if _normalize(current) != _normalize(config.ROOT):
                    continue
                winreg.DeleteValue(key, name)
                removed.append(name)
    except OSError as exc:
        return False, "删除环境变量失败：%s" % exc
    if not removed:
        return True, "%s 未设置（或指向别处，未改动）" % HOME_ENV
    _broadcast_environment_change()
    return True, "%s 已移除" % "、".join(removed)


def has_home_env():
    """新名或旧名任一指向本安装目录即算已装。"""
    if not is_windows():
        return False
    winreg = _try_import_winreg()
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                            winreg.KEY_READ) as key:
            for name in HOME_ENVS:
                try:
                    value, _ = winreg.QueryValueEx(key, name)
                except OSError:
                    continue
                if _normalize(value) == _normalize(config.ROOT):
                    return True
            return False
    except (OSError, FileNotFoundError):
        return False


def _is_our_profile_line(line):
    """判断某行是不是 HuntGuard 自己写进 PowerShell profile 的。

    用于原地升级：先把历史版本写的行全部剔除，再写入唯一的新区块，
    避免重复安装后 profile 越来越长。

    注意：比较时两边都要去空格。``flat`` 去掉了空格，所以标记本身
    也必须先去空格，否则像 ``"one-line pointer"`` 这种自带空格的
    标记永远匹配不上（曾因此漏删历史区块，留下孤立的 ``}``，
    直接让整个 profile 解析失败）。
    """
    flat = line.replace(" ", "").replace("\t", "").lower()
    if not flat:
        return False

    markers = (
        "agent-waf", "agent_waf", "end-agent-waf",
        "remove-itemalias:curl", "remove-itemalias:wget",
        "invoke-webrequest",          # 旧版说明注释
        "拦截器目录", "内置的curl",
        "不删的话", "拦截器形同虚设",
        "agentwaf_home",              # 新版一行指针（旧变量名）
        "huntguard_home",             # 新版一行指针（现变量名）
        "one-linepointer",            # 新版说明注释（去空格后的形态）
        "logiclivesintheprojectfolder",
        "$wafhome",
    )
    for marker in markers:
        if marker.replace(" ", "").lower() in flat:
            return True

    # PATH 前置行：引用的是我们的 bin 目录
    bin_flat = bin_dir().replace(" ", "").lower()
    if "$env:path" in flat and bin_flat in flat:
        return True
    return False


def _strip_our_profile_blocks(text):
    """按**整块**删除我们写进 PowerShell profile 的内容。

    为什么不能逐行过滤：我们前后写过三种形态的区块，其中两版是
    ``if (...) { ... }`` 结构。逐行匹配会把 ``if`` 行删掉却留下
    孤立的 ``}`` —— PowerShell 解析到一半遇到多余的右括号，
    整个 profile 直接报错，用户环境就坏了（实际踩过这个坑）。

    所以按块删：遇到我们的标记行就开始跳过，直到
    * 出现结束标记 ``# end-agent-waf``，或
    * 大括号配对回到 0（兼容没有结束标记的旧版），或
    * 文件结束
    """
    lines = text.replace("\r\n", "\n").split("\n")
    out = []
    index = 0
    total = len(lines)

    while index < total:
        line = lines[index]
        if not _is_our_profile_line(line):
            out.append(line)
            index += 1
            continue

        # 命中标记：开始跳过一个完整区块
        depth = 0
        opened = False
        index += 1
        while index < total:
            current = lines[index]
            if not opened and PROFILE_END_MARK in current:
                index += 1
                break
            depth += current.count("{") - current.count("}")
            if "{" in current:
                opened = True
            index += 1
            if opened and depth <= 0:
                break
    return "\n".join(out)


def install_powershell_profile():
    """在 PowerShell profile 里装**一行指针**，逻辑放在安装目录内。

    profile 里只写：

        . "$env:HUNTGUARD_HOME\\bin\\waf.ps1"

    真正的处理（删 curl 别名 + 前置 PATH）都在 ``bin/waf.ps1`` 里。
    这样 profile 几乎不留痕迹，删掉项目目录就干净了。

    同时覆盖 Windows PowerShell 5.1 与 PowerShell 7 两个 profile。
    """
    if not is_windows():
        return False, "仅 Windows 支持"

    script = os.path.join(bin_dir(), "waf.ps1")
    if not os.path.isfile(script):
        return False, "缺少 %s" % script

    # 定位顺序：HUNTGUARD_HOME（新）→ AGENTWAF_HOME（旧）→ 绝对路径兜底。
    # 兜底那一层是必须的：环境变量要新开的终端才可见，已运行的会话读不到，
    # 只靠变量会让"装完立刻在原有窗口里试"的人以为没生效。
    block = (
        '%s\r\n'
        '# One-line pointer: logic lives in the project folder.\r\n'
        '$wafHome = if ($env:HUNTGUARD_HOME) { $env:HUNTGUARD_HOME }'
        ' elseif ($env:AGENTWAF_HOME) { $env:AGENTWAF_HOME } else { "%s" }\r\n'
        'if (Test-Path "$wafHome\\bin\\waf.ps1") { . "$wafHome\\bin\\waf.ps1" }\r\n'
        '%s\r\n'
        % (PROFILE_MARK, config.ROOT, PROFILE_END_MARK))

    targets = powershell_profile_paths()
    if not targets:
        return False, "找不到 PowerShell profile 路径"

    written, failed = [], []
    for path in targets:
        try:
            folder = os.path.dirname(path)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)

            existing = ""
            if os.path.isfile(path):
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    existing = fh.read()

            keep = _strip_our_profile_blocks(existing).split("\n")
            compact = []
            for line in keep:
                if not line.strip() and compact and not compact[-1].strip():
                    continue
                compact.append(line)
            cleaned = "\n".join(compact).strip()

            payload = (cleaned + "\n\n" if cleaned else "") + block
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(payload.replace("\n", "\r\n"))
            written.append(os.path.basename(os.path.dirname(path)) or path)
        except OSError as exc:
            failed.append("%s: %s" % (path, exc))

    if not written:
        return False, "写入失败：" + "；".join(failed)
    msg = "已写入 PowerShell profile（%s，仅一行指针）" % "、".join(written)
    if failed:
        msg += "；部分失败：" + "；".join(failed)
    return True, msg


# ---------------------------------------------------------------- Git Bash / MSYS

def bash_env_script():
    """返回 BASH_ENV 指向的脚本路径（bin/waf-bash-env.sh）。"""
    return os.path.join(bin_dir(), "waf-bash-env.sh")


def user_bashrc_path():
    """Git Bash 用户级 ~/.bashrc 的真实路径。

    Git Bash 的 $HOME 通常是 ``C:\\Users\\<user>``，所以 .bashrc
    就在那里。跟 PowerShell profile 不冲突。
    """
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    return os.path.join(home, ".bashrc")


def write_bashrc_pointer():
    """把 ~/.bashrc 里的拦截器行更新为目标值（替换，不是追加）。

    单独拆出来是为了**可测试**：调用它只碰一个文件，不碰注册表。
    install_bash_env 会写注册表，测试里不该调用它 —— 那会把开发机
    真实的 BASH_ENV 指到临时目录（实测污染过一次）。

    为什么必须替换：同一个套件解压两份、或把文件夹挪个位置后重装，
    旧的那行还在 .bashrc 里；Git Bash 按顺序取第一个命中的 curl，
    于是走的是旧副本 —— 新装的这份完全不生效。
    """
    bashrc = user_bashrc_path()
    line = 'export PATH="%s:$PATH"  %s' % (_to_posix(bin_dir()), BASHRC_MARK)
    try:
        existing = ""
        if os.path.isfile(bashrc):
            with open(bashrc, "r", encoding="utf-8", errors="replace") as fh:
                existing = fh.read()
        kept = [ln for ln in existing.splitlines() if BASHRC_MARK not in ln]
        kept_text = "\n".join(kept)
        if kept_text and not kept_text.endswith("\n"):
            kept_text += "\n"
        new_text = kept_text + ("\n" if kept_text else "") + line + "\n"
        if new_text == existing:
            return True, "~/.bashrc 已配置"
        with open(bashrc, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(new_text)
        return True, ("~/.bashrc 已更新" if BASHRC_MARK in existing
                      else "~/.bashrc 已写入")
    except OSError as exc:
        return False, "~/.bashrc 写入失败：%s" % exc


def install_bash_env():
    """让 Git Bash（含非交互式）里的 curl 走拦截器。

    为什么必须用 BASH_ENV：
      * Git Bash 的 PATH 把 ``/mingw64/bin`` 排在最前，且**不受 Windows
        机器级/用户级 PATH 顺序影响** —— 所以调 PATH 优先级对 Git Bash 无效。
      * ``~/.bashrc`` 只对交互式 shell 生效；AI 工具（ZCode / Claude Code /
        Codex）执行命令用的是 ``bash -c "..."``（非交互），不读 .bashrc。
      * ``BASH_ENV`` 正是"非交互 bash 启动时读取的文件"，实测有效。

    因此两处都写：BASH_ENV 覆盖非交互，.bashrc 覆盖交互（双保险）。
    """
    if not is_windows():
        return False, "仅 Windows 支持；Linux 请用 source scripts/install_shim.sh"

    script = bash_env_script()
    if not os.path.isfile(script):
        return False, "缺少 %s" % script

    messages = []

    # 1) BASH_ENV —— 覆盖非交互 bash（AI 工具的主战场）
    if is_windows():
        winreg = _try_import_winreg()
        if winreg is None:
            return False, "winreg 不可用"
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, "Environment", 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE) as key:
                current = ""
                try:
                    current, _ = winreg.QueryValueEx(key, "BASH_ENV")
                except OSError:
                    current = ""
                if _normalize(current) == _normalize(script):
                    messages.append("BASH_ENV 已是目标值")
                else:
                    winreg.SetValueEx(key, "BASH_ENV", 0, winreg.REG_SZ, script)
                    messages.append("BASH_ENV 已写入用户环境变量")
        except OSError as exc:
            return False, "写 BASH_ENV 失败：%s" % exc
        _broadcast_environment_change()

    # 2) ~/.bashrc —— 覆盖交互式 Git Bash（用户自己开终端手敲时）
    ok, msg = write_bashrc_pointer()
    messages.append(msg)

    return True, "；".join(messages)


def _to_posix(win_path):
    """D:\\agent-waf\\bin -> /d/agent-waf/bin"""
    text = win_path.replace("\\", "/")
    if len(text) > 1 and text[1] == ":":
        text = "/" + text[0].lower() + text[2:]
    return text


def uninstall_bash_env():
    if not is_windows():
        return False, "仅 Windows 支持"
    winreg = _try_import_winreg()
    messages = []
    if winreg is not None:
        try:
            with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, "Environment", 0,
                                    winreg.KEY_READ | winreg.KEY_WRITE) as key:
                try:
                    current, _ = winreg.QueryValueEx(key, "BASH_ENV")
                except OSError:
                    current = ""
                if "agent-waf" in (current or "").lower():
                    winreg.DeleteValue(key, "BASH_ENV")
                    messages.append("BASH_ENV 已移除")
                else:
                    messages.append("BASH_ENV 未设置为本工具")
        except OSError as exc:
            messages.append("BASH_ENV 处理失败：%s" % exc)
        _broadcast_environment_change()

    bashrc = user_bashrc_path()
    if os.path.isfile(bashrc):
        try:
            with open(bashrc, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
            keep = [l for l in lines if BASHRC_MARK not in l]
            if len(keep) != len(lines):
                with open(bashrc, "w", encoding="utf-8") as fh:
                    fh.write("\n".join(keep) + "\n")
                messages.append("~/.bashrc 已清理")
        except OSError as exc:
            messages.append("~/.bashrc 处理失败：%s" % exc)
    return True, "；".join(messages) if messages else "未安装"


def has_bash_env():
    if not is_windows():
        return False
    winreg = _try_import_winreg()
    if winreg is None:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                            winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, "BASH_ENV")
            return "agent-waf" in (value or "").lower()
    except (OSError, FileNotFoundError):
        return False


def resolve_curl_in_bash():
    """真实起一个 bash，看它把 curl 解析到哪 —— Git Bash 覆盖的唯一可靠验证。

    注意：当前进程的环境可能是旧的（BASH_ENV 刚写进注册表，还没刷新到
    本进程）。所以这里**主动从注册表读 BASH_ENV 并注入**，模拟一个
    新开的进程会看到的环境 —— 否则探测结果会误报"仍是原生 curl"。
    """
    if not is_windows():
        return None

    env = dict(os.environ)
    winreg = _try_import_winreg()
    if winreg is not None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                                winreg.KEY_READ) as key:
                value, _ = winreg.QueryValueEx(key, "BASH_ENV")
                if value:
                    env["BASH_ENV"] = value
        except (OSError, FileNotFoundError):
            pass
    # .bashrc 兜底也要能看到，所以用 login shell
    env.setdefault("HOME", os.environ.get("USERPROFILE", ""))

    # bash 位置：优先用自动探测缓存（autodetect 会扫注册表 + 常见位置），
    # 再退回常见安装路径，最后交给 PATH。
    #
    # 早先硬编码了一个具体的 Git 安装路径（本机特有的路径）——
    # 虽然只是候选列表的一项、不影响别人（有 Program Files 兜底 + PATH），
    # 但那是不该出现在发布版里的痕迹，不该出现在发布版里。
    candidates = []
    try:
        from . import autodetect
        cached = autodetect.cached_bash() if hasattr(autodetect, "cached_bash") \
            else ""
        if cached and os.path.isfile(cached):
            candidates.append(cached)
    except Exception:
        pass
    import shutil as _shutil
    for name in ("bash", "bash.exe"):
        found = _shutil.which(name)
        if found:
            candidates.append(found)
            break
    candidates.extend([
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files (x86)\Git\bin\bash.exe",
        os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                     "Git", "bin", "bash.exe"),
        os.path.join(os.environ.get("LOCALAPPDATA", ""),
                     "Programs", "Git", "bin", "bash.exe"),
    ])
    found = []
    for c in candidates:
        if c and os.path.isfile(c) and c not in found:
            found.append(c)
    if not found:
        found = ["bash"]
    for bash in found:
        try:
            result = subprocess.run([bash, "-lc", "which curl"],
                                    capture_output=True, timeout=25, env=env)
            text = result.stdout.decode("utf-8", "replace").strip()
            if text:
                return text.splitlines()
        except Exception:
            continue
    return None


def uninstall_powershell_profile():
    if not is_windows():
        return True, "非 Windows，跳过"
    removed, failed = [], []
    for path in powershell_profile_paths():
        if not os.path.isfile(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                original = fh.read()
            cleaned_text = _strip_our_profile_blocks(original)
            if cleaned_text == original.replace("\r\n", "\n"):
                continue
            keep = cleaned_text.split("\n")
            compact = []
            for line in keep:
                if not line.strip() and compact and not compact[-1].strip():
                    continue
                compact.append(line)
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write("\r\n".join(compact).strip() + "\r\n")
            removed.append(os.path.basename(os.path.dirname(path)))
        except OSError as exc:
            failed.append("%s: %s" % (path, exc))
    if failed:
        return False, "部分失败：" + "；".join(failed)
    if not removed:
        return True, "PowerShell profile 未安装接入"
    return True, "已从 PowerShell profile 移除（%s）" % "、".join(removed)


# ---------------------------------------------------------------- Python 钩子
#
# 设计原则：**所有文件都留在安装目录内**。
#
# 早期版本把 .pth + 引导器写进系统的 site-packages —— 那是安装目录
# 之外的文件，删掉项目后会在系统里留残留。现在改成：
#
#     PYTHONPATH=<root>\hooks        （注册表里的环境变量，不落文件）
#         ↓
#     <root>\hooks\sitecustomize.py  （项目目录内的真实文件）
#
# Python 启动时自动 import `sitecustomize`，效果与 .pth 相同。
#
# PowerShell 同理：profile 里只留一行指针指向 <root>\bin\waf.ps1。

PYHOOK_ENV = "PYTHONPATH"
HOOKS_DIRNAME = "hooks"

# 旧版本遗留在系统 site-packages 的文件名（安装时顺手清理）
LEGACY_HOOK_FILES = ("agent_waf_hook.pth", "agent_waf_boot.py")


def python_user_site():
    """旧版遗留文件所在的用户级 site-packages（仅用于清理）。"""
    try:
        import site
        paths = [site.getusersitepackages()]
    except Exception:
        paths = []
    home = os.environ.get("USERPROFILE") or os.path.expanduser("~")
    paths.append(os.path.join(home, "AppData", "Roaming", "Python",
                              "Python%d%d" % (sys.version_info[0],
                                             sys.version_info[1]),
                              "site-packages"))
    for path in paths:
        if path:
            return path
    return None


def hooks_dir():
    """项目内的 hooks 目录（sitecustomize.py 所在处）。"""
    return os.path.join(config.ROOT, HOOKS_DIRNAME)


def hooks_script():
    return os.path.join(hooks_dir(), "sitecustomize.py")


def read_user_pythonpath():
    """读用户级 PYTHONPATH（注册表）。"""
    if not is_windows():
        return os.environ.get("PYTHONPATH", "")
    winreg = _try_import_winreg()
    if winreg is None:
        return ""
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment", 0,
                            winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, PYHOOK_ENV)
            return value or ""
    except (OSError, FileNotFoundError):
        return ""


def _strip_our_pythonpath(value):
    """从 PYTHONPATH 里移除**所有** agent-waf 的 hooks 目录。

    和 AutoRun 同理：只删"当前安装目录"那一份是不够的。解压两份、
    或把文件夹挪个位置，旧副本的 hooks 会留在 PYTHONPATH 里；因为
    它排在前面，Python 启动时加载的是**旧副本**的钩子 —— 你在新副本里
    改了规则/开关，实际生效的却是旧副本的状态。

    判据：路径以 ``hooks`` 结尾，且同级目录里确实躺着我们的
    ``sitecustomize.py``（或同级存在 waf/ 包）。这样不会误删用户
    自己恰好也叫 hooks 的目录。
    """
    keep = []
    for part in (value or "").split(os.pathsep):
        if not part.strip():
            continue
        try:
            if _looks_like_our_hooks(part):
                continue
        except OSError:
            pass
        keep.append(part)
    return os.pathsep.join(keep)


def _looks_like_our_hooks(path):
    """判断这个目录是不是某个 agent-waf 副本的 hooks/。"""
    try:
        if _normalize(path) == _normalize(hooks_dir()):
            return True
    except OSError:
        pass
    try:
        if os.path.basename(os.path.normpath(path)) != HOOKS_DIRNAME:
            return False
        # hooks/sitecustomize.py 是我们的招牌文件
        if os.path.isfile(os.path.join(path, "sitecustomize.py")):
            return True
        # 目录被删了但同级还有 waf/ 包：也算残留，清掉
        sibling = os.path.join(os.path.dirname(os.path.normpath(path)), "waf")
        return os.path.isdir(sibling)
    except OSError:
        return False


def _write_user_pythonpath(value):
    winreg = _try_import_winreg()
    if winreg is None:
        return False, "winreg 不可用"
    try:
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, "Environment", 0,
                                winreg.KEY_READ | winreg.KEY_WRITE) as key:
            if value:
                winreg.SetValueEx(key, PYHOOK_ENV, 0, winreg.REG_SZ, value)
            else:
                try:
                    winreg.DeleteValue(key, PYHOOK_ENV)
                except OSError:
                    pass
    except OSError as exc:
        return False, "写入 PYTHONPATH 失败：%s" % exc
    _broadcast_environment_change()
    return True, ""


def _cleanup_legacy_hook_files():
    """删掉旧版本写在系统 site-packages 里的文件。

    不清理的话，用户删掉本项目目录后系统里还会留两个孤儿文件，
    而且它们会指向一个不存在的路径（静默失效，更难排查）。
    """
    site_dir = python_user_site()
    if not site_dir:
        return []
    removed = []
    for name in LEGACY_HOOK_FILES:
        path = os.path.join(site_dir, name)
        if not os.path.isfile(path):
            continue
        try:
            os.remove(path)
            removed.append(name)
        except OSError:
            pass
    return removed


def install_python_hook():
    """装 Python 钩子：把 <root>\\hooks 加进 PYTHONPATH。

    所有文件都在安装目录内 —— 外部只有一个环境变量作指针。
    """
    script = hooks_script()
    if not os.path.isfile(script):
        return False, "缺少 %s" % script

    if not is_windows():
        return True, "非 Windows：请自行把 %s 加入 PYTHONPATH" % hooks_dir()

    current = read_user_pythonpath()
    cleaned = _strip_our_pythonpath(current)
    # 放最前面：确保我们的 sitecustomize 先被找到
    merged = os.pathsep.join([hooks_dir()] + ([cleaned] if cleaned else []))

    if current == merged:
        _cleanup_legacy_hook_files()
        return True, "Python 钩子已就绪（%s）" % hooks_dir()

    ok, err = _write_user_pythonpath(merged)
    if not ok:
        return False, err
    removed = _cleanup_legacy_hook_files()
    msg = "Python 钩子已装：%s → PYTHONPATH" % hooks_dir()
    if removed:
        msg += "（已清理旧版遗留：%s）" % "、".join(removed)
    return True, msg


def uninstall_python_hook():
    removed = _cleanup_legacy_hook_files()
    if not is_windows():
        return True, "非 Windows：请自行从 PYTHONPATH 移除 %s" % hooks_dir()
    current = read_user_pythonpath()
    cleaned = _strip_our_pythonpath(current)
    if cleaned != current:
        ok, err = _write_user_pythonpath(cleaned)
        if not ok:
            return False, err
        msg = "已从 PYTHONPATH 移除 %s" % hooks_dir()
    else:
        msg = "PYTHONPATH 未包含本工具"
    if removed:
        msg += "；已清理旧版遗留：%s" % "、".join(removed)
    return True, msg


def has_python_hook():
    """钩子是否已生效（看环境变量里有没有我们的目录）。"""
    if not is_windows():
        return False
    current = read_user_pythonpath()
    target = _normalize(hooks_dir())
    for part in (current or "").split(os.pathsep):
        if not part.strip():
            continue
        try:
            if _normalize(part) == target:
                return True
        except OSError:
            continue
    return False


def python_hook_effective():
    """真实起一个 python 进程，确认 sitecustomize 被加载。"""
    try:
        env = dict(os.environ)
        # 当前进程环境可能是旧的，主动注入注册表里的值来模拟新进程
        merged = _strip_our_pythonpath(env.get("PYTHONPATH", ""))
        env["PYTHONPATH"] = os.pathsep.join(
            [hooks_dir()] + ([merged] if merged else []))
        proc = subprocess.run(
            [sys.executable, "-c",
             "import sys; print('sitecustomize' in sys.modules)"],
            capture_output=True, timeout=25, env=env)
        text = proc.stdout.decode("utf-8", "replace").strip().lower()
        return text.endswith("true")
    except Exception:
        return False


# ---------------------------------------------------------------- 统一入口

def install(machine=False, cmd=True, powershell=True, bash=True, python=True):
    """安装接入。machine=True 时优先机器级 PATH。返回结果 dict。

    所有逻辑文件都留在安装目录内，外部只写**指针**：
      * HUNTGUARD_HOME 环境变量（统一主指针，另写旧名 AGENTWAF_HOME 兼容）
      * cmd AutoRun（一个注册表值）
      * BASH_ENV（一个注册表值）
      * PowerShell profile 里的一行
      * PYTHONPATH（一个注册表值）
    """
    results = {}

    # 主指针先写：其它机制都用它定位
    results["home_env"] = install_home_env()

    # 清掉旧版写在用户级 PATH 里的冗余条目
    # （那条目排机器级之后，从来没生效过，还会和 BASH_ENV 叠加成重复）
    ok, msg = cleanup_legacy_user_path()
    if "无本工具条目" not in msg:
        results["legacy_path_cleanup"] = (ok, msg)

    if machine:
        ok, msg = install_machine_path()
        results["machine_path"] = (ok, msg)
        if ok:
            # 机器级 PATH 对所有进程生效，其余机制就不必再装了
            uninstall_cmd_autorun()
            results["cmd_autorun"] = (True, "已由机器级 PATH 覆盖，跳过")
            uninstall_powershell_profile()
            results["powershell"] = (True, "已由机器级 PATH 覆盖，跳过")
            uninstall_bash_env()
            results["bash_env"] = (True, "已由机器级 PATH 覆盖，跳过")
            if python:
                results["python_hook"] = install_python_hook()
            return results

    if cmd:
        results["cmd_autorun"] = install_cmd_autorun()
    if bash:
        results["bash_env"] = install_bash_env()
    if powershell:
        results["powershell"] = install_powershell_profile()
    if python:
        results["python_hook"] = install_python_hook()
    return results


def uninstall():
    results = {}
    results["machine_path"] = uninstall_machine_path()
    results["cmd_autorun"] = uninstall_cmd_autorun()
    results["bash_env"] = uninstall_bash_env()
    results["powershell"] = uninstall_powershell_profile()
    results["python_hook"] = uninstall_python_hook()
    results["home_env"] = uninstall_home_env()
    return results


CLEAN_CHECK_NAMES = (
    "cmd_autorun", "powershell_profile", "bash_env", "python_hook",
    "home_env", "user_path", "machine_path",
)


def verify_clean():
    """卸载之后复核：机器上还有没有指向本工具的接入。

    为什么不能只看 ``uninstall()`` 的返回值（实测踩过）：
    那些返回值说的是"我这次清理动作的结果"——失败原因可能是
    权限不足、注册表不可用、根本没装过（"跳过"），三种情况在
    用户眼里都是"没看到 OK"。而用户真正要知道的是**最终状态**：
    这些东西还在不在。所以卸载完必须重新查一遍。

    返回 ``[(名称, 是否干净, 说明)]``，名称见 CLEAN_CHECK_NAMES。
    """
    checks = []

    def add(name, dirty, detail=""):
        checks.append((name, not dirty,
                       detail or ("仍有残留" if dirty else "无残留")))

    def guard(name, func, dirty_when):
        try:
            add(name, dirty_when(func()))
        except Exception as exc:                      # noqa: BLE001
            add(name, True, "无法判定：%s" % exc)

    guard("cmd_autorun", has_cmd_autorun, bool)
    guard("powershell_profile", has_powershell_profile, bool)
    guard("bash_env", has_bash_env, bool)
    guard("python_hook", has_python_hook, bool)
    guard("home_env", has_home_env, bool)

    # 用户级 / 机器级 PATH 里是否还留着指向本工具 bin 的条目。
    # 只读检查，不写注册表 —— 非管理员也能跑（机器级只能看不能改）。
    target = _normalize(bin_dir())
    for scope, name in (("User", "user_path"), ("Machine", "machine_path")):
        if not is_windows():
            add(name, False, "非 Windows，不适用")
            continue
        try:
            entries = path_entries(read_registry_path(scope))
        except Exception as exc:                      # noqa: BLE001
            add(name, True, "无法读取 %s PATH：%s" % (scope, exc))
            continue
        residue = []
        for part in entries:
            try:
                if _normalize(part) == target:
                    residue.append(part)
            except OSError:
                continue
        add(name, bool(residue),
            ("仍有条目：%s" % residue[0]) if residue else "无残留")
    return checks


def purge_data_dir(path=None, require_inside_root=True):
    """删掉 data/ 里的运行数据（拦截记录、规则、证书、设置）。

    **不可逆**：events.db 里是完整拦截记录，certs/ 下有 CA 私钥，
    rules.json 可能是用户自己改过的规则。所以：
      * 只在用户明确要求时调用（`wafctl uninstall-path --purge-data`，
        或双击 uninstall.bat 时回答 y）
      * 默认要求目标在**安装目录内**（防呆：别让一个被改过的配置
        或手滑的参数把别处的目录删了）
      * 删完把 data/ 本身也一并移除；下次启动会自动重建默认规则

    返回 ``(ok, msg, 删除文件数)``。
    """
    data_dir = os.path.abspath(path or config.DATA_DIR)

    # 盘根/文件系统根一律拒绝 —— 这一条与 require_inside_root **无关**，
    # 必须是最后一道闸：一个手滑的参数（--purge-data 指到 D:\）就会
    # 把整个盘删了，而"删除"正是这个工具存在的意义，自己不能犯这种错。
    drive, tail = os.path.splitdrive(data_dir)
    if tail in ("", os.sep, "/"):
        return False, "拒绝删除：%s 是盘根/文件系统根" % data_dir, 0

    root = os.path.abspath(config.ROOT)
    if require_inside_root:
        try:
            inside = os.path.commonpath([data_dir, root]) == root
        except ValueError:                            # 不同盘符
            inside = False
        if not inside or data_dir == root:
            return False, ("拒绝删除：%s 不在安装目录内（%s）"
                           % (data_dir, root)), 0

    if not os.path.isdir(data_dir):
        return True, "data 目录不存在，无需清理", 0

    removed = 0
    errors = []
    for folder, dirs, files in os.walk(data_dir):
        for name in files:
            full = os.path.join(folder, name)
            try:
                os.remove(full)
                removed += 1
            except OSError as exc:
                errors.append("%s（%s）" % (full, exc))
    for folder, dirs, files in os.walk(data_dir, topdown=False):
        for name in dirs:
            full = os.path.join(folder, name)
            try:
                os.rmdir(full)
            except OSError as exc:
                errors.append("%s（%s）" % (full, exc))
    try:
        os.rmdir(data_dir)
    except OSError as exc:
        errors.append("%s（%s）" % (data_dir, exc))

    if errors:
        return False, ("删了 %d 个文件，但有 %d 项失败（多半是控制台还开着、"
                       "文件被占用）：%s"
                       % (removed, len(errors), "；".join(errors[:3]))), removed
    return True, "已删除 data 目录（%d 个文件）" % removed, removed


def status(path_probe=False):
    """诊断报告：告诉用户 curl 到底会解析到哪个文件。

    ``path_probe=True`` 会真的起一个 cmd.exe 跑 ``where curl``（约 100ms），
    这是**唯一准确**的判定 —— 因为 cmd AutoRun 是在 cmd 启动时修改 PATH 的，
    不在注册表里，纯模拟会得出错误结论。
    """
    entry = {
        "is_windows": is_windows(),
        "is_admin": is_admin(),
        "bin_dir": bin_dir(),
        "machine_path_ok": in_registry_path("Machine") if is_windows() else False,
        "user_path_ok": in_registry_path("User") if is_windows() else False,
        "cmd_autorun": has_cmd_autorun() if is_windows() else False,
        "cmd_autorun_value": cmd_autorun_value() if is_windows() else "",
        "bash_env": has_bash_env() if is_windows() else False,
        "python_hook": has_python_hook(),
        "python_hook_file": hooks_script(),
        "python_hook_dir": hooks_dir(),
        "home_env": has_home_env() if is_windows() else False,
        "powershell_profile": has_powershell_profile() if is_windows() else False,
        "resolved": [],
        "source": "registry",
    }

    resolved = None
    if path_probe and is_windows():
        resolved = effective_for_new_cmd()
        if resolved:
            entry["source"] = "live_cmd"

    if not resolved:
        resolved = resolve_curl()
        entry["source"] = "registry"

    entry["resolved"] = resolved
    entry["shim_wins"] = bool(resolved) and \
        _same_dir(os.path.dirname(resolved[0]), bin_dir())

    # Git Bash 是独立解析路径，单独探测（ZCode / Claude Code / Codex
    # 在 Windows 上执行命令基本都走它）
    if path_probe and is_windows():
        bash_resolved = resolve_curl_in_bash()
        entry["resolved_bash"] = bash_resolved
        entry["shim_wins_bash"] = bool(bash_resolved) and \
            _same_dir(os.path.dirname(bash_resolved[0]), bin_dir())
        entry["python_hook_effective"] = python_hook_effective() \
            if entry["python_hook"] else False
    else:
        entry["resolved_bash"] = None
        entry["shim_wins_bash"] = False
        entry["python_hook_effective"] = False

    return entry


def effective_for_new_cmd():
    """真实起一个 cmd.exe，看它把 curl 解析到哪 —— 最可靠的验证。"""
    if not is_windows():
        return None
    try:
        result = subprocess.run(["cmd", "/c", "where curl"],
                                capture_output=True, timeout=25)
        text = result.stdout.decode("utf-8", "replace")
        lines = [l.strip() for l in text.splitlines() if l.strip()]
        return lines
    except Exception:
        return None
