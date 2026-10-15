# -*- coding: utf-8 -*-
"""环境自动探测：把关键工具的真实路径找出来并缓存。

为什么需要
----------
别人下载这个工具后，环境跟作者的不一样：

* curl 可能在 System32、在 Git 的 mingw64、在某个面板软件目录……
* Python 可能装在不同盘、不同版本目录
* Git Bash 可能装在 E:\\Git 或 C:\\Program Files\\Git

如果让用户自己填这些路径，大部分人填不对。所以这里**全部自动探测**，
结果写到 ``data/detected.json``，shim 直接读缓存 —— 又快又准。

探测失败不影响使用：shim 里保留了动态搜索作为兜底。
"""

import json
import os
import shutil
import subprocess
import sys
import time

from . import config

CACHE_NAME = "detected.json"


def cache_path():
    return os.path.join(config.DATA_DIR, CACHE_NAME)


# ---------------------------------------------------------------- 单项探测

def detect_python():
    """Python 解释器路径。当前进程本身就是最好的答案。"""
    candidates = [sys.executable]
    for name in ("python", "python3", "py"):
        found = shutil.which(name)
        if found:
            candidates.append(found)
    for candidate in candidates:
        if candidate and os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return ""


def _looks_like_shim(path):
    """判断一个候选 curl 是不是"我们自己的 shim"而不是真 curl。

    为什么不能只看目录：机器上可能装了多份 HuntGuard（作者一份、别人
    拷了自己一份），或旧安装的 shim 目录还留在 PATH 里。只看"当前
    安装目录"会漏掉其他安装的 shim，探测结果就变成 shim 自己 ——
    转发时形成递归，或干脆拦不住。

    判据：真 curl 是二进制（Windows PE 以 MZ 开头，Linux ELF 以
    \\x7fELF 开头，macOS Mach-O 以 feedface 等开头）；我们的 shim
    是脚本，内容必然带特征词。
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096)
    except OSError:
        return True                     # 读不了就别用，宁可跳过

    # 二进制可执行文件 → 是真 curl
    if head[:2] == b"MZ" or head[:4] == b"\x7fELF":
        return False
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
                    b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return False                    # Mach-O

    # 文本脚本：看内容特征
    lowered = head.lower()
    markers = (b"agent-waf", b"agent_waf", b"curlshim", b"agentwaf")
    return any(m in lowered for m in markers)


def _is_usable_curl(path):
    """路径存在、且不是我们自己的 shim。"""
    return bool(path) and os.path.isfile(path) and not _looks_like_shim(path)


def detect_curl():
    """真实 curl 的路径（跳过所有 HuntGuard shim，含其他安装的）。

    搜索顺序：
      1. PATH 里第一个可用的真 curl
      2. 系统常见位置
    """
    for folder in (os.environ.get("PATH") or "").split(os.pathsep):
        if not folder:
            continue
        for name in ("curl.exe", "curl"):
            candidate = os.path.join(folder, name)
            if os.path.isfile(candidate) and not _looks_like_shim(candidate):
                return os.path.abspath(candidate)

    preferred = [
        r"C:\Windows\System32\curl.exe",
        r"C:\Program Files\Git\mingw64\bin\curl.exe",
        r"C:\Program Files\Git\usr\bin\curl.exe",
        r"C:\Program Files (x86)\Git\mingw64\bin\curl.exe",
        "/usr/bin/curl",
        "/bin/curl",
        "/usr/local/bin/curl",
    ]
    for candidate in preferred:
        if _is_usable_curl(candidate):
            return candidate
    return ""


def detect_git_bash():
    """Git Bash 的 bash.exe 路径。

    优先 ``<Git>\\bin\\bash.exe`` —— 那是 Git for Windows 的启动器，
    行为与用户手点 "Git Bash" 一致。``<Git>\\usr\\bin\\bash.exe`` 是
    MSYS2 内部的那个，直接用它有时拿不到正确的 Windows PATH 转换。
    """
    preferred = []
    # 常见 Git 安装根目录 → 优先它们的 bin\bash.exe
    for root in (r"C:\Program Files\Git", r"C:\Program Files (x86)\Git",
                 r"D:\Git", r"E:\Git", r"D:\Program Files\Git"):
        preferred.append(os.path.join(root, "bin", "bash.exe"))
    preferred.extend([
        "/bin/bash",
        "/usr/bin/bash",
    ])

    for candidate in preferred:
        if os.path.isfile(candidate):
            lowered = candidate.lower()
            # 排除 WSL 的 bash（读不到 Windows 的 PATH 配置）
            if "system32" in lowered:
                continue
            return os.path.abspath(candidate)

    # PATH 里找（如果上面都没命中）
    for name in ("bash", "bash.exe"):
        found = shutil.which(name)
        if found and "system32" not in found.lower():
            return os.path.abspath(found)
    return ""


def detect_git_root():
    """Git 安装根目录（从 bash.exe 反推）。"""
    bash = detect_git_bash()
    if not bash:
        return ""
    # <Git>\bin\bash.exe -> <Git>
    parent = os.path.dirname(os.path.dirname(bash))
    if os.path.isdir(os.path.join(parent, "cmd")) or \
            os.path.isfile(os.path.join(parent, "git-bash.exe")):
        return parent
    if os.path.isdir(parent):
        return parent
    return ""


def detect_powershell():
    """优先 PowerShell 7，其次 Windows PowerShell 5.1。"""
    found = shutil.which("pwsh")
    if found:
        return os.path.abspath(found)
    preferred = [
        r"C:\Program Files\PowerShell\7\pwsh.exe",
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    ]
    for candidate in preferred:
        if os.path.isfile(candidate):
            return candidate
    return ""


def detect_cmd():
    """cmd.exe 路径（基本总是存在）。"""
    comspec = os.environ.get("ComSpec")
    if comspec and os.path.isfile(comspec):
        return comspec
    candidate = r"C:\Windows\System32\cmd.exe"
    return candidate if os.path.isfile(candidate) else ""


def detect_python_launcher():
    """py 启动器（Windows）。"""
    found = shutil.which("py")
    return os.path.abspath(found) if found else ""


# ---------------------------------------------------------------- 汇总

def detect_all():
    """探测全部关键路径，返回 dict。"""
    return {
        "detected_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "root": config.ROOT,
        "platform": sys.platform,
        "python": detect_python(),
        "python_launcher": detect_python_launcher(),
        "curl": detect_curl(),
        "bash": detect_git_bash(),
        "git_root": detect_git_root(),
        "powershell": detect_powershell(),
        "cmd": detect_cmd(),
    }


def write_cache(data=None):
    """把探测结果写到 data/detected.json。"""
    if data is None:
        data = detect_all()
    config.ensure_dirs()
    path = cache_path()
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
    # 同时写出 shim 能直接读的简单格式（batch / bash 不便解析 JSON）
    _write_env_files(data)
    return data


def _write_env_files(data):
    """生成 data/env.cmd 与 data/env.sh。

    为什么要这两个文件：shim 是 batch 脚本和 bash 脚本，让它们解析 JSON
    又慢又容易出错。直接写成 ``set VAR=value`` / ``VAR=value`` 最省事，
    shim 一行 source 就能拿到全部探测结果。

    这也正是"自动判定路径然后写入"的落地点 —— 用户不需要填任何东西。
    """
    config.ensure_dirs()

    python_exe = data.get("python") or ""
    curl_exe = data.get("curl") or ""
    bash_exe = data.get("bash") or ""
    root = data.get("root") or config.ROOT

    # --- Windows batch ---
    # 纯 ASCII：cmd.exe 按系统代码页解析 .cmd，中文会破坏命令解析。
    # 这个文件会被 shim 用 call 引入，一旦解析失败整个 shim 就废了。
    cmd_path = os.path.join(config.DATA_DIR, "env.cmd")
    lines = [
        "@echo off",
        "rem HuntGuard auto-detected paths (generated, do not edit by hand)",
        "set \"WAF_ROOT=%s\"" % root,
    ]
    if python_exe:
        lines.append("set \"WAF_PYTHON=%s\"" % python_exe)
    if curl_exe:
        lines.append("set \"WAF_CURL=%s\"" % curl_exe)
    if bash_exe:
        lines.append("set \"WAF_BASH=%s\"" % bash_exe)
    _atomic_write(cmd_path, "\r\n".join(lines) + "\r\n")

    # --- bash / Git Bash（可以带中文注释，bash 无所谓）---
    sh_path = os.path.join(config.DATA_DIR, "env.sh")
    sh_lines = [
        "# HuntGuard 自动探测结果（由 waf/autodetect.py 生成，请勿手工编辑）",
        'WAF_ROOT="%s"' % _to_posix(root),
    ]
    if python_exe:
        sh_lines.append('WAF_PYTHON="%s"' % _to_posix(python_exe))
    if curl_exe:
        sh_lines.append('WAF_CURL="%s"' % _to_posix(curl_exe))
    if bash_exe:
        sh_lines.append('WAF_BASH="%s"' % _to_posix(bash_exe))
    sh_lines.append("export WAF_ROOT WAF_PYTHON WAF_CURL WAF_BASH")
    _atomic_write(sh_path, "\n".join(sh_lines) + "\n")


def _atomic_write(path, text):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        fh.write(text)
    os.replace(tmp, path)


def _to_posix(win_path):
    """D:\\agent-waf\\bin -> /d/agent-waf/bin（Git Bash 认这个形式）。"""
    if not win_path:
        return ""
    text = str(win_path).replace("\\", "/")
    if len(text) > 1 and text[1] == ":":
        text = "/" + text[0].lower() + text[2:]
    return text


def read_cache():
    """读缓存；不存在或损坏返回 {}。"""
    path = cache_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (ValueError, OSError):
        return {}


def cached_curl():
    """从缓存拿 curl 路径；缓存失效（文件被删/移动）返回空串。

    这是 shim 的热路径 —— 必须快，所以只读一次缓存 + 一次 isfile。
    """
    value = read_cache().get("curl") or ""
    if value and os.path.isfile(value):
        return value
    return ""


def refresh_if_missing():
    """缓存不存在时自动探测一次。返回是否写了缓存。

    这个函数让"下载即用"成立：任何人第一次跑起 shim，
    都会自动把本机的真实路径探测出来并记下。
    """
    if os.path.isfile(cache_path()):
        return False
    try:
        write_cache()
        return True
    except OSError:
        return False


def summary(data=None):
    """给 CLI / UI 展示的简表。"""
    data = data or read_cache() or detect_all()
    labels = {
        "python": "Python 解释器",
        "python_launcher": "py 启动器",
        "curl": "真实 curl",
        "bash": "Git Bash",
        "git_root": "Git 安装根目录",
        "powershell": "PowerShell",
        "cmd": "cmd.exe",
    }
    rows = []
    for key, label in labels.items():
        value = data.get(key) or ""
        rows.append((label, value, bool(value)))
    return rows
