# -*- coding: utf-8 -*-
"""waf-run：带 WAF 护栏地运行任意命令。

原理（Windows 无 LD_PRELOAD，用两个互补机制）：
  1. 注入 sitecustomize.py 到 PYTHONPATH → 子 Python 进程启动即装 guard
     （覆盖 requests / urllib / httpx / aiohttp / subprocess）
  2. 把 bin/ 放到子进程 PATH 最前 → 子进程调 curl 时走 shim

用法：
    waf-run python exp.py
    waf-run --no-shim python exp.py     # 只装 guard，不改 PATH
    waf-run --shell "curl http://x/?delete=1"
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import config                                 # noqa: E402

SITECUSTOMIZE = '''# -*- coding: utf-8 -*-
# HuntGuard 自动注入的 sitecustomize：子 Python 进程启动即启用护栏。
import os, sys
if os.environ.get("WAF_DISABLE") != "1":
    try:
        _root = os.environ.get("WAF_ROOT")
        if _root and _root not in sys.path:
            sys.path.insert(0, _root)
        import waf.guard as _guard
        _guard.install_guard()
    except Exception as _exc:
        sys.stderr.write("[agent-waf] guard 注入失败：%r\\n" % (_exc,))
'''


def _ensure_sitecustomize():
    """生成临时 sitecustomize 目录，返回其路径。

    这个目录**必须留在盘上**：子 Python 进程靠 PYTHONPATH 找到它，
    删掉等于让护栏失效 —— 所以不做"用完即删"。

    但里面会积 pycache（子进程导入 sitecustomize 时生成的 .pyc），
    那是纯垃圾。实测发现：以前没有任何清理逻辑，
    data/run/pysite/ 会一直躺着。现在每次调用顺手清掉。

    另一个细节：内容相同时不重写文件 —— 避免无意义的 mtime 变化，
    也让"正在运行的"子进程不会读到一个刚被截断的文件。
    """
    path = os.path.join(config.RUN_DIR, "pysite")
    os.makedirs(path, exist_ok=True)

    # 清 pycache
    for folder, dirs, _files in os.walk(path):
        for name in list(dirs):
            if name == "__pycache__":
                shutil.rmtree(os.path.join(folder, name), ignore_errors=True)
                dirs.remove(name)

    target = os.path.join(path, "sitecustomize.py")
    try:
        with open(target, "r", encoding="utf-8") as fh:
            existing = fh.read()
    except (OSError, ValueError):
        existing = None
    if existing != SITECUSTOMIZE:
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(SITECUSTOMIZE)
    return path


def build_env(use_shim=True):
    env = dict(os.environ)
    site_dir = _ensure_sitecustomize()

    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = site_dir + (os.pathsep + existing if existing else "")
    env["WAF_ROOT"] = ROOT
    env["WAF_ACTIVE"] = "1"

    if use_shim:
        bin_dir = os.path.join(ROOT, "bin")
        parts = [p for p in env.get("PATH", "").split(os.pathsep)
                 if p and os.path.normcase(os.path.abspath(p)) != os.path.normcase(bin_dir)]
        env["PATH"] = os.pathsep.join([bin_dir] + parts)

    return env


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    use_shim = True
    while argv and argv[0].startswith("--"):
        flag = argv.pop(0)
        if flag == "--no-shim":
            use_shim = False
        elif flag == "--shell":
            if not argv:
                sys.stderr.write("用法: waf-run --shell \"命令\"\n")
                return 2
            argv = ["cmd", "/c", argv[0]] if os.name == "nt" else ["/bin/sh", "-c", argv[0]]
        elif flag in ("-h", "--help"):
            sys.stdout.write(__doc__)
            return 0
        else:
            sys.stderr.write("未知参数：%s\n" % flag)
            return 2

    if not argv:
        sys.stdout.write(__doc__)
        return 2

    config.ensure_dirs()
    env = build_env(use_shim)

    if os.environ.get("WAF_RUN_VERBOSE") == "1":
        sys.stderr.write("[agent-waf] waf-run 启动：%s\n" % " ".join(argv))
        sys.stderr.write("[agent-waf]   WAF_ROOT  = %s\n" % ROOT)
        sys.stderr.write("[agent-waf]   PYTHONPATH= %s\n" % env.get("PYTHONPATH", ""))

    executable = argv[0]
    resolved = shutil.which(executable, path=env.get("PATH")) or executable
    try:
        proc = subprocess.Popen(argv, env=env, executable=None)
    except FileNotFoundError:
        sys.stderr.write("[agent-waf] 找不到命令：%s\n" % executable)
        return 127
    try:
        return proc.wait()
    except KeyboardInterrupt:
        proc.terminate()
        return 130


if __name__ == "__main__":
    sys.exit(main())
