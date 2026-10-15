# -*- coding: utf-8 -*-
"""Python 启动钩子 —— 让所有 Python 进程的 HTTP 请求受 WAF 约束。

为什么放在这个目录
------------------
早期版本把 ``.pth`` 和引导器写进系统的 site-packages，那是**安装目录
之外的文件** —— 删掉本项目目录后会在系统里留下残留，别人也搞不清
哪些是自己的。现在改成：

    PYTHONPATH=<安装目录>\\hooks    （注册表里一个环境变量，不落文件）
        ↓
    hooks/sitecustomize.py          （本文件，在项目目录内）

Python 启动时会自动 import ``sitecustomize``（只要它在 sys.path 上），
所以效果与 .pth 相同，但**零文件落在目录外**。

与其它 sitecustomize 共存
-------------------------
Python 只会 import 第一个找到的 ``sitecustomize``。我们的目录在
PYTHONPATH 里、排在 site-packages 之前，会挡住别人装的同名文件。
所以这里做了**链式调用**：执行完自己的逻辑后，主动去找 sys.path 里
其它位置的 sitecustomize 并执行它，保证不破坏别人的环境。

安全约束（与 autohook 一致）
----------------------------
1. WAF 没开就什么都不做（只读一次心跳文件的 mtime）
2. 不 import 任何 WAF 模块，直到确实要装护栏
3. 所有异常一律吞掉，绝不弄崩宿主进程
4. ``AGENTWAF_NO_HOOK=1`` 整体关闭
"""

import os
import sys

_HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HOOKS_DIR)



def _env_flag(*names):
    """任一变量为 1 即算开启（新名在前，旧名兼容）。"""
    for name in names:
        if os.environ.get(name) == "1":
            return True
    return False

def _chain_other_sitecustomize():
    """执行 sys.path 里其它位置的 sitecustomize（如果有）。

    我们占了 ``sitecustomize`` 这个名字，别人装的就轮不到被
    Python 自动 import 了。这里手动找出来执行，避免"装了 HuntGuard
    之后某个库的 sitecustomize 不生效"这种隐蔽问题。
    """
    try:
        for entry in sys.path:
            if not entry:
                continue
            try:
                if os.path.abspath(entry) == _HOOKS_DIR:
                    continue
            except OSError:
                continue
            candidate = os.path.join(entry, "sitecustomize.py")
            if not os.path.isfile(candidate):
                continue
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "_agentwaf_other_sitecustomize", candidate)
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception:
                pass
            return                     # 只执行第一个，与 Python 语义一致
    except Exception:
        pass


def _load_waf_hook():
    """按路径加载 autohook（不 import waf 包名，避免绑定安装目录）。"""
    if _env_flag("HUNTGUARD_NO_HOOK", "AGENTWAF_NO_HOOK"):
        return
    target = os.path.join(_ROOT, "waf", "autohook.py")
    if not os.path.isfile(target):
        return
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "_agentwaf_autohook", target)
        if spec is None or spec.loader is None:
            return
        module = importlib.util.module_from_spec(spec)
        # 不放进 sys.modules：避免被误当成公共模块
        spec.loader.exec_module(module)
    except Exception:
        pass


# 先让别人的 sitecustomize 跑（保持原语义），再装我们的护栏
_chain_other_sitecustomize()
_load_waf_hook()
