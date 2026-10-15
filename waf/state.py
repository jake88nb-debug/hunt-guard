# -*- coding: utf-8 -*-
"""激活态管理：决定拦截器此刻是否生效。

设计依据
--------
需求："我开启了才启用，我没打开就不要生效。"

因此被动拦截需要**同时**满足两个条件：

1. ``settings.enabled`` —— 用户意图开关，持久化在 rules.json（可暂停而不关控制台）
2. 控制台心跳 —— HuntGuard 此刻真的在运行

心跳机制：控制台启动时写 ``data/run/active.json``，后台线程每 5 秒刷新
一次 mtime；正常关闭时删除。判定"活跃" = 文件存在 **且** mtime 在
20 秒内。这样即使控制台被强杀（来不及清理），最多 20 秒后自动失效，
不会出现"程序没开却一直在拦"的情况。

被动路径（curl shim / 代理 / Burp 扩展）走本模块判定。
显式路径（``waf-run`` / ``wafctl check`` / 用户脚本里 import waf.guard）
不经判定 —— 用户主动调用本身就是"开启"的意思。

环境变量
--------
``WAF_ALWAYS_ON=1``   强制视为已开启（脱离控制台使用，测试用）
``WAF_ALWAYS_OFF=1``  强制视为未开启
"""

import json
import os
import threading
import time

from . import config

HEARTBEAT_INTERVAL = 5.0     # 心跳写盘间隔（秒）
STALE_AFTER = 20.0           # 超过这个时间没心跳就视为已停止

_file_lock = threading.RLock()
_heartbeat_thread = None
_heartbeat_stop = threading.Event()


def state_path():
    """心跳文件路径。

    ``WAF_STATE_FILE`` 可覆盖 —— 测试用它指向隔离文件，
    避免读到真实控制台的心跳（否则测试结果依赖外部进程状态）。
    """
    override = os.environ.get("WAF_STATE_FILE")
    if override:
        return override
    return os.path.join(config.RUN_DIR, "active.json")


def _write(payload, path=None):
    path = path or state_path()
    config.ensure_dirs()
    tmp = path + ".tmp"
    with _file_lock:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        os.replace(tmp, path)


def _touch(path):
    """只刷新 mtime，不重写内容（心跳用）。"""
    try:
        now = time.time()
        os.utime(path, (now, now))
        return True
    except OSError:
        return False


# ---------------------------------------------------------------- 开关

def activate(port=None, path=None, pid=None):
    """标记为活跃：写心跳文件并启动后台刷新线程。"""
    cfg = config.load_config()
    payload = {
        "pid": pid if pid is not None else os.getpid(),
        "port": port if port is not None else cfg.get("api_port", config.API_PORT),
        "host": cfg.get("api_host", config.API_HOST),
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "heartbeat": time.time(),
    }
    _write(payload, path)
    start_heartbeat(path, payload)
    return payload


def deactivate(path=None):
    """标记为停止：删除心跳文件并停掉刷新线程。"""
    stop_heartbeat()
    path = path or state_path()
    with _file_lock:
        for candidate in (path, path + ".tmp"):
            try:
                if os.path.exists(candidate):
                    os.remove(candidate)
            except OSError:
                pass
    return True


def start_heartbeat(path=None, payload=None):
    """启动心跳刷新线程。

    语义约定（重要）：
      * 心跳文件 = **控制台进程活着**。文件被删除只是意外（比如被清理
        工具删掉），线程会**自动重建** —— 不会因为一次误删就永久失去
        拦截能力。
      * 要不要拦 = ``settings.enabled``（用户在 UI 上的开关）+
        心跳新鲜，两者都要满足。

    早期版本在文件消失时直接退出线程，导致"控制台还在跑但拦截器
    再也不生效"的静默故障。
    """
    global _heartbeat_thread
    with _file_lock:
        if _heartbeat_thread is not None and _heartbeat_thread.is_alive():
            return
        _heartbeat_stop.clear()
        target = path or state_path()
        data = payload

        def _loop():
            while not _heartbeat_stop.wait(HEARTBEAT_INTERVAL):
                if _touch(target):
                    continue
                # 文件不见了：自我修复，重新写一份完整的
                try:
                    if data:
                        _write(data, target)
                    else:
                        _write(_default_payload(), target)
                except Exception:
                    pass

        _heartbeat_thread = threading.Thread(target=_loop, name="waf-heartbeat")
        _heartbeat_thread.daemon = True
        _heartbeat_thread.start()


def _default_payload():
    cfg = config.load_config()
    return {
        "pid": os.getpid(),
        "port": cfg.get("api_port", config.API_PORT),
        "host": cfg.get("api_host", config.API_HOST),
        "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "heartbeat": time.time(),
    }


def stop_heartbeat():
    global _heartbeat_thread
    _heartbeat_stop.set()
    with _file_lock:
        _heartbeat_thread = None


# ---------------------------------------------------------------- 查询

def read(path=None):
    """读取心跳文件内容；不存在或损坏返回 None。"""
    path = path or state_path()
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            return data
    except (OSError, ValueError):
        pass
    return None


def age(path=None):
    """心跳文件距今多少秒；不存在返回 None。"""
    path = path or state_path()
    try:
        return max(0.0, time.time() - os.path.getmtime(path))
    except OSError:
        return None


def is_active(path=None):
    """拦截器是否处于"正在运行"状态（供被动路径调用）。"""
    if os.environ.get("WAF_ALWAYS_OFF") == "1":
        return False
    if os.environ.get("WAF_ALWAYS_ON") == "1":
        return True
    elapsed = age(path)
    if elapsed is None:
        return False
    return elapsed <= STALE_AFTER


def status(path=None):
    """给 UI / doctor 用的完整状态。"""
    elapsed = age(path)
    active = is_active(path)
    info = read(path) or {}
    result = {
        "active": active,
        "file": path or state_path(),
        "exists": elapsed is not None,
        "age_sec": round(elapsed, 1) if elapsed is not None else None,
        "stale_after": STALE_AFTER,
        "pid": info.get("pid"),
        "port": info.get("port"),
        "started_at": info.get("started_at"),
    }
    if elapsed is not None and elapsed > STALE_AFTER:
        result["hint"] = ("心跳已过期 %.0f 秒，视为已停止。"
                          "若控制台确实在运行，请重启它。" % elapsed)
    elif not active and not result["exists"]:
        result["hint"] = "未启动。双击 start.bat 后拦截才会生效。"
    return result


def should_intercept(engine=None, path=None):
    """被动拦截路径的统一判定：此刻要不要真的检查请求？

    两个条件都要满足：

    1. 控制台在运行（心跳文件新鲜）
    2. 用户没有主动暂停（rules.json 的 settings.enabled 不为 false）

    任一不满足 → 放行。这样"没打开就不生效"和"打开了但想临时暂停"
    两种情况都能正确处理。

    ``path`` 用于测试时指向隔离的心跳文件；生产代码传默认值即可。

    返回 (bool, reason)。
    """
    if os.environ.get("WAF_ALWAYS_OFF") == "1":
        return False, "WAF_ALWAYS_OFF=1"
    if os.environ.get("WAF_ALWAYS_ON") == "1":
        if engine is not None:
            try:
                if not engine.enabled():
                    return False, "控制台内已暂停"
            except Exception:
                pass
        return True, "WAF_ALWAYS_ON=1"

    if not is_active(path):
        elapsed = age(path)
        if elapsed is None:
            return False, "控制台未运行"
        return False, "控制台心跳已过期（%.0f 秒）" % elapsed

    if engine is not None:
        try:
            if not engine.enabled():
                return False, "控制台内已暂停拦截"
        except Exception:
            pass
    return True, "运行中"
