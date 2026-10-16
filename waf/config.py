# -*- coding: utf-8 -*-
"""全局配置：路径、端口、控制台编码。"""

import os
import sys


def _ensure_utf8_console():
    """Windows 控制台默认 GBK，输出中文 JSON 会炸，这里强制 UTF-8。"""
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is None:
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            # Python 3.6 / 已重定向的流
            try:
                import io
                buf = getattr(stream, "buffer", None)
                if buf is not None:
                    setattr(sys, stream_name, io.TextIOWrapper(
                        buf, encoding="utf-8", errors="replace", line_buffering=True))
            except Exception:
                pass


_ensure_utf8_console()


ROOT = os.path.dirname(os.path.abspath(os.path.join(__file__, os.pardir)))
DATA_DIR = os.path.join(ROOT, "data")
RULES_FILE = os.path.join(DATA_DIR, "rules.json")
DB_FILE = os.path.join(DATA_DIR, "events.db")
UI_DIR = os.path.join(ROOT, "ui")
CERTS_DIR = os.path.join(DATA_DIR, "certs")
RUN_DIR = os.path.join(DATA_DIR, "run")
CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

API_HOST = "127.0.0.1"
API_PORT = 8898
PROXY_PORT = 8899
PROXY_HOST = "127.0.0.1"

# 拦截时的退出码（126 = 命令找到但不可执行，符合 POSIX 语义）
BLOCK_EXIT_CODE = 126

VERSION = "1.1.8"

DEFAULT_CONFIG = {
    "api_host": API_HOST,
    "api_port": API_PORT,
    "proxy_host": PROXY_HOST,
    "proxy_port": PROXY_PORT,
    "auth_token": "",
    # 规则文件可以指到别处（比如公司共享盘上的统一规则集）。
    # 留空 = <安装目录>/data/rules.json
    "rules_file": "",
}

# 环境变量覆盖：优先于 config.json，方便临时切换或多人共用一台机器。
#
# 每个键支持新旧两个名字：HUNTGUARD_* 是现在的正式名，
# AGENTWAF_* 是 1.0 时代的名字。两个都认，新名优先。
# 为什么保留旧名：它们已经写进了用户的注册表 / ~/.bashrc，
# 直接改名会让已安装的人（包括本机旧版本）的接入失效，
# 并留下一堆注销不掉的旧条目。
ENV_OVERRIDES = {
    "api_host": "HUNTGUARD_HOST",
    "api_port": "HUNTGUARD_PORT",
    "proxy_host": "HUNTGUARD_PROXY_HOST",
    "proxy_port": "HUNTGUARD_PROXY_PORT",
    "auth_token": "HUNTGUARD_TOKEN",
    # 规则文件也可以整个换掉 —— 测试隔离、多实例并存都用得上
    "rules_file": "HUNTGUARD_RULES_FILE",
}

# 旧名映射（新名没设时才看它们）
ENV_LEGACY = {
    "api_host": "AGENTWAF_HOST",
    "api_port": "AGENTWAF_PORT",
    "proxy_host": "AGENTWAF_PROXY_HOST",
    "proxy_port": "AGENTWAF_PROXY_PORT",
    "auth_token": "AGENTWAF_TOKEN",
    "rules_file": "AGENTWAF_RULES_FILE",
}


def env_value(key):
    """取某个配置项的环境变量值：新名优先，回退旧名，都没有返回 None。

    单独抽出来是因为 autohook / guards 也要用同一套规则 —— 各写一遍
    容易漏掉旧名兼容（历史上就出过 autohook 认错变量名的问题）。
    """
    for name in (ENV_OVERRIDES.get(key), ENV_LEGACY.get(key)):
        if not name:
            continue
        value = os.environ.get(name)
        if value not in (None, ""):
            return value
    return None


def ensure_dirs():
    for path in (DATA_DIR, CERTS_DIR, RUN_DIR):
        os.makedirs(path, exist_ok=True)


def load_config():
    """读取 data/config.json，缺失字段用默认值补齐。

    优先级（低 → 高）：
        内置默认值 < config.json < 环境变量

    环境变量让"临时换个端口""多人共用一台机器"这类场景不用改文件。
    支持的环境变量见 ENV_OVERRIDES。
    """
    import json
    ensure_dirs()
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                cfg.update({k: v for k, v in data.items() if k in DEFAULT_CONFIG})
        except (ValueError, OSError):
            pass

    for key in ENV_OVERRIDES:
        value = env_value(key)
        if value is not None:
            if key.endswith("_port"):
                try:
                    value = int(value)
                except ValueError:
                    continue
            cfg[key] = value
    return cfg


def rules_path():
    """规则文件路径。config.json 里的 rules_file 可指向别处
    （例如团队共享盘上的统一规则集）。"""
    cfg = load_config()
    explicit = cfg.get("rules_file")
    if explicit:
        return os.path.expandvars(os.path.expanduser(explicit))
    return RULES_FILE
