# -*- coding: utf-8 -*-
"""
HuntGuard —— Burp Suite 扩展（Jython）

作用
----
在 Burp 发出请求之前拦下命中敏感词的请求，返回 403 + JSON，目标服务器
收不到任何数据。规则从上位 HuntGuard 的 data/rules.json 读取，改规则后
点扩展面板的「重新加载」即可生效（也可勾选自动重载）。

安装
----
1. Burp → Extensions → Extension settings → Python environment
   选择 jython-standalone-x.x.x.jar（没装先去 jython.org 下载）
2. Burp → Extensions → Installed → Add
   Extension type: Python
   Extension file: 本文件 (burp/burp_waf.py)
3. 安装成功后会出现 "HuntGuard" 标签页

配置
----
规则文件路径**自动发现**，不需要手填。发现顺序：
  1. 从扩展自身位置推导（本文件在 <安装目录>/burp/ 下，往上两级）
  2. 环境变量 HUNTGUARD_HOME（或旧名 AGENTWAF_HOME）指向安装目录
  3. 问本地控制台 API（/api/status 会返回自己的 rules_file）
  4. 探测常见安装位置（C:\agent-waf、%USERPROFILE%\agent-waf 等）

正常情况下第 1 条就命中 —— 文件夹放哪、叫什么名字都不影响。

如果都找不到，在标签页里手动填路径后点「应用路径」。
换过安装目录时点「自动发现」即可。

API 地址可用 AGENTWAF_API（完整 URL）或 AGENTWAF_PORT（只改端口）覆盖。

拦截方式
--------
Burp 旧版扩展 API 无法直接注入合成响应，所以用本地"沉洞"服务器实现：
命中时把请求改写到本机沉洞端口（默认 8897），沉洞返回 403 + JSON。
请求绝对不会到达真实目标。面板里可切换：
  sinkhole —— 改写为 http://127.0.0.1:8897/…（能看到完整 403 JSON）
  fail     —— 改写到关闭端口（Burp 显示连接失败）
如果 HTTPS 请求在 sinkhole 模式下没有正确显示 403，改用 fail 模式，
或直接用「上游代理」方式（把 Burp 的 Upstream Proxy 指到 127.0.0.1:8899）。
"""

import json
import os
import re
import sys
import threading
import time

from java.awt import BorderLayout, Dimension, FlowLayout, GridLayout
from java.io import File
from java.lang import String, Thread as JavaThread
from java.net import ServerSocket, Socket
from javax.swing import (BoxLayout, JButton, JCheckBox, JLabel, JPanel,
                         JScrollPane, JTabbedPane, JTextArea, JTextField,
                         SwingUtilities)
from javax.swing.table import DefaultTableModel

try:
    from burp import IBurpExtender, IHttpListener, ITab
except ImportError:
    # 不在 Burp 环境（例如被 IDE 静态检查）：给占位基类，方便语法检查
    class IBurpExtender(object):
        pass

    class IHttpListener(object):
        pass

    class ITab(object):
        pass


# 规则没写 sources 时按"全部字段"处理，与主引擎一致。
#
# 为什么在这里复制一份而不是 import waf：本扩展跑在 **Jython 2.7**
# 里（Burp 的 Python 环境），而 waf 包是 Python 3 代码，
# 连语法都不兼容，不可能 import。所以字段名列表抄一份。
# 改动 waf/models.ALL_SOURCES 时要同步这里 —— 已在
# tests/test_portable.py 里加了断言盯着。
_ALL_SOURCES = ["url", "path", "query", "body",
                "headers", "method", "host", "raw_cmd"]


# ---------------------------------------------------------------- 配置发现
#
# 不硬编码安装路径 —— 别人可能装在 C:\tools\agent-waf 或任何地方。
# 发现顺序（越靠前越优先）：
#   1. 标签页里手动填的路径（一次填好就记住）
#   2. 环境变量 HUNTGUARD_HOME / AGENTWAF_HOME
#   3. 问本地控制台 API（它知道自己的 root 和 rules_file）
#   4. 常见安装位置探测
#
# 端口同理：从 AGENTWAF_API 环境变量读，默认 127.0.0.1:8898。

DEFAULT_SINKHOLE_PORT = 8897

# 主指针的两个名字：HUNTGUARD_HOME（新）优先，AGENTWAF_HOME 兼容旧装
ENV_HOME = "HUNTGUARD_HOME"
ENV_HOME_LEGACY = "AGENTWAF_HOME"
ENV_API = "AGENTWAF_API"
ENV_PORT = "AGENTWAF_PORT"

# 兜底候选目录：只在"自我定位"和"问 API"都失败时用。
# 正常情况下不需要 —— 扩展自己就在安装目录内，能直接推导出来。
# 这里只是尽量多猜几个常见位置，末尾再拼上 %USERPROFILE% 下的同类目录。
# 只探测盘符根与常见工具目录，**不写死具体安装路径**。
#
# 早先这里硬编码了几个具体的安装路径 —— 那些位置在别人的
# 机器上并不存在，等于白探。目录名候选在 NAME_CANDIDATES，
# 两个维度做笛卡尔积即可覆盖同样的搜索空间。
#
# 用 os.path.join(盘符 + sep, 名字) 拼，避免出现 r"C:\" 这种
# 非法 raw string（raw string 不能以单个反斜杠结尾，编译器直接报
# EOL while scanning string literal —— 实测踩过）。
CANDIDATE_ROOTS = [
    "C:" + os.sep,
    "D:" + os.sep,
    "C:" + os.sep + "tools",
    "D:" + os.sep + "tools",
    "C:" + os.sep + "opt",
    "D:" + os.sep + "opt",
]

# 目录名候选：新名在前，旧名保留 —— 别人可能把文件夹放成任意名字
NAME_CANDIDATES = ["hunt-guard", "HuntGuard", "agent-waf", "agentwaf", "AgentWAF"]


def _candidate_homes():
    """候选目录 + 用户主目录下的同类目录（运行期拼，避免写死某台机器）。"""
    import os as _os
    # 盘符根 × 目录名候选（不再写死具体路径）
    homes = []
    for root in CANDIDATE_ROOTS:
        for name in NAME_CANDIDATES:
            homes.append(_os.path.join(root, name))
    for base in (_os.environ.get("USERPROFILE"),
                 _os.environ.get("HOME"),
                 _os.path.expanduser("~")):
        if not base:
            continue
        for name in NAME_CANDIDATES:
            homes.append(_os.path.join(base, name))
            homes.append(_os.path.join(base, "tools", name))
    return homes


def _api_base():
    """控制台 API 地址。可用 AGENTWAF_API 覆盖整个 URL。"""
    import os as _os
    explicit = _os.environ.get(ENV_API)
    if explicit:
        return explicit.rstrip("/")
    port = _os.environ.get(ENV_PORT) or "8898"
    return "http://127.0.0.1:%s" % port


def _discover_from_env():
    import os as _os
    # 两个名字都试：新名优先，旧名兼容已装好的机器
    home = (_os.environ.get(ENV_HOME)
            or _os.environ.get(ENV_HOME_LEGACY))
    if not home:
        return None
    candidate = _os.path.join(home, "data", "rules.json")
    if _os.path.isfile(candidate):
        return candidate
    return None


def _discover_from_api():
    """问控制台 API 要规则文件路径。

    控制台响应 /api/status 会带 root 与 rules_file —— 这是最可靠的
    自动发现方式（不需要用户填任何东西）。
    """
    import json as _json
    try:
        from java.net import URL
        from java.io import BufferedReader, InputStreamReader
        url = URL(_api_base() + "/api/status")
        conn = url.openConnection()
        conn.setConnectTimeout(800)
        conn.setReadTimeout(1200)
        reader = BufferedReader(InputStreamReader(conn.getInputStream(), "UTF-8"))
        chunks = []
        line = reader.readLine()
        while line is not None:
            chunks.append(line)
            line = reader.readLine()
        reader.close()
        data = _json.loads("\n".join(chunks))
        path = data.get("rules_file")
        if path:
            return path
    except Exception:
        pass
    return None


def _discover_from_candidates():
    import os as _os
    for home in _candidate_homes():
        candidate = _os.path.join(home, "data", "rules.json")
        if _os.path.isfile(candidate):
            return candidate
    return None


def _discover_from_self():
    """从扩展自己的位置推导安装目录。

    扩展就放在 ``<安装目录>/burp/burp_waf.py``，所以往上两级就是根。
    这是最可靠的发现方式 —— 不管用户把文件夹叫什么、放在哪个盘，
    只要扩展还是从本地文件加载的，就能算出来（下载即用的关键）。
    """
    import os as _os
    try:
        here = _os.path.abspath(__file__)
    except NameError:
        return None                      # 极端情况下 Jython 不提供 __file__
    root = _os.path.dirname(_os.path.dirname(here))
    candidate = _os.path.join(root, "data", "rules.json")
    if _os.path.isfile(candidate):
        return candidate
    # rules.json 还没生成也算有效位置（首次运行前），返回 None 让别的
    # 方式继续找；这种情况用户跑一次 wafctl 就解决了
    return None


def discover_rules_path():
    """按优先级发现规则文件路径；找不到返回 None。

    顺序：自我定位 → 环境变量 → 问控制台 API → 常见目录兜底。
    自我定位放第一是因为它不需要任何外部条件，最稳。
    """
    for finder in (_discover_from_self, _discover_from_env,
                   _discover_from_api, _discover_from_candidates):
        try:
            found = finder()
            if found:
                return found
        except Exception:
            continue
    return None

SEPARATORS = r"[\s_\-\.\,;:/\|\\\*\+\~\^`'\"\(\)\[\]\{\}<>@!\?#=&%$]"


# ====================================================================
# 规则引擎（自包含，与 waf/engine.py 语义一致）
# ====================================================================

class MiniEngine(object):
    """Jython 版规则匹配：归一化 + 关键词/正则 + 白名单 + 解锁窗口。"""

    def __init__(self, rules_path, log):
        self.rules_path = rules_path
        self.log = log
        self.rules = []
        self.allowlist = []
        self.settings = {}
        self._stamp = None
        self._lock = threading.RLock()
        # 当前处理的字段原文 —— _hit 需要它来填 _orig（见 _excluded）
        self._cur_original = ""

    # -------------------------------------------------- 加载

    def _stat_stamp(self):
        try:
            st = os.stat(self.rules_path)
            return (st.st_mtime, st.st_size)
        except OSError:
            return None

    # 病态正则会让 re.finditer 卡死在单次匹配里，而这里跑在 Burp 的
    # 线程上 —— 一旦卡住整个扩展界面都不响应（主引擎有 regexguard
    # 子进程探测 + 超时，Jython 这边没有 subprocess，所以用静态启发式）。
    _REDOS_SIGNS = [
        r"\((?:[^()\\]|\\.)*[+*]\)\s*[+*]",     # (a+)+ / (a*)*
        r"\((?:[^()\\]|\\.)*[+*]\)\s*\{",      # (a+){2,}
        r"\[[^\]]+\][+*]\s*[+*]",                  # [a-z]*+ 之类
        r"\(\?[:=!]?[^()]*[+*][^()]*\)\s*\{",     # 组内量词再加计数
    ]

    def _regex_is_risky(self, pattern):
        """静态判断正则是否有灾难性回溯风险（保守，只挡明显的）。

        Jython 里没有子进程可用，做不了主引擎那种真实超时探测，
        所以用形态启发式：嵌套量词（(a+)+ 这类）是绝大多数 ReDoS
        的形态。宁可误拒几条规则正则，也不能让 Burp 界面卡死。
        """
        if not pattern or len(pattern) > 4000:
            return True                    # 超长的一律拒绝（与主引擎一致）
        for sign in self._REDOS_SIGNS:
            try:
                if re.search(sign, pattern):
                    return True
            except Exception:
                continue
        return False

    def load_if_changed(self, force=False):
        stamp = self._stat_stamp()
        if not force and stamp is not None and stamp == self._stamp:
            return False
        with self._lock:
            if not os.path.exists(self.rules_path):
                self.log("[waf] 规则文件不存在：%s" % self.rules_path)
                self.rules, self.allowlist, self.settings = [], [], {}
                self._stamp = stamp
                return True
            try:
                fh = open(self.rules_path, "r")
                try:
                    raw = fh.read()
                finally:
                    fh.close()
                if isinstance(raw, bytes):
                    raw = raw.decode("utf-8", "replace")
                doc = json.loads(raw)
            except Exception as exc:
                self.log("[waf] 规则文件解析失败：%r" % (exc,))
                self._stamp = stamp
                return False

            self.settings = doc.get("settings") or {}
            self.rules = [r for r in (doc.get("rules") or []) if r.get("enabled", True)]
            self.allowlist = [a for a in (doc.get("allowlist") or []) if a.get("enabled", True)]
            self._stamp = stamp
            self.log("[waf] 已加载 %d 条规则 / %d 条放行" %
                     (len(self.rules), len(self.allowlist)))
            return True

    @property
    def _api_token(self):
        """从控制台配置读 auth_token（拿不到就返回空，不影响回传）。"""
        try:
            cfg_path = os.path.join(os.path.dirname(self.rules_path),
                                    "config.json")
            with open(cfg_path, "r") as fh:
                cfg = json.load(fh)
            return str(cfg.get("auth_token") or "")
        except Exception:
            return ""

    def mode(self):
        return str(self.settings.get("mode", "block")).lower()

    def unlock_remaining(self):
        try:
            until = float(self.settings.get("unlock_until") or 0)
        except (TypeError, ValueError):
            until = 0
        return max(0.0, until - time.time())

    def unlock_reason(self):
        return str(self.settings.get("unlock_reason") or "")

    def normalize_ops(self):
        return self.settings.get("normalize") or [
            "url_decode", "html_unescape", "unicode_unescape",
            "fold_fullwidth", "strip_invisible", "collapse_ws", "compact", "lower"]

    # -------------------------------------------------- 归一化

    def _url_decode_deep(self, text, rounds=3):
        from java.net import URLDecoder
        current = text
        for _ in range(rounds):
            try:
                nxt = URLDecoder.decode(current, "UTF-8")
            except Exception:
                break
            if nxt == current:
                break
            current = nxt
        return current

    def _html_unescape(self, text):
        return (text.replace("&lt;", "<").replace("&gt;", ">")
                    .replace("&quot;", '"').replace("&#39;", "'")
                    .replace("&amp;", "&"))

    def _unicode_unescape(self, text):
        def _rep(match):
            raw = match.group(1) or match.group(2)
            try:
                code = int(raw, 16)
                if code > 0x10FFFF:
                    return match.group(0)
                return unichr(code) if sys.version_info[0] == 2 else chr(code)
            except Exception:
                return match.group(0)

        try:
            return re.sub(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})", _rep, text)
        except Exception:
            return text

    def _strip_invisible(self, text):
        try:
            return re.sub(u"[\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u2028\u2029]",
                          u"", text)
        except Exception:
            return text

    def _fold_fullwidth(self, text):
        out = []
        for ch in text:
            code = ord(ch)
            if 0xFF01 <= code <= 0xFF5E:
                out.append(unichr(code - 0xFEE0) if sys.version_info[0] == 2
                           else chr(code - 0xFEE0))
            elif code == 0x3000:
                out.append(u" ")
            else:
                out.append(ch)
        return u"".join(out)

    def normalize(self, text, compact=False):
        if not isinstance(text, basestring if sys.version_info[0] == 2 else str):
            text = str(text)
        try:
            out = self._url_decode_deep(text)
            out = self._html_unescape(out)
            out = self._unicode_unescape(out)
            out = self._fold_fullwidth(out)
            out = self._strip_invisible(out)
            out = re.sub(r"\s+", u" ", out)
            if compact:
                out = re.sub(SEPARATORS, u"", out)
            out = out.lower()
            return out
        except Exception:
            return text.lower()

    def variants(self, text):
        """返回 [(label, value)]：普通归一化 + 压缩变体。"""
        normal = self.normalize(text, compact=False)
        result = [("normalized", normal)]
        compacted = re.sub(SEPARATORS, u"", normal)
        if compacted != normal:
            result.append(("compact", compacted))
        if text != normal:
            result.append(("original", text))
        return result

    # -------------------------------------------------- 匹配

    def allow_hit(self, source, text):
        for entry in self.allowlist:
            src = str(entry.get("source") or "any")
            if src not in ("any", source):
                continue
            try:
                if re.search(entry.get("pattern") or "", text, re.I):
                    return entry
            except Exception:
                continue
        return None

    def scan_fields(self, fields):
        """fields: [(source, text)]；返回命中列表。"""
        self.load_if_changed()
        unlocked = self.unlock_remaining() > 0
        hits = []

        for source, raw_text in fields:
            if not raw_text:
                continue
            text = raw_text
            self._cur_original = text
            if self.allow_hit(source, text):
                continue
            variants = self.variants(text)

            for rule in self.rules:
                # 空 / 缺失的 sources 表示"全部字段" —— 与引擎
                # (engine.py: rule_sources = rule.get("sources") or ALL_SOURCES)
                # 语义必须一致。
                #
                # 这里踩过一次：写成 (rule.get("sources") or [])，
                # 而**内置规则全都没有 sources 键**（"留空 = 全部"
                # 是后来引入的约定，早先的写法是显式列全 8 个字段）。
                # 于是 (None or []) == [] → source not in [] 恒为真 →
                # 每条规则都被 continue 跳过，Burp 扩展**一条都不拦**，
                # 删除类请求直接放行。而主引擎走 ALL_SOURCES 一切正常，
                # 所以从 CLI 侧完全测不出来 —— 只有真在 Burp 里发请求
                # 才会发现。
                rule_sources = rule.get("sources") or _ALL_SOURCES
                if source not in rule_sources:
                    continue
                match_mode = str(rule.get("match_mode") or "substring")
                keywords = rule.get("keywords") or []
                regexes = rule.get("regex") or []
                excludes = rule.get("exclude") or []
                found = []

                # 关键词与正则**都**参与匹配 —— match_mode 只决定关键词
                # 的匹配方式（与主引擎 engine.py:734-741 一致）。
                #
                # 早先是 if/else 二选一，于是 R-101（match_mode 是
                # substring、但 delete 只写在 regex 里）的正则全部不执行
                # —— Burp 里 /api/deleteUser 这类最常见的删除接口完全不拦，
                # 而 CLI 侧完全正常（主引擎跑两遍）。实测：修复前该 payload
                # 命中 0 条，修复后拦下。这是同一个仓库里两套实现漂移的
                # 第五处。
                if keywords:
                    found.extend(self._match_keyword(source, rule, keywords,
                                                     variants, match_mode))
                if regexes:
                    found.extend(self._match_regex(source, rule, regexes,
                                                   variants))

                # 先排除、再去重（与主引擎一致）。
                # 反过来的话，先出现的 deleted_at 会占据去重表，
                # 把后面真正的 delete 当重复吃掉 —— 而它自己又会被
                # exclude 抑制，最终整个字段零命中。
                kept = []
                for hit in found:
                    if self._excluded(hit, excludes):
                        continue
                    kept.append(hit)
                hits.extend(self._dedupe(kept))

        hits.sort(key=lambda h: self._sev_rank(h["severity"]))
        return hits, unlocked

    def _sev_rank(self, sev):
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        return order.get(sev, 99)

    def _match_keyword(self, source, rule, keywords, variants, match_mode):
        """在一个字段的每个归一化变体上找关键词，**每个出现位置都算一次**。

        早先只取第一个出现位置（`value.find` / `re.search` 单次），
        配合"按关键词去重"产生一个可被利用的盲区：

            {"deleted_at":null,"action":"delete"}

        `delete` 第一次出现在 `deleted_at` 里（会被 exclude 正确抑制），
        后面那个真正的 delete 永远不会被检查 —— 在 payload 前面塞一个
        正常业务字段名就等于免检。主引擎 1.1.0 修过这个（见
        engine._match_keyword_rule 的注释），Burp 这份 Jython 副本
        没跟上。实测该 payload 修复前放行、修复后拦截。

        注意 offset 是**该变体坐标系**里的位置，不是原文位置 ——
        所以后续的 exclude 判断必须在同一个变体上做（见 _excluded）。
        """
        hits = []
        for label, value in variants:
            for keyword in keywords:
                needle = str(keyword).lower()
                if not needle:
                    continue
                if match_mode == "word":
                    pattern = (r"(?<![a-z0-9_])" + re.escape(needle)
                               + r"(?![a-z0-9_])")
                    positions = [m.start()
                                 for m in re.finditer(pattern, value)]
                else:
                    positions = []
                    start = value.find(needle)
                    while start >= 0:
                        positions.append(start)
                        start = value.find(needle, start + 1)
                for offset in positions:
                    hits.append(self._hit(source, rule, keyword, value,
                                          offset, label))
        # 不在内部去重：_dedupe 会 pop("_raw")，而 scan_fields 还要用
        # _raw 做 exclude 判断（少了它 _excluded 只能返回 False，
        # exclude 整个失效）。排除与去重统一在 scan_fields 里按顺序做。
        return hits

    def _match_regex(self, source, rule, regexes, variants):
        hits = []
        for label, value in variants:
            for pattern in regexes:
                if self._regex_is_risky(pattern):
                    # 病态正则跳过：卡死 Burp 界面比漏一条规则更糟
                    # （主引擎走 regexguard 子进程探测，这里只能用启发式）
                    continue
                try:
                    for match in re.finditer(pattern, value, re.I):
                        hits.append(self._hit(source, rule, match.group(0),
                                              value, match.start(), label))
                except Exception:
                    continue
        # 同上：不去重（保留 _raw 供 exclude 判断）
        return hits

    def _hit(self, source, rule, keyword, value, offset, label):
        start = max(0, offset - 20)
        end = min(len(value), offset + max(len(str(keyword)), 1) + 20)
        return {
            "source": source,
            "keyword": str(keyword)[:120],
            "matched_text": value[start:end][:400],
            "rule_id": rule.get("id", ""),
            "rule_name": rule.get("name", ""),
            "severity": rule.get("severity", "medium"),
            "action": rule.get("action", "block"),
            "field": label,
            "offset": offset,
            "_raw": value,          # 命中所在变体（坐标基准）
            "_orig": self._cur_original,  # 原文（exclude 按原文判断）
        }

    def _excluded(self, hit, excludes):
        """命中是否被 exclude 抑制。

        两处与主引擎对齐（都是实测发现的漂移）：

        1. **坐标系**：以前传进来的是原文 text，而 hit["offset"] 是
           *归一化变体*里的位置 —— 归一化会改变长度（url_decode 变短、
           compact 删分隔符），拿变体 offset 去切原文必然错位，窗口
           落在错误位置，误拦/漏拦双向都有。现在直接用 hit 里存的
           变体文本（_raw）来切，两边同一套坐标。
           主引擎用 index_map 把 offset 翻译回原文再判，这里因为
           matched_text/exclude 都只看局部，直接用变体坐标等价且更简单。

        2. **判据**：不再是"距命中 ±24 字符内出现 exclude 词"，
           而是"exclude 片段**覆盖了**命中位置"。旧窗口逻辑下
               {"deleted_at":null,"action":"delete","id":9}
           里的 delete 会因为离 deleted_at 二十多个字符而被一起放过 ——
           在 payload 前面塞个正常业务字段名就能免疫。exclude 列的
           本来就是"长得像敏感词的正常标识符"（deleted_at / undelete /
           can_delete），特征是**把敏感词包在里面**，所以判据是覆盖。
        """
        if not excludes:
            return False
        variant = hit.get("_raw")          # 命中所在的归一化变体
        offset = hit.get("offset", -1)
        original = hit.get("_orig")        # 原文（exclude 模式是照原文写的）
        if variant is None or offset < 0:
            return False
        keyword = str(hit.get("keyword") or "")
        length = max(len(keyword), 1)

        # 优先在**原文**上判断。
        #
        # 为什么不能直接在变体上判（踩过）：compact 变体会把分隔符删掉，
        # `deleted_at=2024-01-01` 变成 `deletedat20240101`，
        # 而 exclude 模式写的是 `deleted_at` —— 自然匹配不上，
        # 于是软删除字段被误拦（实测症状：deleted_at 产生 block 命中，
        # 主引擎正确抑制）。用户写 exclude 时看的是原文，
        # 判断就也该在原文上做。
        if isinstance(original, basestring if sys.version_info[0] == 2 else str):
            spans = []
            pos = original.lower().find(keyword.lower())
            while pos >= 0:
                spans.append((pos, pos + length))
                pos = original.lower().find(keyword.lower(), pos + 1)
            if spans:
                for pattern in excludes:
                    try:
                        covered = []
                        for match in re.finditer(pattern, original, re.I):
                            for start, end in spans:
                                covered.append(match.start() < end
                                               and match.end() > start)
                        # 只要有一个出现位置**没被**覆盖，就保留命中：
                        # 与主引擎"每个出现位置都算一次"的语义一致，
                        # 避免在 payload 前面塞个正常字段名就整体免检。
                        if covered and not any(not c for c in covered):
                            return True
                    except Exception:
                        continue
                return False

        # 拿不到原文时退回变体坐标（至少不会崩）
        end = offset + length
        for pattern in excludes:
            try:
                for match in re.finditer(pattern, variant, re.I):
                    if match.start() < end and match.end() > offset:
                        return True
            except Exception:
                continue
        return False

    def _dedupe(self, hits):
        """去重 key 必须含 offset。

        早先是 (source, keyword, rule_id) —— 同一字段里同一个关键词的
        **第二次出现**会被当成重复丢掉。主引擎已把 offset 纳入 key
        （见 engine._dedupe_hits），Burp 副本没跟上。
        """
        seen = set()
        out = []
        for hit in hits:
            key = (hit["source"], hit["keyword"].lower(), hit["rule_id"],
                   hit.get("offset", -1))
            if key in seen:
                continue
            seen.add(key)
            hit.pop("_raw", None)
            hit.pop("_orig", None)
            out.append(hit)
        return out


# ====================================================================
# 沉洞服务器：被拦请求改写到它，返回 403 + JSON
# ====================================================================

class Sinkhole(object):
    def __init__(self, port, log):
        self.port = port
        self.log = log
        self._server = None
        self._thread = None
        self._stop = False
        self.blocked_count = 0
        self._lock = threading.Lock()

    def start(self):
        try:
            self._server = ServerSocket(self.port)
        except Exception as exc:
            self.log("[sinkhole] 端口 %d 绑定失败：%r" % (self.port, exc))
            return False
        self._thread = JavaThread(self._loop)
        self._thread.setDaemon(True)
        self._thread.start()
        self.log("[sinkhole] 已监听 127.0.0.1:%d" % self.port)
        return True

    def stop(self):
        self._stop = True
        try:
            if self._server:
                self._server.close()
        except Exception:
            pass

    def _loop(self):
        while not self._stop:
            try:
                client = self._server.accept()
            except Exception:
                if self._stop:
                    return
                continue
            try:
                self._serve(client)
            except Exception:
                pass
            finally:
                try:
                    client.close()
                except Exception:
                    pass

    def _serve(self, client):
        try:
            client.setSoTimeout(3000)
            stream = client.getInputStream()
            # 读完请求头即可，不需要 body
            buf = []
            total = 0
            while total < 65536:
                b = stream.read()
                if b < 0:
                    break
                total += 1
                if b == 13 or b == 10:
                    if len(buf) >= 4 and buf[-1] == 10 and buf[-2] == 10:
                        break
                    if len(buf) >= 4 and buf[-1] == 10 and buf[-2] == 13 and buf[-3] == 10:
                        break
                buf.append(b)

            payload = json.dumps({
                "success": False,
                "blocked": True,
                "reason": "命中敏感词，请求已被拦截",
                "stage": "burp_extension",
                "hits": [],
                "note": "由 HuntGuard Burp 扩展拦截，请求未到达目标服务器",
            }, ensure_ascii=False, indent=2).encode("utf-8")

            head = ("HTTP/1.1 403 Forbidden\r\n"
                    "Content-Type: application/json; charset=utf-8\r\n"
                    "Content-Length: %d\r\n"
                    "X-HuntGuard: blocked\r\n"
                    "Connection: close\r\n\r\n" % len(payload))  # payload 是 bytes，len 即字节数
            out = client.getOutputStream()
            out.write(head.encode("latin-1"))
            out.write(payload)
            out.flush()
            with self._lock:
                self.blocked_count += 1
        except Exception:
            pass


# ====================================================================
# Burp 扩展主体
# ====================================================================

class BurpExtender(IBurpExtender, IHttpListener, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        callbacks.setExtensionName("HuntGuard")

        # 自动发现安装位置，不依赖硬编码路径
        self.rules_path = discover_rules_path()
        self.sinkhole_port = DEFAULT_SINKHOLE_PORT
        self.block_mode = "sinkhole"
        self.auto_reload = True
        self.report_to_console = True
        self.enabled = True
        self.events = []
        self._events_lock = threading.Lock()

        if self.rules_path:
            self.engine = MiniEngine(self.rules_path, self._log)
            self.engine.load_if_changed(force=True)
        else:
            self.engine = MiniEngine("", self._log)
            self._log("[waf] 未找到规则文件 —— 请在标签页里填入路径，"
                      "或设置环境变量 HUNTGUARD_HOME")

        self.sinkhole = Sinkhole(self.sinkhole_port, self._log)
        self.sinkhole.start()

        self._build_ui()

        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        self._log("[waf] 扩展已加载，规则：%s" % self.rules_path)

    # -------------------------------------------------- 日志

    def _log(self, message):
        line = "[%s] %s" % (time.strftime("%H:%M:%S"), message)
        try:
            print(line)
        except Exception:
            pass
        try:
            with self._events_lock:
                self.events.insert(0, line)
                del self.events[400:]
            SwingUtilities.invokeLater(self._refresh_log)
        except Exception:
            pass

    def _refresh_log(self):
        try:
            self.log_area.setText("\n".join(self.events[:200]))
        except Exception:
            pass

    # -------------------------------------------------- 扫描

    def _request_fields(self, message_info):
        """把 Burp 请求拆成 (fields, url, method)。"""
        request = message_info.getRequest()
        text = self.helpers.bytesToString(request)
        info = self.helpers.analyzeRequest(message_info)
        url = info.getUrl()
        method = info.getMethod()

        headers = info.getHeaders()
        body_offset = info.getBodyOffset()
        # body 必须用**字节**偏移切**字节**数组再解码。
        #
        # 早先是 text[body_offset:] —— getBodyOffset() 返回的是字节
        # 偏移，而 text 是解码后的字符串（Java String）。只要 body 里
        # 有多字节字符（中文），两者下标就对不上：切出来的 body 要么
        # 少几个字符、要么从中间截断。payload 落在 body 开头时直接漏检。
        # 正确做法是在字节域切完再解码（实测发现）。
        try:
            from java.util import Arrays
            raw = request
            n = len(raw)
            if body_offset < 0 or body_offset > n:
                body_offset = n
            body_bytes = Arrays.copyOfRange(raw, body_offset, n)
            body = self.helpers.bytesToString(body_bytes)
        except Exception:
            body = text[body_offset:]

        header_lines = []
        for i in range(1, headers.size()):
            header_lines.append(str(headers.get(i)))

        fields = [
            ("method", str(method)),
            ("host", str(url.getHost())),
            ("url", str(url.toString())),
            ("path", str(url.getPath())),
            ("query", str(url.getQuery() or "")),
            ("body", body),
            ("headers", "\n".join(header_lines)),
        ]
        return fields, str(url.toString()), str(method)

    def processHttpMessage(self, tool_flag, message_is_request, message_info):
        if not message_is_request:
            return
        if not self.enabled:
            return

        try:
            if self.auto_reload:
                self.engine.load_if_changed()

            # 拦截器是否开启：控制台心跳新鲜 且 settings.enabled 不为 false。
            # 与 curl shim / 代理用的是同一套判定 —— 没打开就不拦。
            if not self._intercept_active():
                return

            fields, url, method = self._request_fields(message_info)
            hits, unlocked = self.engine.scan_fields(fields)
            if not hits:
                return

            blocking = [h for h in hits if h.get("action") == "block"]
            mode = self.engine.mode
            will_block = bool(blocking) and mode != "monitor" and not unlocked

            verdict = {
                "success": not will_block,
                "blocked": will_block,
                "reason": ("命中敏感词，请求已被拦截" if will_block
                           else ("命中敏感词（解锁窗口内，已放行并记录）" if unlocked
                                 else "命中敏感词（仅监控规则）")),
                "stage": "burp_extension",
                "hits": hits,
                "url": url,
                "method": method,
                "tool": "burp",
            }

            tool_name = self._tool_name(tool_flag)
            if will_block:
                self._log("[拦截] %s %s  规则=%s" % (
                    method, url[:110],
                    ",".join(sorted(set(h["rule_id"] for h in hits if h.get("rule_id"))))))
                self._apply_block(message_info, verdict, url)
            else:
                self._log("[记录] %s %s" % (method, url[:110]))

            self._report(verdict, tool_name)

        except Exception as exc:
            self._log("[waf] 处理异常：%r" % (exc,))

    def _tool_name(self, tool_flag):
        mapping = {}
        try:
            mapping = {
                self.callbacks.TOOL_PROXY: "burp-proxy",
                self.callbacks.TOOL_REPEATER: "burp-repeater",
                self.callbacks.TOOL_SCANNER: "burp-scanner",
                self.callbacks.TOOL_INTRUDER: "burp-intruder",
                self.callbacks.TOOL_SPIDER: "burp-spider",
                self.callbacks.TOOL_EXTENDER: "burp-extender",
            }
        except Exception:
            pass
        return mapping.get(tool_flag, "burp")

    def _intercept_active(self):
        """拦截器是否已开启 —— 与 curl shim / 代理同一套判定。

        两个条件：
          1. 控制台心跳新鲜（<home>/data/run/active.json 的 mtime 在阈值内）
          2. settings.enabled 不是 false

        环境变量 WAF_ALWAYS_ON=1 可强制开启（不依赖控制台）。
        """
        import os as _os
        import time as _time

        if _os.environ.get("WAF_ALWAYS_OFF") == "1":
            return False
        if _os.environ.get("WAF_ALWAYS_ON") == "1":
            return bool(self.engine.settings.get("enabled", True))
        if not bool(self.engine.settings.get("enabled", True)):
            return False

        hb = self._heartbeat_path()
        if not hb:
            return False
        try:
            age = _time.time() - _os.path.getmtime(hb)
        except OSError:
            return False
        return age <= 20.0

    def _heartbeat_path(self):
        """心跳文件路径。跟随规则文件位置推导，支持环境变量覆盖。"""
        import os as _os
        # 1) 环境变量指定安装目录（两个名字都试）
        home = (_os.environ.get(ENV_HOME)
                or _os.environ.get(ENV_HOME_LEGACY))
        if home:
            candidate = _os.path.join(home, "data", "run", "active.json")
            if _os.path.isfile(candidate):
                return candidate
        # 2) 从规则文件路径推导：<home>/data/rules.json -> <home>/data/run/active.json
        if self.rules_path:
            candidate = _os.path.join(_os.path.dirname(self.rules_path),
                                      "run", "active.json")
            if _os.path.isfile(candidate):
                return candidate
        # 3) 候选目录兜底
        for home in _candidate_homes():
            candidate = _os.path.join(home, "data", "run", "active.json")
            if _os.path.isfile(candidate):
                return candidate
        return None

    def _apply_block(self, message_info, verdict, url):
        """把请求改写到沉洞（或关闭端口），使目标收不到请求。"""
        request = message_info.getRequest()
        info = self.helpers.analyzeRequest(message_info)
        headers = info.getHeaders()
        body_offset = info.getBodyOffset()
        body = self.helpers.bytesToString(request)[body_offset:]
        method = str(info.getMethod())

        # 手工构造发往沉洞的请求，尽量保持原样，只换目标
        keep = []
        for i in range(1, headers.size()):
            line = str(headers.get(i))
            key = line.split(":", 1)[0].lower()
            if key in ("host", "content-length", "connection",
                       "proxy-connection", "accept-encoding"):
                continue
            keep.append(line)

        if self.block_mode == "fail":
            target_port = 1                     # 关闭端口：连接立即失败
            target_host = "127.0.0.1"
            new_headers = ["Host: %s:%d" % (target_host, target_port)] + keep
        else:
            target_port = self.sinkhole_port
            target_host = "127.0.0.1"
            new_headers = ["Host: %s:%d" % (target_host, target_port)] + keep

        try:
            payload = body if isinstance(body, str) else str(body)
            if payload:
                # Content-Length 是**字节**数，不是字符数。
                # 早先用 len(payload)（字符数），body 含中文时长度偏小，
                # 严格的上游会按短长度截断或报错。实测发现（影响小，
                # 因为目标已被改写成沉洞，但既然看到了就修对）。
                try:
                    clen = len(payload.encode("utf-8"))
                except Exception:
                    clen = len(payload)
                new_headers.append("Content-Length: %d" % clen)
        except Exception:
            payload = ""

        new_headers.append("Connection: close")
        head = "%s %s HTTP/1.1\r\n" % (
            method, "http://%s:%d/__agentwaf_blocked" % (target_host, target_port))
        message = self.helpers.buildHttpMessage(new_headers, payload)
        message_info.setRequest(message)

        # 在 Burp 里打标记，便于回看
        try:
            self.callbacks.addToMessageEditorConsoleOutput(
                "HuntGuard 已拦截：%s" % url)
        except Exception:
            pass
        try:
            message_info.setComment("HuntGuard BLOCKED: %s" % (
                ",".join(sorted(set(h["rule_id"] for h in verdict["hits"] if h.get("rule_id"))))))
            message_info.setHighlight("red")
        except Exception:
            pass

    def _report(self, verdict, tool_name):
        """可选：把事件回传到控制台日志库，便于统一查看。"""
        if not self.report_to_console:
            return

        def _worker():
            try:
                from java.net import URL
                from java.io import OutputStreamWriter
                url = URL(_api_base() + "/api/report")
                conn = url.openConnection()
                conn.setRequestMethod("POST")
                conn.setDoOutput(True)
                conn.setConnectTimeout(1200)
                conn.setReadTimeout(1800)
                conn.setRequestProperty("Content-Type",
                                        "application/json; charset=utf-8")
                # 控制台配了 auth_token 时必须带上，否则 /api/report 被
                # 401 拒绝 —— 而且失败是静默的（回传在后台线程里，
                # 异常只进日志），用户会以为"事件没记上"是别的原因。
                # UI 早就支持 token 了（服务端注入 window.__WAF_TOKEN），
                # Burp 这条通道漏了（实测发现）。
                try:
                    tok = self._api_token()
                    if tok:
                        conn.setRequestProperty("X-Auth-Token", tok)
                except Exception:
                    pass
                # 扩展已自行判定，直接回传结论，避免控制台二次扫描产生重复事件
                hits = []
                for hit in verdict.get("hits") or []:
                    hits.append({
                        "source": hit.get("source", ""),
                        "keyword": hit.get("keyword", ""),
                        "matched_text": hit.get("matched_text", ""),
                        "rule_id": hit.get("rule_id", ""),
                        "rule_name": hit.get("rule_name", ""),
                        "severity": hit.get("severity", ""),
                        "action": hit.get("action", ""),
                    })
                payload = json.dumps({
                    "tool": tool_name,
                    "method": verdict.get("method", ""),
                    "url": verdict.get("url", ""),
                    "blocked": verdict.get("blocked", False),
                    "reason": verdict.get("reason", ""),
                    "stage": "burp_extension",
                    "hits": hits,
                }, ensure_ascii=False)
                writer = OutputStreamWriter(conn.getOutputStream(), "UTF-8")
                writer.write(payload)
                writer.flush()
                writer.close()
                conn.getResponseCode()
            except Exception:
                pass                          # 控制台没开就静默跳过

        JavaThread(_worker).start()

    # -------------------------------------------------- UI

    def _build_ui(self):
        self.panel = JPanel(BorderLayout())

        top = JPanel(FlowLayout(FlowLayout.LEFT, 8, 6))
        self.status_label = JLabel("加载中…")
        top.add(self.status_label)
        top.add(JButton("重新加载规则", actionPerformed=self._on_reload))
        top.add(JButton("清空日志", actionPerformed=self._on_clear_log))

        self.enable_box = JCheckBox("启用拦截", True,
                                    actionPerformed=self._on_toggle)
        top.add(self.enable_box)
        self.auto_box = JCheckBox("自动重载规则", True,
                                  actionPerformed=self._on_toggle)
        top.add(self.auto_box)
        self.report_box = JCheckBox("回传控制台日志", True,
                                    actionPerformed=self._on_toggle)
        top.add(self.report_box)

        mid = JPanel(GridLayout(2, 1, 4, 4))
        path_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        path_row.add(JLabel("规则文件："))
        self.path_field = JTextField(self.rules_path, 46)
        path_row.add(self.path_field)
        path_row.add(JButton("应用路径", actionPerformed=self._on_apply_path))
        path_row.add(JButton("自动发现", actionPerformed=self._on_autodiscover))
        mid.add(path_row)

        mode_row = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2))
        mode_row.add(JLabel("拦截方式："))
        self.mode_field = JTextField(self.block_mode, 8)
        mode_row.add(self.mode_field)
        mode_row.add(JLabel("（sinkhole=沉洞返回403 / fail=改到关闭端口）"))
        mode_row.add(JButton("应用", actionPerformed=self._on_apply_mode))
        mid.add(mode_row)

        top_container = JPanel(BorderLayout())
        top_container.add(top, BorderLayout.NORTH)
        top_container.add(mid, BorderLayout.SOUTH)

        self.panel.add(top_container, BorderLayout.NORTH)

        self.log_area = JTextArea(20, 100)
        self.log_area.setEditable(False)
        self.panel.add(JScrollPane(self.log_area), BorderLayout.CENTER)

        bottom = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4))
        bottom.add(JLabel("提示：命中后请求不会到达目标；规则改动后点「重新加载规则」即可生效。"))
        self.panel.add(bottom, BorderLayout.SOUTH)

        self._refresh_status()

    def _refresh_status(self):
        try:
            n = len(self.engine.rules)
            unlocked = self.engine.unlock_remaining()
            text = "规则 %d 条 · 模式 %s · 已拦截 %d 次" % (
                n, self.engine.mode, self.sinkhole.blocked_count)
            if unlocked > 0:
                text += " · ⚠ 解锁中 %.0f 秒（%s）" % (
                    unlocked, self.engine.unlock_reason())
            self.status_label.setText(text)
        except Exception:
            pass

    def _on_reload(self, event):
        self.engine.rules_path = self.path_field.getText().strip()
        self.rules_path = self.engine.rules_path
        self.engine.load_if_changed(force=True)
        self._refresh_status()
        self._log("[waf] 手动重新加载完成：%d 条规则" % len(self.engine.rules))

    def _on_apply_path(self, event):
        self._on_reload(event)

    def _on_autodiscover(self, event):
        """一键重新自动发现安装位置（改过安装目录 / 换机器后用）。"""
        found = discover_rules_path()
        if not found:
            self._log("[waf] 自动发现失败。请手动填路径，或设置环境变量 "
                      "HUNTGUARD_HOME 后重启 Burp")
            return
        self.path_field.setText(found)
        self.engine.rules_path = found
        self.rules_path = found
        self.engine.load_if_changed(force=True)
        self._log("[waf] 自动发现成功：%s（%d 条规则）"
                  % (found, len(self.engine.rules)))
        self._refresh_status()

    def _on_apply_mode(self, event):
        value = self.mode_field.getText().strip().lower()
        if value not in ("sinkhole", "fail"):
            self._log("[waf] 拦截方式只能是 sinkhole 或 fail")
            return
        self.block_mode = value
        self._log("[waf] 拦截方式已切换为 %s" % value)

    def _on_toggle(self, event):
        self.enabled = self.enable_box.isSelected()
        self.auto_reload = self.auto_box.isSelected()
        self.report_to_console = self.report_box.isSelected()
        self._log("[waf] 启用=%s 自动重载=%s 回传=%s" %
                  (self.enabled, self.auto_reload, self.report_to_console))

    def _on_clear_log(self, event):
        with self._events_lock:
            self.events = []
        self._refresh_log()

    # -------------------------------------------------- ITab

    def getTabCaption(self):
        return "HuntGuard"

    def getUiComponent(self):
        return self.panel
