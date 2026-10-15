# -*- coding: utf-8 -*-
"""核心判定引擎：加载规则 → 归一化 → 匹配 → 生成 Verdict。

设计要点
--------
* 热重载：按 rules.json 的 mtime/size 变化自动重载，UI 改规则立即生效。
* 多源扫描：url / path / query / body / headers / method / host / raw_cmd。
* 多轮归一化：URL 解码、HTML 反转义、Unicode 转义、全角折叠、去隐藏字符、
  去分隔符压缩 —— 覆盖 `de%6cete`、`d_e l e t e`、`delete/**/` 之类绕过。
* 误报抑制：命中点 ±WINDOW 字符内若匹配 rule.exclude 则丢弃该命中。
* 放行名单：source 维度正则；命中则整个 source 跳过（记入 suppressed）。
* 解锁窗口：settings.unlock_until 之前命中降级为记录，不拦截。
* fail_mode=closed：引擎内部异常时默认拦截（护栏工具应偏保守），
  并在 reason 中说明是引擎故障，避免"静默放行"。
"""

import os
import re
import sys
import threading
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

from . import config, rules as rules_mod
from . import logstore
from .models import (ALL_SOURCES, SEVERITY_ORDER, Hit, ScanTarget, Verdict,
                     WafBlocked)

EXCLUDE_WINDOW = 24          # 误报抑制的上下文窗口（字符）
MAX_MATCHED_TEXT = 400       # matched_text 截断长度

_engine_lock = threading.RLock()


class RuleEngine(object):
    def __init__(self, rules_path=None, logger=None):
        self.rules_path = rules_path or config.rules_path()
        self._doc = None
        self._compiled = []          # [(rule_dict, [compiled_regex], [compiled_exclude])]
        self._allowlist = []         # [(entry, compiled)]
        self._settings = {}
        self._rejected_regexes = []       # 被 ReDoS 防护停用的规则正则
        self._rejected_allow_regexes = []  # 同上，放行名单里的
        self._stamp = None           # (mtime, size)
        self._lock = threading.RLock()
        self._logger = logger
        self.load(force=True)

    # ------------------------------------------------------------ 加载

    def _stamp_of(self):
        try:
            st = os.stat(self.rules_path)
            return (st.st_mtime, st.st_size)
        except OSError:
            return None

    def load(self, force=False):
        """按需重载；返回是否真的重载了。"""
        stamp = self._stamp_of()
        if not force and stamp is not None and stamp == self._stamp:
            return False
        with self._lock:
            doc = rules_mod.load_document(self.rules_path)
            self._doc = doc
            self._settings = doc.get("settings") or {}
            self._compiled = self._compile_rules(doc.get("rules") or [])
            self._allowlist = self._compile_allowlist(doc.get("allowlist") or [])
            self._stamp = self._stamp_of()
        if self._logger:
            self._logger("engine reloaded: %d rules, %d allowlist" %
                         (len(self._compiled), len(self._allowlist)))
        return True

    def reload_if_changed(self):
        return self.load(force=False)

    @property
    def _regex_flags(self):
        """正则编译标志：受 settings.case_sensitive 控制。

        默认（不敏感）行为保持 re.I；开了 case_sensitive 就不加，
        与归一化去掉 lower 保持一致 —— 两边必须同时改，
        只改一边等于开关失效（详见 _scan_inner 里的注释）。
        """
        try:
            if bool(self._settings.get("case_sensitive", False)):
                return 0
        except Exception:
            pass
        return re.I

    def _compile_rules(self, raw_rules):


        compiled = []
        rejected = []

        # ReDoS 防护：病态正则会让每个请求卡死在匹配里（实测
        # (a+)+$ 对 27 字符输入耗时 4.7 秒，更极端的直接挂住进程）。
        # 规则可以由用户在 UI 里添加，所以必须在编译期挡住。
        #
        # 关键：**批量**探测，不要逐条调 check_pattern。
        # 逐条会给每条正则起一个子进程（约 0.3s），156 条就是 50 秒 ——
        # 而 _compile_rules 在每次 curlshim / 代理 / guard 启动时都跑，
        # 实测把单次 curl 从 0.2s 拖到 54s。批量版一次解释器走完
        # 全部正则（实测 0.27s）。
        all_patterns = []
        for rule in raw_rules:
            if rule.get("enabled", True):
                all_patterns.extend(rule.get("regex") or [])
                all_patterns.extend(rule.get("exclude") or [])
        try:
            from .regexguard import check_patterns as _check_patterns
            unsafe = _check_patterns(all_patterns)
        except Exception:
            unsafe = {}                # 探测不可用 → 保守放行

        for rule in raw_rules:
            if not rule.get("enabled", True):
                continue
            # 被拒的正则单独跳过，不影响同一条规则里的其它正则
            raw_regexes = []
            for pattern in (rule.get("regex") or []):
                reason = unsafe.get(pattern)
                if reason:
                    rejected.append((rule.get("id", "?"), pattern, reason))
                    continue
                raw_regexes.append(pattern)
            raw_excludes = []
            for pattern in (rule.get("exclude") or []):
                reason = unsafe.get(pattern)
                if reason:
                    rejected.append((rule.get("id", "?"), pattern, reason))
                    continue
                raw_excludes.append(pattern)
            try:
                # case_sensitive 开关必须真的生效。
                #
                # 早先这里硬编码 re.I，同时归一化里又带 lower —— 两个
                # 动作叠加的结果是：不管用户怎么设置 case_sensitive，
                # 匹配永远忽略大小写。开关形同虚设（实测发现的问题）。
                # 现在只有在"不敏感"（默认）时才加 re.I；开了敏感模式
                # 就交给归一化不要 lower、正则也不加 re.I，
                # 两边保持一致。
                regexes = [re.compile(p, self._regex_flags)
                           for p in raw_regexes]
                excludes = [re.compile(p, self._regex_flags)
                            for p in raw_excludes]
            except re.error:
                continue
            keywords = [str(k) for k in (rule.get("keywords") or []) if str(k).strip()]
            if not keywords and not regexes:
                continue
            compiled.append((rule, regexes, excludes, keywords))

        if rejected:
            self._rejected_regexes = rejected
            try:
                # 只提示一次，避免热重载刷屏
                if not getattr(self, "_reject_warned", False):
                    sys.stderr.write(
                        "[agent-waf] 以下正则因疑似灾难性回溯被停用"
                        "（规则其余部分仍然生效）：\n")
                    for rid, pattern, reason in rejected:
                        sys.stderr.write("  %s %s → %s\n"
                                         % (rid, pattern[:70], reason))
                    self._reject_warned = True
            except Exception:
                pass
        # critical/high 优先，保证 hits 顺序稳定可读
        compiled.sort(key=lambda item: SEVERITY_ORDER.get(item[0].get("severity", "medium"), 99))
        return compiled

    def _compile_allowlist(self, entries):
        """编译白名单条目。

        加载时也要过 ReDoS 检查（实测发现的缺口）：
        保存路径（rules.upsert_allow）会调 check_redos，但
        **手工编辑 rules.json** 或用 ``rules_file`` 指向团队共享规则集时
        走不到那里 —— 一条病态 allowlist.pattern 会被直接编译，
        然后**在每个字段上跑**（触发频率比 rule.regex 还高）。
        探测结果有磁盘缓存，正常情况这里几乎零开销。
        """
        out = []
        rejected = []
        for entry in entries:
            if not entry.get("enabled", True):
                continue
            pattern = entry.get("pattern")
            if not isinstance(pattern, str) or not pattern:
                continue
            try:
                from .regexguard import check_patterns as _check_patterns
                unsafe = _check_patterns([pattern])
            except Exception:
                unsafe = {}
            if pattern in unsafe:
                rejected.append((entry.get("id", "?"), pattern,
                                 unsafe[pattern]))
                continue
            try:
                out.append((entry, re.compile(pattern, self._regex_flags)))
            except (re.error, KeyError):
                continue
        if rejected:
            try:
                if not getattr(self, "_reject_warned", False):
                    sys.stderr.write(
                        "[agent-waf] 以下放行名单正则因疑似灾难性回溯"
                        "被停用：\n")
                    for rid, pattern, reason in rejected:
                        sys.stderr.write("  %s %s → %s\n"
                                         % (rid, pattern[:70], reason))
                    self._reject_warned = True
            except Exception:
                pass
        # 记录下来，便于 UI / 自测查看（与 _rejected_regexes 同样的约定）
        self._rejected_allow_regexes = rejected
        return out

    # ------------------------------------------------------------ 属性

    @property
    def doc(self):
        self.reload_if_changed()
        return self._doc

    @property
    def settings(self):
        self.reload_if_changed()
        return self._settings

    @property
    def rules(self):
        self.reload_if_changed()
        return (self._doc or {}).get("rules") or []

    def mode(self):
        return str(self.settings.get("mode", "block")).lower()

    def enabled(self):
        """用户意图开关。False 表示"我主动暂停了拦截"。"""
        value = self.settings.get("enabled", True)
        if isinstance(value, str):
            return value.strip().lower() not in ("0", "false", "no", "off", "")
        return bool(value)

    def set_enabled(self, enabled):
        # 走 update_document（读-改-写整段在同一把跨进程锁里）。
        # 原来是自己 load + save —— 控制台与独立 wafctl 并发时后写者
        # 整体覆盖前者（实测丢失更新，见 rules.update_document 的说明）。
        def _mutate(doc):
            doc.setdefault("settings", {})["enabled"] = bool(enabled)
            return bool(enabled)

        result = rules_mod.update_document(_mutate, self.rules_path)
        self.load(force=True)
        return result

    def unlock_remaining(self):
        """返回解锁剩余秒数（0 表示未解锁）。"""
        until = float(self.settings.get("unlock_until") or 0)
        remaining = until - time.time()
        return max(0.0, remaining)

    def set_unlock(self, minutes, reason=""):
        until = time.time() + float(minutes) * 60.0

        def _mutate(doc):
            settings = doc.setdefault("settings", {})
            settings["unlock_until"] = until
            settings["unlock_reason"] = str(reason or "")
            return until

        result = rules_mod.update_document(_mutate, self.rules_path)
        self.load(force=True)
        return result

    def clear_unlock(self):
        def _mutate(doc):
            settings = doc.setdefault("settings", {})
            settings["unlock_until"] = 0
            settings["unlock_reason"] = ""

        rules_mod.update_document(_mutate, self.rules_path)
        self.load(force=True)

    # ------------------------------------------------------------ 扫描

    def scan(self, target: ScanTarget, log=True) -> Verdict:
        """扫描一个目标，返回 Verdict。"""
        started = time.time()
        try:
            self.reload_if_changed()
            if self._is_self_endpoint(target):
                # WAF 自己的控制台接口不检查。
                # 为什么必须豁免：那些 API 路径本身就带敏感词 ——
                # /api/shutdown、/api/rules/delete、/api/events/clear。
                # 不豁免的话会拦掉自己：实测 `curl .../api/shutdown`
                # 被 R-102 的 shutdown 规则拦下，控制台关不掉。
                verdict = Verdict(
                    blocked=False,
                    reason="WAF 自身控制台接口，跳过检测",
                    stage="self_endpoint",
                    hits=[],
                    target=target.summary(),
                    tool=target.tool,
                    method=target.method,
                )
                return verdict
            verdict = self._scan_inner(target)
        except Exception:
            # fail_mode: closed=拦截 open=放行
            fail_mode = "closed"
            try:
                fail_mode = str(self._settings.get("fail_mode", "closed")).lower()
            except Exception:
                pass
            blocked = fail_mode != "open"
            verdict = Verdict(
                blocked=blocked,
                reason=("WAF 引擎异常，按 fail_mode=%s 处理" % fail_mode) if blocked
                       else "WAF 引擎异常，已放行",
                stage="engine_error",
                hits=[],
                mode="block",
                target=target.summary(),
                tool=target.tool,
            )
            verdict.error = traceback.format_exc()[-2000:]
        verdict.duration_ms = (time.time() - started) * 1000.0
        verdict.target = verdict.target or target.summary()
        verdict.tool = verdict.tool or target.tool
        verdict.method = verdict.method or target.method
        verdict.mode = self.mode()
        verdict.unlocked = self.unlock_remaining() > 0
        if log and self._should_log(verdict):
            logstore.add_event(verdict, tool=target.tool)
        return verdict

    def _is_self_endpoint(self, target):
        """判断目标是不是 WAF 控制台自己的接口。

        为什么必须豁免：控制台的 API 路径本身就含敏感词 ——
        ``/api/shutdown``、``/api/rules/delete``、``/api/events/clear``。
        不豁免会把工具自己的管理调用拦掉（实测：``curl .../api/shutdown``
        被 R-102 的 shutdown 规则拦住，控制台关不掉）。

        判据（三个都要满足）：
          1. 主机是回环
          2. 端口等于**控制台实际监听的端口**
          3. 路径以 /api/ 开头（或就是根路径 /）

        端口必须取自**心跳文件**而不是配置（实测发现）：
        控制台可以用 ``HUNTGUARD_PORT=9895`` 起，此时 config.json 里
        仍写着 8898、心跳文件里记的才是 9895（实测本机就是这种状态）。
        只读 config 的话会两头出错 ——
          * 真有靶场占 8898 → 被误当成控制台豁免掉
          * 控制台自己在 9895 的 API 调用 → 不豁免，自己拦自己

        路径判据是为了收窄：只豁免我们自己的接口，而不是"这个端口上
        什么都放行"。万一靶场恰好也在同一个端口（端口冲突时可能发生），
        路径对不上就不会被豁免。
        """
        # 拿候选端口：控制台在跑就用**它实际监听的端口**（心跳文件里记的），
        # 没在跑才退回配置里的端口。
        #
        # 为什么不能两个都收（实测踩过）：控制台用 HUNTGUARD_PORT=9895 起、
        # config.json 里仍写 8898 时，两个端口都进候选集的话 ——
        # 一个恰好跑在 8898 的靶场会被当成控制台豁免掉。
        api_ports = set()
        live_port = None
        try:
            from . import state as _state
            live = _state.read() or {}
            if live.get("port"):
                live_port = int(live["port"])
        except Exception:
            live_port = None
        if live_port:
            api_ports.add(live_port)
        else:
            try:
                cfg = config.load_config()
                api_ports.add(int(cfg.get("api_port", config.API_PORT)))
            except Exception:
                pass
        if not api_ports:
            return False

        # 路径必须是控制台自己的接口
        path = (target.path or "").strip()
        if path and not (path.startswith("/api/") or path == "/"):
            return False

        loopback = {"127.0.0.1", "localhost", "::1"}
        is_https = bool(target.url) and target.url.lower().startswith("https://")

        candidates = []
        if target.host:
            candidates.append(target.host)
        if target.url:
            try:
                from urllib.parse import urlsplit
                netloc = urlsplit(target.url).netloc
                if netloc:
                    candidates.append(netloc)
            except Exception:
                pass

        for candidate in candidates:
            # 支持 [::1]:8898 形式
            if candidate.startswith("["):
                host, _, rest = candidate[1:].partition("]")
                port = rest.lstrip(":").strip()
            else:
                host, _, port = candidate.rpartition(":")
                if not port.isdigit():
                    host, port = candidate, ""
            host = host.strip("[]").lower()
            if host not in loopback:
                continue
            if port.isdigit():
                effective_port = int(port)
            else:
                # 没写端口 = 默认端口。控制台通常不在默认端口上，
                # 所以这种情况一般不豁免（保护 127.0.0.1 上的靶场）。
                effective_port = 443 if is_https else 80
            if effective_port in api_ports:
                return True
        return False

    def _should_log(self, verdict):
        """未拦截的请求默认不落库，避免代理模式把日志库灌满。"""
        if verdict.blocked:
            return True
        if verdict.hits:
            return True                    # 有命中（监控规则/解锁窗口）：记下来
        try:
            return bool(self._settings.get("log_allowed", False))
        except Exception:
            return False

    def _scan_inner(self, target: ScanTarget) -> Verdict:
        settings = self._settings
        case_sensitive = bool(settings.get("case_sensitive", False))
        # 大小写敏感时不能再做 lower 归一化 —— 否则关键词侧不做 lower、
        # 文本侧却已经小写化，敏感模式永远匹配不到大写写法，
        # 开关等于没用（同 re.I 那个问题的一体两面）。
        ops = [op for op in (settings.get("normalize") or [])]
        if case_sensitive:
            ops = [op for op in ops if op != "lower"]
            if not ops:
                ops = ["url_decode"]
        elif not ops:
            ops = ["url_decode", "lower"]
        scan_headers = bool(settings.get("scan_headers", True))
        global_mode = str(settings.get("mode", "block")).lower()
        unlocked = self.unlock_remaining() > 0

        hits: List[Hit] = []
        suppressed: List[Dict[str, Any]] = []

        # 请求级放行：source=url/host 的条目命中后跳过检查。
        #
        # 但有多个 URL 时**不能**整个请求免检（实测发现的绕过）：
        #     curl <白名单URL> --next http://victim/delete
        # 第一条命中白名单就 return 的话，第二个 URL 上的 delete
        # 完全看不见。多 URL 是 curl 的正常能力（--next 分隔多组参数）。
        #
        # 判据：目标里所有 URL（target.meta["urls"]，由 curlshim 收集）
        # **每一条**都命中白名单才跳过；只要有一条不在白名单里，
        # 就继续正常扫描（raw_cmd 会把第二个 URL 一并扫到）。
        all_urls = []
        try:
            all_urls = list((target.meta or {}).get("urls") or [])
        except Exception:
            all_urls = []
        request_allow = self._request_level_allow(target)
        if request_allow is not None:
            # 除了"所有 URL 都在白名单"，还要检查 **--connect-to/--resolve
            # 改写出的真实主机**是否也在白名单里。
            #
            # 为什么：URL 写着白名单主机、实际连到别处时，只看 URL 会被骗：
            #   curl --connect-to 127.0.0.1:8898:evil.com:443 \
            #        http://127.0.0.1:8898/delete
            # URL 与白名单完全匹配（本机靶场放行），但流量去 evil.com。
            real_hosts = []
            # 真实主机按 **host 源**单独判一次，而不是拼成 "//evil.com"
            # 再走 url 匹配（实测发现）：拼出来的字符串能命中
            # `127\.0\.0\.1[:/].*` 这类宽正则，但对 host 锚定的白名单
            # （如 `^evil\.com$`）永远不命中 —— 方向是 fail-closed
            # （宁可多拦），但判据不干净。现在先按 host 源判，
            # 没配 host 源条目时再退回 url 形式兜底。
            try:
                real_hosts = list((target.meta or {}).get("real_hosts") or [])
            except Exception:
                real_hosts = []
            host_mismatch = []
            for h in real_hosts:
                if not h:
                    continue
                if self._host_allowed_any(h):
                    continue
                if self._url_allowed_any("//" + h):
                    continue
                host_mismatch.append(h)
            extra = [u for u in all_urls
                     if u and u != target.url
                     and not self._url_allowed_any(u)]
            if not extra and not host_mismatch:
                suppressed.append({
                    "source": "request",
                    "keyword": request_allow.get("pattern", ""),
                    "matched_text": (target.url or target.host)[:MAX_MATCHED_TEXT],
                    "reason": "allowlist",
                    "allow_id": request_allow.get("id", ""),
                    "note": request_allow.get("note", ""),
                })
                return Verdict(blocked=False, reason="命中放行名单，已跳过检查",
                               stage="content_scan", hits=[], suppressed=suppressed,
                               mode=global_mode, unlocked=unlocked)
            # 有 URL 不在白名单里 → 不豁免，继续扫（raw_cmd 会带出它们）

        for source, raw_text in target.fields():
            if source == "headers" and not scan_headers:
                continue
            if not raw_text:
                continue
            limit = int(settings.get("max_scan_bytes") or 262144)
            text = raw_text[:limit]

            # 放行名单按**命中点**抑制，而不是跳过整个字段。
            #
            # 为什么不能整字段跳过（曾被利用）：默认白名单 A-002 是
            # source=any 的 deleted_at|is_deleted 这类软删除字段名。
            # 整字段跳过的语义 = body 里出现任何一个正常业务字段名，
            # 整个 body 就免检 —— 于是
            #     POST /api {"deleted_at":null,"action":"delete","id":9}
            # 直接放行。用户开的白名单本意是"别为这个字段名报警"，
            # 不是"这个字段以后什么都别查了"。
            #
            # 现在改成：只有命中位置**落在被放行片段内**才抑制。
            # 硬编码在源码里的字段名本身仍然不报警（白名单的目的），
            # 但同一个字段里另外出现 delete 照样拦。
            allow_spans = self._allow_spans(source, text)
            source_hits = self._match_source(source, text, ops, case_sensitive)
            if allow_spans:
                kept = []
                for hit in source_hits:
                    if self._hit_in_allow_spans(hit, allow_spans, text):
                        suppressed.append({
                            "source": source,
                            "keyword": hit.keyword,
                            "matched_text": hit.matched_text,
                            "reason": "allowlist",
                            "allow_id": self._allow_id_for(hit, allow_spans, text),
                        })
                        continue
                    kept.append(hit)
                source_hits = kept
            hits.extend(source_hits)

        # 按严重级别 + 规则顺序稳定排序
        hits.sort(key=lambda h: (SEVERITY_ORDER.get(h.severity, 99), h.rule_id))

        if not hits:
            return Verdict(blocked=False, reason="未命中敏感词",
                           stage="content_scan", hits=[], mode=global_mode,
                           unlocked=unlocked)

        blocking = [h for h in hits if h.action == "block"]
        if global_mode == "monitor":
            reason = "命中敏感词（全局只读模式，仅记录）"
            blocked = False
        elif unlocked:
            reason = "命中敏感词（解锁窗口内，已放行并记录）"
            blocked = False
        elif blocking:
            reason = "命中敏感词，请求已被拦截"
            blocked = True
        else:
            reason = "命中敏感词（仅监控规则）"
            blocked = False

        return Verdict(blocked=blocked, reason=reason, stage="content_scan",
                       hits=hits, suppressed=suppressed, mode=global_mode,
                       unlocked=unlocked)

    def _host_allowed_any(self, host):
        r"""这个主机名是否命中任一条 **source=host** 的白名单。

        与 _url_allowed_any 的区别：那条把值当"完整 URL 片段"去匹配
        （适合 ^https?://lab\.local/ 这种），这条只看主机名字段，
        让 `^evil\.com$` 这类锚定写法能正常工作。
        """
        if not host:
            return False
        name = host.split(":")[0].strip().lower()
        if not name:
            return False
        for entry, regex in self._allowlist:
            if str(entry.get("source") or "any") != "host":
                continue
            try:
                if regex.search(name):
                    return True
            except Exception:
                continue
        return False

    def _url_allowed_any(self, url):
        """这个 URL 是否命中任一条 url/host 类型的白名单。"""
        if not url:
            return False
        for entry, regex in self._allowlist:
            if str(entry.get("source") or "any") not in ("url", "host"):
                continue
            try:
                if regex.search(url):
                    return True
            except Exception:
                continue
        return False

    def _request_level_allow(self, target):
        """source=url 或 host 的放行条目：命中则跳过检查。

        只对真正的 URL/主机名生效，避免 body 里的字段名意外放开整个请求。

        注意：调用方（_scan_inner）还要确认**所有** URL 都在白名单里
        才会真的跳过 —— 单看第一条会让 `curl <白名单> --next <攻击URL>`
        绕过（见 _scan_inner 里的说明）。
        """
        candidates = []
        if target.url:
            candidates.append(target.url)
        elif target.host:
            candidates.append(target.host)
        if not candidates:
            return None
        for entry, regex in self._allowlist:
            if str(entry.get("source") or "any") not in ("url", "host"):
                continue
            for text in candidates:
                if regex.search(text):
                    return entry
        return None

    def _allow_spans(self, source, text):
        """字段级放行条目的命中区间 [(start, end, entry)]。

        与 _request_level_allow 的区别：那个是"整个请求免检"（用于
        本机靶场这种明确意图），这里的语义是"报这几个词别管"，
        只抑制落在区间内的命中。
        """
        spans = []
        if not self._allowlist:
            return spans
        for entry, regex in self._allowlist:
            entry_source = str(entry.get("source") or "any")
            if entry_source in ("url", "host"):
                continue                       # 已在请求级处理
            if entry_source not in ("any", source):
                continue
            for m in regex.finditer(text):
                if m.end() > m.start():
                    spans.append((m.start(), m.end(), entry))
        return spans

    @staticmethod
    def _hit_in_allow_spans(hit, spans, text):
        """命中位置是否落在某个放行区间内。

        判据是**严格包含**（命中区间与放行区间有重叠），不做邻近容差。

        为什么不再需要容差（实测发现过"邻近豁免"问题）：
        早先这里有个 ``abs(offset - start) <= 3`` 的兜底，理由是
        "归一化会改变长度、offset 可能偏几个字符"。但现在命中 offset
        已经通过 normalize 的 index_map **翻译回原文坐标**
        （见 _map_offset），而 allow_spans 本来就是在原文上算的 ——
        两边同一套坐标系，不需要容差。

        留着容差的坏处是实打实的：命中点只要离白名单片段起点 3 字符内
        就会被一起抑制，等于把"整字段豁免"换成了"邻近豁免"，
        攻击者可以在白名单字段名后面紧挨着写敏感词。
        点号/下划线这类分隔符正好 1 个字符，3 字符容差能盖住
        ``deleted_at.delete`` 这种写法。
        """
        offset = getattr(hit, "offset", -1)
        if offset < 0:
            return False
        length = max(len(getattr(hit, "keyword", "") or ""), 1)
        end = offset + length
        for start, stop, _entry in spans:
            # 区间重叠即算（含端点相切）
            if start < end and stop > offset:
                return True
        return False

    @staticmethod
    def _allow_id_for(hit, spans, text):
        """这条命中是被哪个白名单条目抑制的（用于日志追溯）。"""
        offset = getattr(hit, "offset", -1)
        for start, stop, entry in spans:
            if offset < 0 or start <= offset < stop:
                return entry.get("id", "")
        return spans[0][2].get("id", "") if spans else ""

    def _allow_match(self, source, text):
        """字段级放行：兼容旧调用，返回是否**整段**被放行。

        保留是为了不破坏外部调用方；内部扫描已改用 _allow_spans。
        """
        spans = self._allow_spans(source, text)
        if not spans:
            return None
        start, stop, entry = spans[0]
        if start <= 0 and stop >= len(text):
            return entry
        return None

    def _match_source(self, source, text, ops, case_sensitive):
        from .normalize import build_variants_with_map

        # 变体携带 index_map：命中位置要能翻译回原文。
        # 不带映射直接用归一化 offset 会导致 matched_text 错位，
        # 并让 exclude / 白名单按错误位置判断（误拦+漏拦双向）。
        variants = build_variants_with_map(text, ops)
        if not variants:
            return []

        hits = []
        for rule, regexes, excludes, keywords in self._compiled:
            rule_sources = rule.get("sources") or ALL_SOURCES
            if source not in rule_sources:
                continue
            match_mode = rule.get("match_mode", "substring")
            rule_hits = []
            kept_hits = []

            # 关键词与正则都参与匹配：match_mode 只决定关键词的匹配方式。
            # 这样"关键词兜底 + 正则精确"可以同时存在，避免漏拦。
            if rule.get("keywords"):
                rule_hits.extend(self._match_keyword_rule(
                    source, text, rule, keywords, variants, match_mode, case_sensitive))
            if regexes:
                rule_hits.extend(self._match_regex_rule(source, text, rule,
                                                        regexes, variants))

            for hit in rule_hits:
                if self._is_excluded(text, hit, excludes):
                    continue
                kept_hits.append(hit)
            # 去重必须在**排除之后**做。
            #
            # 曾经的 bug（可被利用）：_dedupe_hits 按
            # (source, keyword, rule_id) 去重，而排除过滤在其后。
            # 于是 body 里先出现的 `deleted_at`（被 exclude 正确抑制）
            # 会把同一关键词后面那个真命中一起吃掉：
            #     {"deleted_at":null,"action":"delete"}
            #          ↑ offset 2 被 exclude 掉，却在去重表里占位，
            #            offset 29 的真 delete 被当成重复丢弃 → 整个 body 放行
            # 只要在 payload 前面塞一个正常业务字段名，就等于给自己
            # 开了免检。现在先排除、再去重，留下的必然是"未被抑制"的命中。
            deduped = _dedupe_hits(kept_hits)
            hits.extend(deduped)
        return hits

    def _match_keyword_rule(self, source, text, rule, keywords, variants,
                            match_mode, case_sensitive):
        """在一个字段的每个归一化变体上找关键词，**每个出现位置都算一次命中**。

        早先只取第一个出现位置（``haystack.find``），配合"按关键词去重"
        就产生了一个可被利用的盲区：
            {"deleted_at":null,"action":"delete"}
        `delete` 第一次出现在 `deleted_at` 里（会被 exclude 正确抑制），
        于是后面那个真正的 delete 永远不会被检查 —— 在 payload 前面
        塞一个正常业务字段名就等于免检。现在遍历全部出现位置。

        offset 一律**翻译回原文**（用变体的 index_map），这样
        matched_text、exclude 窗口、白名单区间判断都基于同一套坐标。
        """
        hits = []
        for label, variant, index_map in variants:
            haystack = variant if case_sensitive else variant.lower()
            for keyword in keywords:
                needle = keyword if case_sensitive else keyword.lower()
                if not needle:
                    continue
                if match_mode == "word":
                    pattern = r"(?<![a-z0-9_])" + re.escape(needle) + r"(?![a-z0-9_])"
                    starts = [m.start() for m in re.finditer(pattern, haystack)]
                else:
                    starts = []
                    pos = haystack.find(needle)
                    while pos >= 0:
                        starts.append(pos)
                        pos = haystack.find(needle, pos + 1)
                for pos in starts:
                    offset = _map_offset(index_map, pos, len(needle))
                    hits.append(Hit(
                        source=source,
                        keyword=keyword,
                        matched_text=_snippet(text, offset, len(needle)),
                        rule_id=rule.get("id", ""),
                        rule_name=rule.get("name", ""),
                        severity=rule.get("severity", "medium"),
                        action=rule.get("action", "block"),
                        field_name=label,
                        offset=offset,
                    ))
        return _dedupe_hits(hits)

    def _match_regex_rule(self, source, text, rule, regexes, variants=None):
        """正则匹配。沿用调用方给的（带 index_map 的）变体，保证 offset 一致。

        早先这里自己重建了一套不带映射的变体，于是正则命中的 offset
        与关键词命中的坐标不统一：matched_text 显示错位、
        exclude/白名单按错误位置判断。现在统一用同一批变体。
        """
        if variants is None:
            from .normalize import build_variants_with_map
            ops = list(self._settings.get("normalize") or [])
            if self._regex_flags == 0:
                # 大小写敏感模式：与 _scan_inner 保持一致，不做 lower
                ops = [op for op in ops if op != "lower"] or ["url_decode"]
            variants = build_variants_with_map(text, ops)

        hits = []
        for label, value, index_map in variants:
            for regex in regexes:
                try:
                    for found in regex.finditer(value):
                        length = max(1, found.end() - found.start())
                        # 正则常跨多个归一化字符（rm\\s+-rf），
                        # 用整段范围换算回原文，避免只映射首字符导致长度不对
                        offset = _map_offset(index_map, found.start(), length)
                        span_end = _map_offset(index_map, found.end() - 1, 1)
                        hits.append(Hit(
                            source=source,
                            keyword=found.group(0)[:120],
                            matched_text=_snippet(
                                text, offset,
                                max(length, span_end - offset + 1)),
                            rule_id=rule.get("id", ""),
                            rule_name=rule.get("name", ""),
                            severity=rule.get("severity", "medium"),
                            action=rule.get("action", "block"),
                            field_name=label,
                            offset=offset,
                        ))
                except Exception:
                    continue
        return _dedupe_hits(hits)

    def _is_excluded(self, text, hit, excludes):
        """命中是否被 exclude 抑制。

        语义是"这个**词**属于白名单语境"，不是"附近有这个词就行"。
        早先用 ±24 字符窗口，于是
            {"deleted_at":null,"action":"delete","id":9}
        里的 delete 因为离 deleted_at 有 20 多字符而被一起放过 ——
        攻击者只要在 payload 前面塞一个正常业务字段名就能免疫。
        实际上 exclude 列的本来就是"跟敏感词长得很像的正常标识符"
        （deleted_at / undelete / can_delete），它们的特征是
        **把敏感词包在里面**，所以判据应该是"exclude 片段覆盖了这个
        命中的位置"，而不是"距离近"。
        """
        if not excludes:
            return False

        offset = getattr(hit, "offset", -1)
        if offset < 0:
            return False
        length = max(len(getattr(hit, "keyword", "") or ""), 1)
        hit_start, hit_end = offset, offset + length

        for regex in excludes:
            # 先看窗口内有没有 exclude 片段（窗口只用于缩小搜索范围，
            # 不再直接当作"命中"依据）
            win_start = max(0, hit_start - EXCLUDE_WINDOW)
            win_end = min(len(text), hit_end + EXCLUDE_WINDOW)
            window = text[win_start:win_end]
            for m in regex.finditer(window):
                ex_start = win_start + m.start()
                ex_end = win_start + m.end()
                # 仅当 exclude 片段覆盖命中点，或与命中段重叠时才抑制。
                # `deleted_at` 覆盖 delete（2..12 包住 2..8）→ 抑制 ✓
                # `deleted_at` 与后面的 action=delete（14..28）不重叠 → 不抑制 ✓
                if ex_start <= hit_start and ex_end >= hit_end:
                    return True
                if ex_start < hit_end and ex_end > hit_start:
                    return True
        return False


def _map_offset(index_map, pos, length=1):
    """把归一化文本里的位置翻译回**原文**位置。

    归一化会改变长度（url_decode 变短、compact 删字符），所以
    "在归一化文本里发现命中"必须换算才能拿去切原文 / 判断 exclude。
    早先直接用归一化 offset，实测导致
    ``?deleted_at=2024-01-01`` 本该放行却被拦（compact 变体上的
    offset 13 在原文里指向完全不同的位置）。

    映射不到（越界）时退回原值，保证不会抛异常打断扫描。
    """
    if not index_map:
        return pos
    if pos < 0:
        return 0
    if pos < len(index_map):
        return index_map[pos]
    return index_map[-1] + max(0, pos - (len(index_map) - 1))


def _snippet(text, offset, length):
    if offset < 0:
        return text[:MAX_MATCHED_TEXT]
    start = max(0, offset - 20)
    end = min(len(text), offset + max(length, 1) + 20)
    piece = text[start:end]
    if len(piece) > MAX_MATCHED_TEXT:
        piece = piece[:MAX_MATCHED_TEXT] + "..."
    return piece


def _dedupe_hits(hits):
    """同一位置、同一关键词、同一规则只留一条。

    键里带 offset 是必须的：同一个关键词在一个字段里出现多次
    （`?a=delete&b=delete`）时，只留第一条会让"第一条被 exclude 抑制"
    的情况连累第二条 —— 必须先按位置区分，再交给排除过滤各自判断。
    """
    seen = set()
    out = []
    for hit in hits:
        key = (hit.source, hit.keyword.lower(), hit.rule_id,
               getattr(hit, "offset", -1))
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    return out


# ------------------------------------------------------------ 全局单例

_ENGINE: Optional[RuleEngine] = None


def get_engine(rules_path=None) -> RuleEngine:
    global _ENGINE
    with _engine_lock:
        if _ENGINE is None:
            _ENGINE = RuleEngine(rules_path)
        else:
            _ENGINE.reload_if_changed()
        return _ENGINE
