# -*- coding: utf-8 -*-
"""回归：一轮外部审计里实测确认的 P0（每条都先复现、再修）。

写在一起是因为它们同源：都属于"配置/解析说了一套，实际做的是另一套"，
单独看每条都不显眼，合起来就是"用户以为拦住了，其实没有"。
"""

import os
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import config, engine as engine_mod, normalize, rules   # noqa: E402
from waf.engine import RuleEngine                                 # noqa: E402
from waf.models import ScanTarget                                 # noqa: E402


def _target(url, method="GET", body=""):
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    return ScanTarget(kind="request", method=method, url=url,
                      host=parts.netloc, path=parts.path, query=parts.query,
                      body=body, tool="test")


class EngineCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-audit-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        self._env = {}
        for key, value in (("AGENTWAF_RULES_FILE", self.rules_path),
                           ("WAF_ALWAYS_ON", "1"),
                           ("WAF_NO_LOG", "1")):
            self._env[key] = os.environ.get(key)
            os.environ[key] = value
        engine_mod._ENGINE = None

    def tearDown(self):
        for key, value in self._env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        engine_mod._ENGINE = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    def make_engine(self, allowlist=None, settings=None):
        doc = rules.default_document()
        if allowlist:
            doc["allowlist"].extend(allowlist)
        if settings:
            doc["settings"].update(settings)
        rules.save_document(doc, self.rules_path)
        return RuleEngine(self.rules_path)


class TestHostAllowlist(EngineCase):
    """P0-1：source=host 的条目必须按主机名匹配。"""

    def test_host_entry_actually_whitelists(self):
        eng = self.make_engine([{"id": "A-H", "source": "host",
                                 "pattern": r"^lab\.local$",
                                 "enabled": True, "note": "t"}])
        verdict = eng.scan(_target("http://lab.local/delete"), log=False)
        self.assertFalse(verdict.blocked,
                         "host 白名单写了却不生效：%s" % verdict.reason)

    def test_host_entry_tolerates_port(self):
        eng = self.make_engine([{"id": "A-H2", "source": "host",
                                 "pattern": r"^lab\.local$",
                                 "enabled": True, "note": "t"}])
        verdict = eng.scan(_target("http://lab.local:8080/delete"), log=False)
        self.assertFalse(verdict.blocked, "带端口的 host 没匹配上锚定写法")

    def test_url_entry_still_works(self):
        eng = self.make_engine([{"id": "A-U", "source": "url",
                                 "pattern": r"^http://ok\.local/",
                                 "enabled": True, "note": "t"}])
        self.assertFalse(eng.scan(_target("http://ok.local/delete"),
                                  log=False).blocked)

    def test_host_entry_does_not_leak_to_other_hosts(self):
        eng = self.make_engine([{"id": "A-H3", "source": "host",
                                 "pattern": r"^lab\.local$",
                                 "enabled": True, "note": "t"}])
        self.assertTrue(eng.scan(_target("http://evil.local/delete"),
                                 log=False).blocked,
                        "host 白名单放过了别的主机")

    def test_host_pattern_must_not_match_url_text(self):
        """host 条目不该因为 URL 里恰好含主机名而命中别的请求。"""
        eng = self.make_engine([{"id": "A-H4", "source": "host",
                                 "pattern": r"lab",
                                 "enabled": True, "note": "t"}])
        self.assertTrue(eng.scan(
            _target("http://evil.local/delete?next=http://lab.local/x"),
            log=False).blocked)


class TestCurlMultiUrl(EngineCase):
    """P0-2：多个 --url / --next 之后的 URL 都要进扫描面。"""

    def setUp(self):
        super().setUp()
        from waf import curlshim
        self.curlshim = curlshim
        self._home = os.environ.get("HOME")
        # 别让开发机自己的 curlrc 干扰用例
        self._paths = {}
        for key in ("HOME", "USERPROFILE", "APPDATA", "CURL_HOME",
                    "XDG_CONFIG_HOME"):
            self._paths[key] = os.environ.get(key)
            os.environ.pop(key, None)
        os.environ["HOME"] = self.tmp

    def tearDown(self):
        for key, value in self._paths.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        super().tearDown()

    def test_all_url_flags_collected(self):
        _target_obj, info = self.curlshim.parse_curl_args(
            ["--url", "http://victim/delete", "--next",
             "--url", "http://127.0.0.1/x"])
        urls = info.get("urls") or []
        self.assertTrue(any("victim/delete" in u for u in urls),
                        "第一个 --url 被丢了：%s" % urls)
        self.assertTrue(any("127.0.0.1" in u for u in urls))

    def test_whitelisted_first_url_does_not_hide_the_second(self):
        eng = self.make_engine([{"id": "A-L", "source": "url",
                                 "pattern": r"^http://127\.0\.0\.1/",
                                 "enabled": True, "note": "t"}])
        target, _info = self.curlshim.parse_curl_args(
            ["--url", "http://127.0.0.1/x", "--next",
             "--url", "http://victim/delete"])
        verdict = eng.scan(target, log=False)
        self.assertTrue(verdict.blocked,
                        "白名单命中了第一个 URL，第二个 delete 被放过")


class TestDefaultCurlrc(EngineCase):
    """P0-3：curl 自动读取的默认配置文件也要扫。"""

    def setUp(self):
        super().setUp()
        from waf import curlshim
        self.curlshim = curlshim
        self._paths = {}
        for key in ("HOME", "USERPROFILE", "APPDATA", "CURL_HOME",
                    "XDG_CONFIG_HOME"):
            self._paths[key] = os.environ.get(key)
            os.environ.pop(key, None)
        os.environ["HOME"] = self.tmp

    def tearDown(self):
        for key, value in self._paths.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        super().tearDown()

    def _write_rc(self, text):
        path = os.path.join(self.tmp, ".curlrc")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_default_rc_is_part_of_scan_surface(self):
        self._write_rc("url = http://victim/delete\n")
        target, info = self.curlshim.parse_curl_args(["http://127.0.0.1/x"])
        # 有效值进 config_urls / urls（原文本不再整段进扫描面 ——
        # 那会把注释也当成请求内容，见第二轮 #7）
        blob = " ".join(list(info.get("config_urls") or [])
                        + list(info.get("urls") or []))
        self.assertIn("victim/delete", blob,
                      "默认 .curlrc 没进扫描面：%r" % blob)

    def test_default_rc_actually_blocks(self):
        self._write_rc("url = http://victim/delete\n")
        eng = self.make_engine()
        target, _info = self.curlshim.parse_curl_args(["http://127.0.0.1/x"])
        self.assertTrue(eng.scan(target, log=False).blocked,
                        "藏在 .curlrc 里的删除 URL 没被拦")

    def test_q_disables_default_rc(self):
        self._write_rc("url = http://victim/delete\n")
        _target_obj, info = self.curlshim.parse_curl_args(
            ["-q", "http://127.0.0.1/x"])
        blob = " ".join(list(info.get("config_urls") or [])
                        + list(info.get("urls") or []))
        self.assertNotIn("victim/delete", blob,
                         "-q 时 curl 不读默认配置，我们也不该读")


class TestOversizeRefused(EngineCase):
    """P0-4：扫描字节必须等于发送字节；超限拒绝，不截断。"""

    def setUp(self):
        super().setUp()
        from waf import curlshim
        self.curlshim = curlshim
        self._paths = {}
        for key in ("HOME", "USERPROFILE", "APPDATA", "CURL_HOME",
                    "XDG_CONFIG_HOME"):
            self._paths[key] = os.environ.get(key)
            os.environ.pop(key, None)
        os.environ["HOME"] = self.tmp
        self.curlshim.set_body_limit(4096)

    def tearDown(self):
        self.curlshim.set_body_limit(262144)
        for key, value in self._paths.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        super().tearDown()

    def test_big_data_file_refused(self):
        path = os.path.join(self.tmp, "big.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("A" * 5000)
        with self.assertRaises(self.curlshim.BodyTooLarge):
            self.curlshim.parse_curl_args(
                ["-d", "@" + path, "http://t/api"])

    def test_big_stdin_body_refused(self):
        class _FakeStdin(object):
            class buffer(object):
                @staticmethod
                def read(size):
                    return b"B" * 5000

        saved = sys.stdin
        sys.stdin = _FakeStdin()
        try:
            with self.assertRaises(self.curlshim.BodyTooLarge):
                self.curlshim.parse_curl_args(
                    ["-d", "@-", "http://t/api"])
        finally:
            sys.stdin = saved

    def test_small_body_still_fine(self):
        path = os.path.join(self.tmp, "small.json")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write('{"q":"ok"}')
        _t, info = self.curlshim.parse_curl_args(
            ["-d", "@" + path, "http://t/api"])
        self.assertIn('{"q":"ok"}', "\n".join(info["body_parts"]))


class TestSettingsSanitized(unittest.TestCase):
    """P0-7：非法 settings 不能让整份配置在运行时炸掉。"""

    def _validated(self, **overrides):
        doc = rules.default_document()
        doc["settings"].update(overrides)
        ok, out = rules.validate_document(doc)
        self.assertTrue(ok, out)
        return out["settings"]

    def test_bad_max_scan_bytes_falls_back(self):
        settings = self._validated(max_scan_bytes="abc")
        self.assertEqual(settings["max_scan_bytes"],
                         rules.DEFAULT_SETTINGS["max_scan_bytes"])

    def test_out_of_range_clamped(self):
        settings = self._validated(max_scan_bytes=10 ** 12)
        self.assertLessEqual(settings["max_scan_bytes"], 64 * 1024 * 1024)
        settings = self._validated(max_scan_bytes=1)
        self.assertGreaterEqual(settings["max_scan_bytes"], 4096)

    def test_bad_types_fixed(self):
        settings = self._validated(enabled="false", scan_headers="0",
                                   case_sensitive="true",
                                   normalize="url_decode, lower")
        self.assertIs(settings["enabled"], False)
        self.assertIs(settings["scan_headers"], False)
        self.assertIs(settings["case_sensitive"], True)
        self.assertEqual(settings["normalize"], ["url_decode", "lower"])

    def test_unknown_normalize_ops_dropped(self):
        settings = self._validated(normalize=["url_decode", "nope", 5])
        self.assertEqual(settings["normalize"], ["url_decode"])

    def test_engine_survives_bad_settings(self):
        """端到端：非法值修好之后，扫描不能变成"全拦"。"""
        tmp = tempfile.mkdtemp(prefix="agentwaf-set-")
        try:
            path = os.path.join(tmp, "rules.json")
            doc = rules.default_document()
            doc["settings"]["max_scan_bytes"] = "abc"
            rules.save_document(doc, path)
            eng = RuleEngine(path)
            verdict = eng.scan(_target("http://127.0.0.1/ok"), log=False)
            self.assertFalse(verdict.blocked,
                             "非法配置导致正常请求被拦：%s" % verdict.reason)
            self.assertNotEqual(verdict.stage, "engine_error")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSqlCommentMapping(unittest.TestCase):
    """P0-8：带映射的归一化变体里，SQL 注释必须被替换成空格。"""

    def test_mapped_variant_gets_space(self):
        variants = normalize.build_variants_with_map(
            "drop/**/table", ["strip_sql_comment"])
        texts = [text for _label, text, _m in variants]
        self.assertTrue(any("drop table" in t for t in texts),
                        "映射变体里注释没处理：%s" % texts)

    def test_plain_normalize_also_spaces(self):
        self.assertEqual(normalize.strip_sql_noise("drop/**/table"),
                         "drop table")

    def test_offsets_still_map_back(self):
        variants = normalize.build_variants_with_map(
            "aa drop/**/table", ["strip_sql_comment"])
        for _label, text, index_map in variants:
            if "drop table" in text:
                pos = text.index("drop")
                self.assertLessEqual(index_map[pos], 5,
                                     "偏移没有映射回原文")


class TestSelfEndpointPath(EngineCase):
    """P0-9：自身接口豁免必须要求明确的 /api/ 路径。"""

    def _engine(self):
        from waf import state
        self._saved_read = state.read
        state.read = lambda *a, **kw: {"port": 65000}
        try:
            return self.make_engine()
        finally:
            pass

    def tearDown(self):
        if getattr(self, "_saved_read", None) is not None:
            from waf import state
            state.read = self._saved_read
        super().tearDown()

    def test_empty_path_not_exempt(self):
        eng = self._engine()
        target = ScanTarget(kind="request", method="GET",
                            url="http://127.0.0.1:65000",
                            host="127.0.0.1:65000", path="", tool="test")
        self.assertFalse(eng._is_self_endpoint(target),
                         "空 path 被当成了自身接口")

    def test_api_path_exempt(self):
        eng = self._engine()
        target = ScanTarget(kind="request", method="POST",
                            url="http://127.0.0.1:65000/api/shutdown",
                            host="127.0.0.1:65000", path="/api/shutdown",
                            tool="test")
        self.assertTrue(eng._is_self_endpoint(target))

    def test_other_path_not_exempt(self):
        eng = self._engine()
        target = ScanTarget(kind="request", method="DELETE",
                            url="http://127.0.0.1:65000/delete",
                            host="127.0.0.1:65000", path="/delete",
                            tool="test")
        self.assertFalse(eng._is_self_endpoint(target))


class TestGateCacheInvalidation(EngineCase):
    """P0-6：命令门槛词表必须跟随规则文件变化。"""

    def test_cache_follows_rules_file(self):
        from waf import guard
        rules.save_document(rules.default_document(), self.rules_path)
        guard._GATE_WORDS_CACHE = None
        before = guard._gate_words_cached()
        self.assertNotIn("zzcustomverb", before)

        doc = rules.default_document()
        doc["rules"].append({
            "id": "R-998", "name": "custom", "enabled": True,
            "severity": "high", "action": "block", "match_mode": "regex",
            "keywords": [], "regex": [r"\bzzcustomverb\b"], "exclude": [],
            "note": "t",
        })
        rules.save_document(doc, self.rules_path)
        # save_document 会重写文件 → mtime/size 变化 → 缓存必须失效
        os.utime(self.rules_path, None)
        after = guard._gate_words_cached()
        self.assertIn("zzcustomverb", after,
                      "新增规则没进门槛词表（长驻进程会一直漏扫）")


class TestProxyHardening(EngineCase):
    """P0-4c / P0-5：代理不能截断转发，引擎异常要跟 fail_mode。"""

    def _free_port(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return port

    def _start_proxy(self):
        from waf.proxy import ProxyServer
        port = self._free_port()
        server = ProxyServer(host="127.0.0.1", port=port, mitm=False)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        time.sleep(0.4)
        return server, port

    def _raw(self, port, payload, timeout=6):
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        try:
            sock.sendall(payload)
            sock.settimeout(timeout)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            return data
        finally:
            sock.close()

    def test_oversize_body_gets_413_not_truncated(self):
        server, port = self._start_proxy()
        try:
            resp = self._raw(
                port,
                b"POST http://127.0.0.1/x HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Length: 999999999\r\n\r\n")
            status = resp.split(b"\r\n", 1)[0]
            self.assertIn(b"413", status,
                          "超大 Content-Length 没有被拒绝：%r" % status)
            self.assertIn(b"X-HuntGuard", resp)
        finally:
            server.shutdown()

    def test_engine_error_is_fail_closed(self):
        import waf.proxy as proxy_mod

        class Boom(object):
            settings = {"fail_mode": "closed"}

            def scan(self, target, log=True):
                raise RuntimeError("boom")

            def enabled(self):
                return True

        saved = proxy_mod.get_engine
        proxy_mod.get_engine = lambda: Boom()
        try:
            server, port = self._start_proxy()
            try:
                resp = self._raw(
                    port,
                    b"GET http://127.0.0.1/ok HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\nConnection: close\r\n\r\n")
                status = resp.split(b"\r\n", 1)[0]
                self.assertIn(b"403", status,
                              "引擎异常时代理放行了：%r" % status)
                self.assertIn(b"X-HuntGuard", resp)
            finally:
                server.shutdown()
        finally:
            proxy_mod.get_engine = saved


class CurlCase(EngineCase):
    """curl 解析类用例的公共部分：隔离 HOME，避免读开发机自己的 .curlrc。"""

    def setUp(self):
        super().setUp()
        from waf import curlshim
        self.curlshim = curlshim
        self._paths = {}
        for key in ("HOME", "USERPROFILE", "APPDATA", "CURL_HOME",
                    "XDG_CONFIG_HOME"):
            self._paths[key] = os.environ.get(key)
            os.environ.pop(key, None)
        os.environ["HOME"] = self.tmp

    def tearDown(self):
        for key, value in self._paths.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        super().tearDown()

    def write(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path


class TestRound2HostMultiUrl(EngineCase):
    """第二轮 #1：多 URL 时 host 白名单要生效（额外 URL 也要按 host 判）。"""

    def test_host_entry_covers_extra_urls(self):
        eng = self.make_engine([{"id": "A-H5", "source": "host",
                                 "pattern": r"^lab\.local$",
                                 "enabled": True, "note": "t"}])
        target = _target("http://lab.local/a")
        target.meta["urls"] = ["http://lab.local/a",
                              "http://lab.local/delete"]
        verdict = eng.scan(target, log=False)
        self.assertFalse(verdict.blocked,
                         "多 URL 下 host 白名单又失效了：%s" % verdict.reason)

    def test_other_host_still_blocked(self):
        eng = self.make_engine([{"id": "A-H6", "source": "host",
                                 "pattern": r"^lab\.local$",
                                 "enabled": True, "note": "t"}])
        target = _target("http://lab.local/a")
        target.meta["urls"] = ["http://lab.local/a",
                              "http://evil.local/delete"]
        self.assertTrue(eng.scan(target, log=False).blocked,
                        "第二个 URL 不在白名单却被放行")


class TestRound2SchemeLessUrl(CurlCase):
    """第二轮 #2：不带 scheme 的 URL 也是 URL（curl 默认按 http 处理）。"""

    def test_detected_after_next(self):
        _t, info = self.curlshim.parse_curl_args(
            ["http://127.0.0.1/x", "--next", "victim.local/delete"])
        urls = info.get("urls") or []
        self.assertTrue(any("victim.local/delete" in u for u in urls),
                        "无 scheme 的 URL 没进 urls：%s" % urls)

    def test_whitelist_does_not_hide_it(self):
        eng = self.make_engine([{"id": "A-S", "source": "url",
                                 "pattern": r"^http://127\.0\.0\.1/",
                                 "enabled": True, "note": "t"}])
        target, _info = self.curlshim.parse_curl_args(
            ["http://127.0.0.1/x", "--next", "victim.local/delete"])
        self.assertTrue(eng.scan(target, log=False).blocked,
                        "白名单命中了第一个 URL，无 scheme 的目标被放过")

    def test_plain_word_is_not_a_url(self):
        self.assertIsNone(self.curlshim._normalize_url_token("notaurl"))
        self.assertIsNone(self.curlshim._normalize_url_token("-d"))


class TestRound2ConfigValues(CurlCase):
    """第二轮 #3/#4/#7：配置文件里的 URL / 文件引用 / 注释。"""

    def _rc(self, text):
        return self.write(".curlrc", text)

    def test_config_url_merged_into_urls(self):
        self._rc("url = http://victim/delete\n")
        _t, info = self.curlshim.parse_curl_args(["http://127.0.0.1/x"])
        urls = info.get("urls") or []
        self.assertTrue(any("victim/delete" in u for u in urls),
                        "配置里的 url 没进 urls：%s" % urls)

    def test_config_url_not_hidden_by_whitelist(self):
        self._rc("url = http://victim/delete\n")
        eng = self.make_engine([{"id": "A-C", "source": "url",
                                 "pattern": r"^http://127\.0\.0\.1/",
                                 "enabled": True, "note": "t"}])
        target, _info = self.curlshim.parse_curl_args(["http://127.0.0.1/x"])
        self.assertTrue(eng.scan(target, log=False).blocked,
                        "白名单命中命令行 URL，配置里的目标没检查")

    def test_config_data_file_reference_reads_content(self):
        payload = self.write("payload.txt", "action=delete")
        cfg = self.write("cfg.txt", 'data = "@%s"\n' % payload)
        _t, info = self.curlshim.parse_curl_args(
            ["-K", cfg, "http://127.0.0.1/x"])
        blob = "\n".join(info.get("body_parts") or [])
        self.assertIn("action=delete", blob,
                      "配置里的 data=@file 只扫了路径字符串")

    def test_config_header_file_reference_reads_content(self):
        hdr = self.write("hdr.txt", "X-Action: delete\n")
        cfg = self.write("cfg2.txt", 'header = "@%s"\n' % hdr)
        _t, info = self.curlshim.parse_curl_args(
            ["-K", cfg, "http://127.0.0.1/x"])
        blob = "\n".join(info.get("headers") or [])
        self.assertIn("delete", blob, "配置里的 header=@file 没读内容")

    def test_nested_config_is_followed(self):
        inner = self.write("inner.cfg", "url = http://victim/delete\n")
        outer = self.write("outer.cfg", "config = %s\n" % inner)
        _t, info = self.curlshim.parse_curl_args(
            ["-K", outer, "http://127.0.0.1/x"])
        urls = " ".join(info.get("urls") or []) + " " + \
               " ".join(info.get("config_urls") or [])
        self.assertIn("victim/delete", urls, "嵌套 config 没有被跟进")

    def test_comments_are_not_scanned(self):
        """第二轮 #7：注释里的 remove/delete 不能把正常 curl 全拦掉。"""
        self._rc("# do not remove this comment\nsilent\n")
        eng = self.make_engine()
        target, _info = self.curlshim.parse_curl_args(["http://example.com/"])
        self.assertFalse(eng.scan(target, log=False).blocked,
                         "curlrc 注释导致误拦")

    def test_unknown_options_ignored_but_values_scanned(self):
        self._rc("user-agent = 'something with delete in it'\n")
        _t, info = self.curlshim.parse_curl_args(["http://example.com/"])
        # -A 是已知选项 → 值要进扫描面（这里只断言没崩、且不误判为 URL）
        self.assertEqual(info.get("url"), "http://example.com/")


class TestRound2ConfigStdin(CurlCase):
    """第二轮 #6：`-K -` 也要遵守扫描上限，不能静默截断。"""

    def test_oversize_config_stdin_refused(self):
        class _FakeStdin(object):
            class buffer(object):
                @staticmethod
                def read(size):
                    return b"silent\n" * 2000

        self.curlshim.set_body_limit(4096)
        saved = sys.stdin
        sys.stdin = _FakeStdin()
        try:
            with self.assertRaises(self.curlshim.BodyTooLarge):
                self.curlshim.parse_curl_args(["-K", "-", "http://t/x"])
        finally:
            sys.stdin = saved
            self.curlshim.set_body_limit(262144)


class TestRound2UnifiedLimit(EngineCase):
    """第二轮 #5：guard / 代理与引擎用同一个扫描上限。"""

    def test_guard_rejects_oversize_body(self):
        self.make_engine(settings={"max_scan_bytes": 4096})
        from waf import guard
        from waf.models import WafBlocked
        try:
            guard.check_request(method="POST", url="http://t/ok",
                                body="a" * 5000, tool="test", log=False)
        except WafBlocked as exc:
            self.assertEqual(exc.verdict.stage, "oversize")
            self.assertIn("扫描上限", exc.verdict.reason)
        else:
            self.fail("guard 把超限 body 完整放行了")

    def test_guard_accepts_body_within_limit(self):
        self.make_engine(settings={"max_scan_bytes": 4096})
        from waf import guard
        verdict = guard.check_request(method="POST", url="http://t/ok",
                                      body="a" * 100, tool="test", log=False)
        self.assertFalse(verdict.blocked)


class TestRound2ProxyAndConnect(EngineCase):
    """第二轮 #5/#8：代理上限一致；CONNECT 引擎异常不再 fail-open。"""

    def _start_proxy(self):
        from waf.proxy import ProxyServer
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        server = ProxyServer(host="127.0.0.1", port=port, mitm=False)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        time.sleep(0.4)
        return server, port

    def _raw(self, port, payload, timeout=6):
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        try:
            sock.sendall(payload)
            sock.settimeout(timeout)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            return data
        finally:
            sock.close()

    def test_proxy_rejects_body_over_scan_limit(self):
        self.make_engine(settings={"max_scan_bytes": 8192})
        server, port = self._start_proxy()
        try:
            resp = self._raw(
                port,
                b"POST http://127.0.0.1/x HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\nContent-Length: 9000\r\n\r\n")
            status = resp.split(b"\r\n", 1)[0]
            self.assertIn(b"413", status,
                          "超过扫描上限的 body 没有被拒绝：%r" % status)
        finally:
            server.shutdown()

    def test_connect_engine_error_is_fail_closed(self):
        import waf.proxy as proxy_mod

        class Boom(object):
            settings = {"fail_mode": "closed"}

            def scan(self, target, log=True):
                raise RuntimeError("boom")

            def enabled(self):
                return True

        saved = proxy_mod.get_engine
        proxy_mod.get_engine = lambda: Boom()
        try:
            server, port = self._start_proxy()
            try:
                resp = self._raw(
                    port,
                    b"CONNECT example.com:443 HTTP/1.1\r\n"
                    b"Host: example.com:443\r\n\r\n")
                status = resp.split(b"\r\n", 1)[0]
                self.assertIn(b"403", status,
                              "CONNECT 在引擎异常时被放行：%r" % status)
            finally:
                server.shutdown()
        finally:
            proxy_mod.get_engine = saved


class TestRound3CurlOptions(CurlCase):
    """第三轮 #1/#2：@file 命令行 / 本地输出参数。"""

    def test_header_at_file_read(self):
        hdr = self.write("h.txt", "X-Action: delete\n")
        _t, info = self.curlshim.parse_curl_args(
            ["-H", "@" + hdr, "http://127.0.0.1/x"])
        blob = " ".join(info.get("headers") or [])
        self.assertIn("delete", blob, "命令行 -H @file 没读文件内容")

    def test_cookie_at_file_read(self):
        jar = self.write("c.txt", "session=delete\n")
        _t, info = self.curlshim.parse_curl_args(
            ["-b", "@" + jar, "http://127.0.0.1/x"])
        self.assertIn("delete", info.get("cookie") or "",
                      "命令行 -b @file 没读文件内容")

    def test_url_query_at_file_read(self):
        frag = self.write("q.txt", "action=delete")
        _t, info = self.curlshim.parse_curl_args(
            ["--url-query", "@" + frag, "http://127.0.0.1/x"])
        self.assertIn("delete", " ".join(info.get("extra_query") or []),
                      "--url-query @file 没读文件内容")

    def test_local_output_options_not_scanned(self):
        """-o / -D / -w / --output-dir 的值是本地文件名，不能当请求内容。"""
        eng = self.make_engine()
        for argv in (["-o", "delete.txt", "http://127.0.0.1/"],
                     ["-D", "delete.headers", "http://127.0.0.1/"],
                     ["--output-dir", "remove", "http://127.0.0.1/"],
                     ["-w", "%{http_code} delete", "http://127.0.0.1/"]):
            target, info = self.curlshim.parse_curl_args(argv)
            verdict = eng.scan(target, log=False)
            self.assertFalse(verdict.blocked,
                             "本地输出参数被当成请求内容：%s" % (argv,))

    def test_local_value_is_not_a_url(self):
        _t, info = self.curlshim.parse_curl_args(
            ["-o", "1.5", "http://127.0.0.1/x"])
        urls = info.get("urls") or []
        self.assertFalse(any("1.5" in u for u in urls),
                         "-o 的值被当成了 URL：%s" % urls)


class TestRound3ConfigSecurityOptions(CurlCase):
    """第三轮 #3：配置里的 connect-to / resolve 必须进结构化字段。"""

    def test_connect_to_in_config(self):
        cfg = self.write("cfg.cfg", "connect-to = good.com:443:evil.com:443\n")
        target, info = self.curlshim.parse_curl_args(
            ["-K", cfg, "https://good.com/x"])
        reals = " ".join(info.get("real_hosts") or [])
        self.assertIn("evil.com", reals,
                      "配置里的 connect-to 没有被解析：%s" % info)

    def test_resolve_in_config(self):
        cfg = self.write("cfg2.cfg", "resolve = good.com:443:1.2.3.4\n")
        target, info = self.curlshim.parse_curl_args(
            ["-K", cfg, "https://good.com/x"])
        self.assertIn("1.2.3.4", " ".join(info.get("real_hosts") or []))


class TestRound3SingleLabelHost(CurlCase):
    """第三轮 #4：单标签内网主机（metadata/delete）也是 URL。"""

    def test_single_label_after_next(self):
        _t, info = self.curlshim.parse_curl_args(
            ["http://127.0.0.1/x", "--next", "metadata/delete"])
        urls = info.get("urls") or []
        self.assertTrue(any("metadata/delete" in u for u in urls),
                        "单标签主机没进 urls：%s" % urls)

    def test_single_label_not_hidden_by_whitelist(self):
        eng = self.make_engine([{"id": "A-W", "source": "url",
                                 "pattern": r"^http://127\.0\.0\.1/",
                                 "enabled": True, "note": "t"}])
        target, _info = self.curlshim.parse_curl_args(
            ["http://127.0.0.1/x", "--next", "metadata/delete"])
        self.assertTrue(eng.scan(target, log=False).blocked,
                        "白名单命中了第一个 URL，单标签目标被放过")


class TestRound3UnlockAndLimits(EngineCase):
    """第三轮 #5/#6：unlock 与白名单要能放行超限；文本模式不能假检查。"""

    def test_guard_oversize_allowed_when_unlocked(self):
        from waf import guard
        self.make_engine(settings={"max_scan_bytes": 4096})
        eng = engine_mod.get_engine()
        eng.unlock_remaining = lambda: 60          # 模拟解锁窗口
        try:
            verdict = guard.check_request(method="POST", url="http://t/ok",
                                          body="a" * 5000, tool="test",
                                          log=False)
            self.assertFalse(verdict.blocked, "解锁后仍被超限拒绝")
        finally:
            pass

    def test_guard_oversize_allowed_by_allowlist(self):
        from waf import guard
        self.make_engine(allowlist=[{"id": "A-BIG", "source": "url",
                                     "pattern": r"^http://big\.local/",
                                     "enabled": True, "note": "t"}],
                         settings={"max_scan_bytes": 4096})
        verdict = guard.check_request(method="POST",
                                      url="http://big.local/ok",
                                      body="a" * 5000, tool="test",
                                      log=False)
        self.assertFalse(verdict.blocked, "白名单目标仍被超限拒绝")

    def test_guard_oversize_still_blocked_for_others(self):
        from waf import guard
        from waf.models import WafBlocked
        self.make_engine(settings={"max_scan_bytes": 4096})
        with self.assertRaises(WafBlocked):
            guard.check_request(method="POST", url="http://t/ok",
                                body="a" * 5000, tool="test", log=False)

    def test_cli_text_mode_refuses_oversize(self):
        from waf import cli
        self.make_engine(settings={"max_scan_bytes": 4096})
        args = cli.build_parser().parse_args(["check", "x" * 5000])
        self.assertEqual(cli.cmd_check(args), 2,
                         "wafctl check 文本模式对超限文本做了假检查")


class TestRound3CompressedBody(EngineCase):
    """第三轮 #7：压缩请求体要解开再扫；解不了就拒绝。"""

    def _gzip(self, text):
        import gzip
        return gzip.compress(text.encode("utf-8"))

    def test_guard_scans_gzip_body(self):
        from waf import guard
        from waf.models import WafBlocked
        self.make_engine()
        body = self._gzip('{"sql":"delete from users"}')
        with self.assertRaises(WafBlocked):
            guard.check_request(method="POST", url="http://t/api",
                                headers={"Content-Encoding": "gzip"},
                                body=body, tool="test", log=False)

    def test_guard_rejects_unsupported_encoding(self):
        from waf import guard
        from waf.models import WafBlocked
        self.make_engine()
        with self.assertRaises(WafBlocked) as ctx:
            guard.check_request(method="POST", url="http://t/api",
                                headers={"Content-Encoding": "br"},
                                body=b"\x00\x01", tool="test", log=False)
        self.assertEqual(ctx.exception.verdict.stage, "body_encoding")

    def test_guard_allows_gzip_benign(self):
        from waf import guard
        self.make_engine()
        body = self._gzip('{"q":"hello"}')
        verdict = guard.check_request(method="POST", url="http://t/api",
                                      headers={"Content-Encoding": "gzip"},
                                      body=body, tool="test", log=False)
        self.assertFalse(verdict.blocked)

    def test_codec_limits_and_errors(self):
        from waf import bodycodec
        data, status = bodycodec.decode_request_body(b"x", "identity")
        self.assertEqual((data, status), (b"x", "none"))
        data, status = bodycodec.decode_request_body(b"not-gzip", "gzip")
        self.assertEqual(status, "bad")
        data, status = bodycodec.decode_request_body(b"xx", "zstd")
        self.assertEqual(status, "unsupported")


class TestRound3ProxyCompressed(EngineCase):
    """第三轮 #7（代理侧）：gzip 体解压后再扫，解不了回 415。"""

    def _start_proxy(self):
        from waf.proxy import ProxyServer
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        server = ProxyServer(host="127.0.0.1", port=port, mitm=False)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        time.sleep(0.4)
        return server, port

    def _send(self, port, payload, timeout=6):
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        try:
            sock.sendall(payload)
            sock.settimeout(timeout)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            return data
        finally:
            sock.close()

    def test_gzip_body_blocked(self):
        import gzip
        body = gzip.compress(b'{"sql":"delete from users"}')
        server, port = self._start_proxy()
        try:
            head = (b"POST http://127.0.0.1/api HTTP/1.1\r\n"
                    b"Host: 127.0.0.1\r\nContent-Encoding: gzip\r\n"
                    b"Content-Length: %d\r\n\r\n" % len(body))
            resp = self._send(port, head + body)
            status = resp.split(b"\r\n", 1)[0]
            self.assertIn(b"403", status,
                          "gzip 压缩的删除载荷没被拦：%r" % status)
        finally:
            server.shutdown()

    def test_unsupported_encoding_rejected(self):
        server, port = self._start_proxy()
        try:
            resp = self._send(
                port,
                b"POST http://127.0.0.1/api HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\nContent-Encoding: br\r\n"
                b"Content-Length: 2\r\n\r\nxx")
            status = resp.split(b"\r\n", 1)[0]
            self.assertIn(b"415", status,
                          "无法解码的编码被转发：%r" % status)
        finally:
            server.shutdown()


class TestRound3PerfSanity(unittest.TestCase):
    """第三轮性能：按需归一化不能改变结果。"""

    def test_variants_unchanged_for_trigger_chars(self):
        cases = ["%64elete", "&#100;elete", "\\u0064elete",
                 "ｄｅｌｅｔｅ", "del\u200bete", "de   lete",
                 "d_e_l_e_t_e", "DELETE", "drop/**/table"]
        for text in cases:
            variants = normalize.build_variants_with_map(
                text, list(rules.DEFAULT_SETTINGS["normalize"]))
            texts = [v for _label, v, _m in variants]
            self.assertTrue(texts, "%r 没有产生任何变体" % text)
            # 至少有一个变体把干扰字符处理掉了
            self.assertTrue(
                any("delete" in t for t in texts)
                or any("droptable" in t for t in texts),
                "%r 的变体异常：%s" % (text, texts))

    def test_plain_ascii_skips_fold(self):
        variants = normalize.build_variants_with_map(
            "plain text", ["fold_fullwidth", "lower"])
        # 归一化变体不变；compact 变体（去掉空格）仍会生成 —— 那是设计
        self.assertEqual(variants[0][1], "plain text")


class TestRound4ProxyGzip(EngineCase):
    """第四轮 #1/#2：解压体超限拒绝；转发仍用原始压缩字节。"""

    def _start_proxy(self):
        from waf.proxy import ProxyServer
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        server = ProxyServer(host="127.0.0.1", port=port, mitm=False)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        time.sleep(0.4)
        return server, port

    def _upstream(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)
        port = srv.getsockname()[1]
        records = []

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                try:
                    conn.settimeout(2.0)
                    buf = b""
                    while b"\r\n\r\n" not in buf:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        buf += chunk
                    head, _, rest = buf.partition(b"\r\n\r\n")
                    need = 0
                    for line in head.split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            try:
                                need = int(line.split(b":", 1)[1].strip())
                            except ValueError:
                                need = 0
                    while len(rest) < need:
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        rest += chunk
                    records.append((head, rest))
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                                 b"Connection: close\r\n\r\nok")
                except Exception:
                    pass
                finally:
                    try:
                        conn.close()
                    except Exception:
                        pass

        threading.Thread(target=serve, daemon=True).start()
        return srv, port, records

    def _send(self, port, payload, timeout=6):
        sock = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        try:
            sock.sendall(payload)
            sock.settimeout(timeout)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                data += chunk
            return data
        finally:
            sock.close()

    def test_forwards_original_compressed_bytes(self):
        """解压只用于扫描；转发的仍是原始 gzip 字节，头不能被剥。"""
        import gzip
        upstream, up_port, records = self._upstream()
        payload = b'{"q":"hello"}'
        gz = gzip.compress(payload)
        server, port = self._start_proxy()
        try:
            resp = self._send(
                port,
                b"POST http://127.0.0.1:%d/api HTTP/1.1\r\n"
                b"Host: 127.0.0.1:%d\r\nContent-Encoding: gzip\r\n"
                b"Content-Length: %d\r\n\r\n" % (up_port, up_port, len(gz))
                + gz)
            self.assertIn(b"200", resp.split(b"\r\n", 1)[0], resp[:200])
            self.assertTrue(records, "上游没收到请求")
            head, body = records[0]
            self.assertIn(b"content-encoding: gzip", head.lower(),
                          "转发的头被改了")
            self.assertEqual(body, gz,
                             "转发的不再是原始压缩字节（上游会解压失败）")
        finally:
            server.shutdown()
            upstream.close()

    def test_rejects_decompressed_oversize(self):
        """解压后超过扫描上限 → 413（不能只扫前一段却转发全部）。"""
        import gzip
        self.make_engine(settings={"max_scan_bytes": 4096})
        gz = gzip.compress(b"a" * 8192 + b"&action=delete")
        self.assertLess(len(gz), 4096, "构造的压缩体本身就超限了，用例无效")
        server, port = self._start_proxy()
        try:
            resp = self._send(
                port,
                b"POST http://127.0.0.1/api HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\nContent-Encoding: gzip\r\n"
                b"Content-Length: %d\r\n\r\n" % len(gz) + gz)
            status = resp.split(b"\r\n", 1)[0]
            self.assertIn(b"413", status,
                          "解压后超限没被拒绝：%r" % status)
        finally:
            server.shutdown()

    def test_connection_cap(self):
        """连接数上限：超出的新连接直接关闭。"""
        import waf.proxy as proxy_mod
        saved = proxy_mod.MAX_CONNECTIONS
        proxy_mod.MAX_CONNECTIONS = 2
        server, port = self._start_proxy()
        held = []
        try:
            for _ in range(2):
                held.append(socket.create_connection(("127.0.0.1", port),
                                                     timeout=5))
            time.sleep(0.3)
            third = socket.create_connection(("127.0.0.1", port), timeout=5)
            try:
                third.settimeout(3)
                self.assertEqual(third.recv(16), b"",
                                 "超过上限的连接没有被关闭")
            finally:
                third.close()
        finally:
            for sock in held:
                try:
                    sock.close()
                except Exception:
                    pass
            server.shutdown()
            proxy_mod.MAX_CONNECTIONS = saved


class TestRound4Misc(unittest.TestCase):
    """第四轮 #5/#6：叶证书缓存上限、utcnow 弃用。"""

    def test_cert_cache_trim(self):
        from waf import certs
        saved = dict(certs._cache)
        try:
            certs._cache.clear()
            for i in range(certs.MAX_CACHE + 20):
                certs._cache["h%d.local" % i] = (b"c", b"k")
            certs._trim_cache()
            self.assertLessEqual(len(certs._cache), certs.MAX_CACHE)
            # 最新的应该还在
            self.assertIn("h%d.local" % (certs.MAX_CACHE + 19), certs._cache)
        finally:
            certs._cache.clear()
            certs._cache.update(saved)

    def test_no_deprecated_utcnow(self):
        path = os.path.join(ROOT, "waf", "certs.py")
        with open(path, encoding="utf-8") as fh:
            self.assertNotIn("utcnow", fh.read(),
                             "certs.py 仍在使用已弃用的 datetime.utcnow()")


if __name__ == "__main__":
    unittest.main()
