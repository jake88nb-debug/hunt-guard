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
        blob = "\n".join(info.get("config_parts") or [])
        self.assertIn("victim/delete", blob,
                      "默认 .curlrc 没进扫描面：%r" % info.get("config_parts"))

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
        blob = "\n".join(info.get("config_parts") or [])
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


if __name__ == "__main__":
    unittest.main()
