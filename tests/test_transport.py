# -*- coding: utf-8 -*-
"""回归：传输层兜底（http.client / 裸 socket）、urllib body、补丁幂等、
递归闸，以及本轮补的规则词表与 PowerShell 通道。

为什么单独一个文件：这些用例要在**本进程里真的装一遍补丁**
（socket / http.client 是进程级的），装完必须还原 —— 否则会影响
test_waf.py / test_channels.py 里那些自己开本地服务、走裸 socket
的用例（比如代理用例预期拿到代理返回的 403，结果被 socket 层
先拦成异常）。setUp/tearDown 负责快照与还原。
"""

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import engine as engine_mod                  # noqa: E402
from waf import guard, rules                          # noqa: E402
from waf.models import WafBlocked                     # noqa: E402


class EchoServer(object):
    """最小 HTTP 回声服务：收一条请求记下来，回 200 并关连接。

    只用来验证"请求到底有没有发出去" —— 被拦的必须一条都收不到。
    """

    def __init__(self):
        self.received = []
        self._sock = socket.socket()
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(16)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        self._thread = threading.Thread(target=self._serve)
        self._thread.daemon = True
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
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
                if buf or rest:
                    self.received.append(head + b"\r\n\r\n" + rest)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n"
                             b"Connection: close\r\n\r\nok")
            except Exception:
                pass
            finally:
                try:
                    conn.close()
                except Exception:
                    pass

    def close(self):
        self._stop = True
        try:
            self._sock.close()
        except Exception:
            pass


class TransportBase(unittest.TestCase):
    """装补丁 → 跑断言 → 还原补丁（不污染同进程其它用例）。"""

    # 会被 guard 覆盖的入口，全部快照下来
    TARGETS = (
        (socket.socket, "sendall"),
        (socket.socket, "send"),
        ("http.client.HTTPConnection", "_send_request"),
        ("http.client.HTTPConnection", "putrequest"),
        ("http.client.HTTPConnection", "endheaders"),
        ("urllib.request", "urlopen"),
        ("urllib.request.OpenerDirector", "open"),
        ("requests.Session", "send"),
        ("requests", "request"),
    )

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-tp-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)

        self._env_backup = {}
        for key, value in (("AGENTWAF_RULES_FILE", self.rules_path),
                           ("WAF_ALWAYS_ON", "1"),
                           ("WAF_NO_LOG", "1"),
                           ("WAF_QUIET", "1")):
            self._env_backup[key] = os.environ.get(key)
            os.environ[key] = value
        engine_mod._ENGINE = None

        self._snapshot = []
        for owner, name in self.TARGETS:
            obj = self._resolve(owner)
            if obj is None or not hasattr(obj, name):
                continue
            self._snapshot.append((obj, name, getattr(obj, name)))

        guard._installed = False
        guard.install_guard(patch_subprocess=False)
        self.server = EchoServer()

    def tearDown(self):
        self.server.close()
        for obj, name, value in self._snapshot:
            try:
                setattr(obj, name, value)
            except Exception:
                pass
        guard._installed = False
        for key, value in self._env_backup.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        engine_mod._ENGINE = None
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def _resolve(path):
        if not isinstance(path, str):
            return path
        module_name, _, attr = path.partition(".")
        try:
            module = __import__(module_name)
        except ImportError:
            return None
        return getattr(module, attr, None)

    # -- 便捷方法 ----------------------------------------------------

    @property
    def url(self):
        return "http://127.0.0.1:%d" % self.server.port

    def assert_blocked(self, func, label):
        """跑 func，必须抛 WafBlocked，且**请求没有发出去**。"""
        before = len(self.server.received)
        try:
            func()
        except WafBlocked as exc:
            self.assertIn("命中敏感词", exc.verdict.reason)
        else:
            self.fail("%s：应被拦截但放行了" % label)
        time.sleep(0.2)
        self.assertEqual(len(self.server.received), before,
                         "%s：被拦了却还是发出了 %d 条请求"
                         % (label, len(self.server.received) - before))

    def assert_allowed(self, func, label):
        try:
            func()
        except WafBlocked as exc:
            self.fail("%s：被误拦（%s）" % (label, exc.verdict.reason))
        time.sleep(0.2)
        self.assertTrue(self.server.received, "%s：请求没到达服务端" % label)


# ====================================================================
class TestTransportLayer(TransportBase):
    """用户报告的第 1、2 条绕过：http.client / 裸 socket / urllib body。"""

    def test_http_client_delete_blocked(self):
        """HTTPConnection.request("DELETE", ...) —— 主绕过。"""
        import http.client

        def run():
            conn = http.client.HTTPConnection("127.0.0.1", self.server.port,
                                              timeout=5)
            conn.request("DELETE", "/api/users/1")
            conn.getresponse()
        self.assert_blocked(run, "http.client DELETE")

    def test_http_client_post_body_blocked(self):
        import http.client

        def run():
            conn = http.client.HTTPConnection("127.0.0.1", self.server.port,
                                              timeout=5)
            conn.request("POST", "/api/query",
                         body=b'{"sql":"drop table users"}',
                         headers={"Content-Type": "application/json"})
            conn.getresponse()
        self.assert_blocked(run, "http.client POST body")

    def test_http_client_lowlevel_blocked(self):
        """低级流程：putrequest → putheader → endheaders（不经 request）。"""
        import http.client

        def run():
            conn = http.client.HTTPConnection("127.0.0.1", self.server.port,
                                              timeout=5)
            conn.putrequest("DELETE", "/api/users/2")
            conn.putheader("Host", "127.0.0.1")
            conn.endheaders()
            conn.getresponse()
        self.assert_blocked(run, "http.client 低级流程")

    def test_http_client_benign_passes(self):
        import http.client

        def run():
            conn = http.client.HTTPConnection("127.0.0.1", self.server.port,
                                              timeout=5)
            conn.request("POST", "/api/query", body=b'{"sql":"select 1"}')
            conn.getresponse()
        self.assert_allowed(run, "http.client 正常 POST")

    def test_raw_socket_delete_blocked(self):
        def run():
            sock = socket.create_connection(("127.0.0.1", self.server.port),
                                            timeout=5)
            try:
                sock.sendall(b"DELETE /api/users/3 HTTP/1.1\r\n"
                             b"Host: 127.0.0.1\r\n\r\n")
            finally:
                sock.close()
        self.assert_blocked(run, "裸 socket DELETE")

    def test_raw_socket_body_blocked(self):
        """手写报文一次发完时，body 也在一起扫。"""
        def run():
            sock = socket.create_connection(("127.0.0.1", self.server.port),
                                            timeout=5)
            try:
                sock.sendall(b"POST /api/query HTTP/1.1\r\n"
                             b"Host: 127.0.0.1\r\n"
                             b"Content-Length: 26\r\n\r\n"
                             b'{"sql":"truncate users"}')
            finally:
                sock.close()
        self.assert_blocked(run, "裸 socket POST body")

    def test_raw_socket_benign_passes(self):
        def run():
            sock = socket.create_connection(("127.0.0.1", self.server.port),
                                            timeout=5)
            try:
                sock.sendall(b"GET /health HTTP/1.1\r\n"
                             b"Host: 127.0.0.1\r\n\r\n")
                sock.recv(1024)
            finally:
                sock.close()
        self.assert_allowed(run, "裸 socket 正常 GET")

    def test_raw_socket_non_http_untouched(self):
        """Redis 内联命令这类非 HTTP 流量不能碰。

        "DEL key\\r\\n" 和 HTTP 请求行长得都像（动词 + 参数），
        判据里必须有 "HTTP/x.y" 这一段才不会误伤。
        断言的是"原样发出去且没被拦"，不是"服务端收不到" ——
        这些字节本来就不是 HTTP，服务端照样会收到它们。
        """
        payload = b"DEL user:1\r\nTRUNCATE myfile\r\n"

        def run():
            sock = socket.create_connection(("127.0.0.1", self.server.port),
                                            timeout=5)
            try:
                sock.sendall(payload)
            finally:
                sock.close()

        before = len(self.server.received)
        try:
            run()
        except WafBlocked as exc:
            self.fail("非 HTTP 协议被误拦：%s" % exc.verdict.reason)
        time.sleep(0.3)
        self.assertEqual(len(self.server.received), before + 1,
                         "非 HTTP 报文没有原样发出去")
        self.assertTrue(self.server.received[-1].startswith(b"DEL user:1"),
                        "服务端收到的内容被改动了")

    def test_urllib_request_object_body_blocked(self):
        """urllib 的 body 在 Request 对象上，不在 urlopen 的参数上。

        实测漏过：``urlopen(Request(url, data=payload))`` 时
        ``data`` 形参恒为 None，早先只看参数 → body 完全没检查。
        """
        import urllib.request

        def run():
            req = urllib.request.Request(
                self.url + "/api/query", data=b'{"sql":"delete from users"}',
                method="POST",
                headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5)
        self.assert_blocked(run, "urllib Request(data=...)")

    def test_urllib_urlopen_data_blocked(self):
        import urllib.request

        def run():
            urllib.request.urlopen(self.url + "/api/query",
                                   data=b'{"sql":"delete from users"}',
                                   timeout=5)
        self.assert_blocked(run, "urllib urlopen(data=...)")

    def test_urllib_benign_passes(self):
        import urllib.request

        def run():
            urllib.request.urlopen(self.url + "/health", timeout=5)
        self.assert_allowed(run, "urllib 正常 GET")

    def test_httpx_delete_blocked(self):
        """httpx 回归（用户没测，顺手补上）。"""
        try:
            import httpx
        except ImportError:
            self.skipTest("httpx 未安装")
        self.assert_blocked(
            lambda: httpx.request("DELETE", self.url + "/api/users/9",
                                  timeout=5),
            "httpx DELETE")

    def test_requests_still_blocked(self):
        try:
            import requests
        except ImportError:
            self.skipTest("requests 未安装")
        self.assert_blocked(
            lambda: requests.delete(self.url + "/api/users/1", timeout=5),
            "requests DELETE")

    def test_aiohttp_delete_blocked(self):
        """aiohttp 回归（异步路径，单独跑）。"""
        try:
            import aiohttp
        except ImportError:
            self.skipTest("aiohttp 未安装")
        import asyncio

        async def run():
            async with aiohttp.ClientSession() as session:
                await session.delete(self.url + "/api/users/1")

        before = len(self.server.received)
        try:
            asyncio.new_event_loop().run_until_complete(run())
        except WafBlocked:
            pass
        else:
            self.fail("aiohttp DELETE 应被拦截")
        time.sleep(0.2)
        self.assertEqual(len(self.server.received), before,
                         "aiohttp：被拦了却还是发出了请求")


class TestSingleScanPerRequest(TransportBase):
    """同一请求穿多层（requests → urllib3 → http.client → socket）时只扫一次。

    实测教训：叠层从"多记几条事件"一路恶化到"一次 requests.get 扫 36 次"，
    根因有两个 ——
      1. 补丁不幂等：install_guard(force=True) 被 autohook 反复调用，
         每层包装都被再包一层
      2. 飞行指纹注销得太早：外层扫完就注销，内层挂钩看到的永远是空栈
    两个都要有回归盯着，否则"事件列表里同一条请求出现 N 次"会悄悄回来。
    """

    def _checked_delta(self, func):
        before = dict(guard.stats())
        func()
        time.sleep(0.2)
        after = dict(guard.stats())
        return after["checked"] - before["checked"]

    def test_install_guard_is_idempotent(self):
        """反复 force 安装不能再叠层。"""
        import http.client
        guard.install_guard(patch_subprocess=False, force=True)
        guard.install_guard(patch_subprocess=False, force=True)

        def once():
            conn = http.client.HTTPConnection("127.0.0.1", self.server.port,
                                              timeout=5)
            conn.request("GET", "/health")
            conn.getresponse()

        self.assertEqual(self._checked_delta(once), 1,
                         "同一个请求被扫了多次（补丁叠层了）")

    def test_inner_layers_are_deduped(self):
        """多库叠着走一条请求，只记一次检查。"""
        try:
            import requests
        except ImportError:
            self.skipTest("requests 未安装")
        self.assertEqual(
            self._checked_delta(
                lambda: requests.get(self.url + "/health", timeout=5)),
            1, "requests 一次请求应只扫一次")

    def test_sequential_same_path_not_deduped(self):
        """循环里连续请求同一条路径：每条都要真扫。"""
        import urllib.request

        def three():
            for _ in range(3):
                urllib.request.urlopen(self.url + "/health", timeout=5)

        self.assertEqual(self._checked_delta(three), 3,
                         "连续请求被误判成重复（漏扫）")


class TestRawHttpParser(unittest.TestCase):
    """socket 层报文解析的边界（不装补丁，纯函数）。"""

    def test_origin_form(self):
        parsed = guard.parse_raw_http_request(
            b"GET /a?b=1 HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIsNotNone(parsed)
        method, target, headers, body = parsed
        self.assertEqual(method, "GET")
        self.assertEqual(target, "/a?b=1")
        self.assertEqual(headers.get("Host"), "x")
        self.assertEqual(body, b"")

    def test_absolute_form_and_body(self):
        parsed = guard.parse_raw_http_request(
            b"POST http://h/p HTTP/1.1\r\nHost: h\r\n\r\npayload")
        self.assertEqual(parsed[1], "http://h/p")
        self.assertEqual(parsed[3], b"payload")

    def test_connect_authority_form(self):
        parsed = guard.parse_raw_http_request(
            b"CONNECT h:443 HTTP/1.1\r\nHost: h\r\n\r\n")
        self.assertEqual(parsed[0], "CONNECT")
        self.assertEqual(parsed[1], "h:443")

    def test_response_is_not_a_request(self):
        self.assertIsNone(guard.parse_raw_http_request(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))

    def test_binary_and_text_are_ignored(self):
        for raw in (b"\x00\x01\x02\x03", b"hello world",
                    b"DEL key\r\n", b"USER anonymous\r\n",
                    b"INVITE sip:x SIP/2.0\r\n"):
            self.assertIsNone(guard.parse_raw_http_request(raw),
                              "不该把 %r 当成 HTTP 请求" % raw)

    def test_unknown_method_rejected(self):
        self.assertIsNone(guard.parse_raw_http_request(
            b"FROBNICATE /x HTTP/1.1\r\n\r\n"))

    def test_oversized_chunk_is_bounded(self):
        raw = (b"POST /x HTTP/1.1\r\nHost: h\r\n\r\n" + b"A" * 400000)
        parsed = guard.parse_raw_http_request(raw)
        self.assertIsNotNone(parsed)
        self.assertLessEqual(len(parsed[3]), 262144)


class TestRecursionGuards(TransportBase):
    """工具自身的子进程不能被自己拦，也不能递归。"""

    def test_nested_check_cmd_is_skipped(self):
        """已在扫描中 / 内部动作期间，_check_cmd 必须直接返回。

        修复前：_check_cmd → _console_gate() → get_engine()（冷加载）
        → ReDoS 探测子进程 → guarded_popen → _check_cmd → …… 栈溢出。
        """
        entered = guard._enter_scan()
        self.assertTrue(entered)
        try:
            guard._check_cmd("git rm -rf /", "nested-test")   # 不该抛
        finally:
            guard._exit_scan()

        with guard.internal_call():
            self.assertTrue(guard.is_internal_call())
            guard._check_cmd("git rm -rf /", "internal-test")  # 不该抛
        self.assertFalse(guard.is_internal_call())

    def test_probe_spawn_is_marked_internal(self):
        """regexguard 起探测子进程时要声明内部调用（父进程侧）。"""
        import waf.regexguard as regexguard

        seen = []
        real_run = regexguard.subprocess.run

        def spy(*args, **kwargs):
            seen.append(guard.is_internal_call())
            return real_run(*args, **kwargs)

        regexguard.subprocess.run = spy
        try:
            results, timed_out = regexguard._run_probe(
                [r"\bzq_regression_probe_marker\b"], timeout=60, budget=0.05)
        finally:
            regexguard.subprocess.run = real_run
        self.assertTrue(seen, "探测子进程没有发生，用例无效")
        self.assertTrue(all(seen), "探测那一跳没有被标记为内部调用")
        self.assertFalse(timed_out)


class TestNewRuleCoverage(unittest.TestCase):
    """本轮补进词表/规则的破坏性写法（用户实测绕过的那几条）。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="agentwaf-rules-")
        cls.path = os.path.join(cls.tmp, "rules.json")
        rules.save_document(rules.default_document(), cls.path)
        cls.engine = engine_mod.RuleEngine(cls.path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _scan(self, body):
        from urllib.parse import urlsplit
        from waf.models import ScanTarget
        url = "http://127.0.0.1/x"
        parts = urlsplit(url)
        target = ScanTarget(kind="request", method="POST", url=url, body=body,
                            host=parts.netloc, path=parts.path,
                            query=parts.query, tool="test")
        return self.engine.scan(target, log=False)

    def assert_blocked(self, body, label):
        verdict = self._scan(body)
        self.assertTrue(verdict.blocked, "应拦未拦：%s（%s）" % (label, body))

    def assert_allowed(self, body, label):
        verdict = self._scan(body)
        self.assertFalse(verdict.blocked,
                         "误拦：%s（%s）" % (label, [h.keyword for h in verdict.hits]))

    # -- R-102 补的写法 --------------------------------------------------

    def test_truncate_bare_identifier(self):
        for body in ('{"sql":"TRUNCATE users"}',
                     '{"sql":"truncate table users"}',
                     '{"sql":"1; TRUNCATE users;-- -"}',
                     '{"sql":"TRUNCATE `users`"}'):
            self.assert_blocked(body, "TRUNCATE 直接跟标识符")

    def test_redis_flush(self):
        self.assert_blocked('{"cmd":"FLUSHDB"}', "FLUSHDB")
        self.assert_blocked('{"cmd":"flushdb"}', "flushdb")

    def test_mongo_camel_case(self):
        for body in ('{"code":"db.dropDatabase()"}',
                     '{"code":"db.drop_database()"}',
                     '{"code":"users.drop_collection()"}',
                     '{"code":"collection.drop()"}',
                     '{"code":"deleteCollection(9)"}'):
            self.assert_blocked(body, "Mongo/ORM 驼峰写法")

    def test_natural_language_truncate_allowed(self):
        """自然语言里的 truncate 不能拦（误拦比漏拦更容易让人关掉工具）。"""
        for body in ('{"text":"truncate the file name to 10 chars"}',
                     '{"text":"please truncate this string"}',
                     '{"text":"truncate lines longer than 80"}',
                     '{"comment":"we truncate data after 30 days"}'):
            self.assert_allowed(body, "自然语言 truncate")

    # -- R-107（原 R-201 监控项提到 block）--------------------------------

    def test_grant_revoke_blocked(self):
        self.assert_blocked('{"sql":"GRANT ALL PRIVILEGES ON *.* TO \'u\'@\'%\'"}',
                            "GRANT 提权")
        self.assert_blocked('{"sql":"REVOKE ALL ON *.* FROM u"}', "REVOKE")

    def test_alter_table_drop_blocked(self):
        self.assert_blocked('{"sql":"ALTER TABLE users DROP COLUMN email"}',
                            "ALTER TABLE ... DROP")
        self.assert_blocked('{"sql":"alter table t drop constraint c"}',
                            "DROP CONSTRAINT")

    def test_oauth_and_permission_words_allowed(self):
        """grant 的裸词不能拦：OAuth 的 grant_type 是最高频正常参数之一。"""
        for body in ('{"grant_type":"authorization_code"}',
                     'grant_type=client_credentials&scope=read',
                     '{"scope":"user:read grant:write"}',
                     '{"permission":"grant"}'):
            self.assert_allowed(body, "OAuth / 权限词")

    def test_traditional_database_rules_unchanged(self):
        for body in ('{"sql":"DROP TABLE users"}',
                     '{"sql":"delete from users"}',
                     '{"sql":"TRUNCATE TABLE t"}',
                     '{"sql":"ShUtDoWn"}'):
            self.assert_blocked(body, "原有 R-102 不能回退")

    def test_r107_is_in_defaults(self):
        doc = rules.default_document()
        by_id = {rule["id"]: rule for rule in doc["rules"]}
        self.assertIn("R-107", by_id, "R-107 没有进默认规则集")
        self.assertEqual(by_id["R-107"]["action"], "block")
        # grant / revoke 不该继续留在 R-201 的关键词里（重复命中=噪声）
        keywords = [k.strip().lower() for k in by_id["R-201"]["keywords"]]
        self.assertNotIn("grant", keywords)
        self.assertNotIn("revoke", keywords)

    def test_defaults_rev_bumped(self):
        """内置规则内容变了就必须抬版本，否则老用户的 rules.json 不会迁移。"""
        self.assertGreaterEqual(rules.DEFAULTS_REV, 16,
                                "改了内置规则但没抬 DEFAULTS_REV")


class TestAutohookPatchDetection(unittest.TestCase):
    """autohook 判断"requests 补丁到底装上没有"的口径。

    实测踩过：它看的是 ``Session.request``，而 guard 包的是
    ``Session.send`` —— 判断永远为假 → import 钩子摘不掉 →
    每次 import HTTP 库都 force 重装 → 补丁叠层（一次请求扫 36 次）。
    """

    def test_requests_ready_sees_the_real_patch_point(self):
        try:
            import requests
        except ImportError:
            self.skipTest("requests 未安装")
        from waf import autohook

        snapshot = requests.Session.send
        try:
            guard._installed = False
            guard.install_guard(patch_subprocess=False)
            self.assertTrue(autohook._requests_ready(),
                            "_requests_ready() 看不到已经装好的补丁")
        finally:
            requests.Session.send = snapshot
            guard._installed = False


class TestPowerShellChannel(unittest.TestCase):
    """PowerShell 通道：Invoke-WebRequest / Invoke-RestMethod。

    实测缺口：这条通道原先只删 curl 别名 + 前置 PATH，
    ``Invoke-RestMethod -Method Delete`` 完全没有检查 —— 它既不走
    curl 也不走 PATH。
    """

    def setUp(self):
        self.ps1 = os.path.join(ROOT, "bin", "waf.ps1")
        self.hook = os.path.join(ROOT, "waf", "pshook.py")
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-ps-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- 静态检查 --------------------------------------------------------

    def test_ps1_wraps_both_cmdlets(self):
        with open(self.ps1, encoding="utf-8") as fh:
            text = fh.read()
        for name in ("Invoke-WebRequest", "Invoke-RestMethod"):
            self.assertIn(name, text, "waf.ps1 没有包装 %s" % name)
        self.assertIn("pshook", text, "waf.ps1 没有调用 pshook.py")

    def test_ps1_forwards_to_module_qualified_cmdlet(self):
        """必须从模块限定名生成包装 —— 否则重新加载 profile 时会包住自己。"""
        with open(self.ps1, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("Microsoft.PowerShell.Utility\\", text)

    def test_ps1_anchor_tolerates_crlf(self):
        """ProxyCommand 输出的换行在不同版本上不同，锚点必须容忍 \\r。

        实测踩过：写死 ``process\\n{\\n`` 时两个 cmdlet 都报
        "unexpected proxy layout"，包装根本没装上 —— 表面上一切正常，
        直到真的发一个 DELETE。
        """
        with open(self.ps1, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn(r"process\r?\n\{\r?\n", text)

    def test_ps1_is_ascii(self):
        with open(self.ps1, "rb") as fh:
            data = fh.read()
        try:
            data.decode("ascii")
        except UnicodeDecodeError as exc:
            self.fail("bin/waf.ps1 含非 ASCII（PS 5.1 按 ANSI 读会乱码）：%s" % exc)

    def test_hook_exists_and_is_valid_python(self):
        self.assertTrue(os.path.isfile(self.hook), "waf/pshook.py 缺失")
        with open(self.hook, "rb") as fh:
            compile(fh.read(), self.hook, "exec")

    def test_hook_path_matches_ps1_reference(self):
        with open(self.ps1, encoding="utf-8") as fh:
            text = fh.read()
        self.assertIn("waf\\pshook.py", text,
                      "waf.ps1 指向的钩子路径变了，检查两边是否一致")

    # -- 行为检查（真的跑一次钩子）----------------------------------------

    def _run_hook(self, payload):
        env = dict(os.environ)
        env["AGENTWAF_RULES_FILE"] = self.rules_path
        env["WAF_ALWAYS_ON"] = "1"
        env["WAF_NO_LOG"] = "1"
        env.pop("WAF_QUIET", None)
        env.pop("WAF_DISABLE", None)
        proc = subprocess.run(
            [sys.executable, self.hook],
            input=json.dumps(payload).encode("utf-8"),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, env=env, cwd=ROOT)
        return proc.returncode, proc.stderr.decode("utf-8", "replace")

    def test_hook_blocks_delete(self):
        code, err = self._run_hook({"method": "DELETE",
                                    "uri": "http://t/api/users/1"})
        self.assertEqual(code, 126, "pshook 没有按 126 退出：%s" % err[:400])
        self.assertIn("命中敏感词", err)
        self.assertIn("content_scan", err)

    def test_hook_blocks_body(self):
        code, err = self._run_hook({"method": "POST",
                                    "uri": "http://t/api/query",
                                    "body": '{"sql":"drop table users"}'})
        self.assertEqual(code, 126, "body 没被检查：%s" % err[:400])

    def test_hook_allows_benign(self):
        code, err = self._run_hook({"method": "GET", "uri": "http://t/health"})
        self.assertEqual(code, 0, "正常请求被拦了：%s" % err[:400])

    def test_hook_allows_oauth_grant_type(self):
        code, err = self._run_hook({"method": "POST", "uri": "http://t/oauth",
                                    "body": "grant_type=authorization_code"})
        self.assertEqual(code, 0, "OAuth 请求被误拦：%s" % err[:400])

    def test_hook_disabled_by_env(self):
        env = dict(os.environ)
        env["AGENTWAF_RULES_FILE"] = self.rules_path
        env["WAF_ALWAYS_ON"] = "1"
        env["WAF_DISABLE"] = "1"
        proc = subprocess.run(
            [sys.executable, self.hook],
            input=json.dumps({"method": "DELETE",
                              "uri": "http://t/x/delete"}).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, env=env, cwd=ROOT)
        self.assertEqual(proc.returncode, 0)
        self.assertNotIn("命中敏感词", proc.stderr.decode("utf-8", "replace"))

    def test_hook_garbage_input_does_not_crash(self):
        """stdin 不是 JSON 也不能崩（调用方按放行+告警处理）。"""
        env = dict(os.environ)
        env["AGENTWAF_RULES_FILE"] = self.rules_path
        env["WAF_ALWAYS_ON"] = "1"
        env["WAF_NO_LOG"] = "1"
        proc = subprocess.run(
            [sys.executable, self.hook], input=b"not-json-at-all",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, env=env, cwd=ROOT)
        self.assertIn(proc.returncode, (0, 1),
                      "钩子对非 JSON 输入返回了异常退出码：%d" % proc.returncode)


# __APPEND_MARKER__
