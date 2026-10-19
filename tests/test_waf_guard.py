# -*- coding: utf-8 -*-
"""HuntGuard 自测：覆盖归一化、规则、引擎、curl shim、guard、API。"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import config, logstore, normalize, rules           # noqa: E402
from waf.engine import RuleEngine                            # noqa: E402
from waf.models import ScanTarget                            # noqa: E402


class BaseWafTest(unittest.TestCase):
    """每个测试用临时规则文件，避免污染真实配置。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-test-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)
        self.engine = RuleEngine(self.rules_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # -- 便捷断言 ----------------------------------------------------

    def block(self, url="", body="", headers=None, method="GET", raw_cmd="",
              source_hint=""):
        target = ScanTarget(kind="request", method=method, url=url, body=body,
                            headers=headers or {}, raw_cmd=raw_cmd, tool="test")
        if url:
            from urllib.parse import urlsplit
            parts = urlsplit(url)
            target.host = parts.netloc
            target.path = parts.path
            target.query = parts.query
        return self.engine.scan(target, log=False)

    def assert_blocked(self, **kwargs):
        verdict = self.block(**kwargs)
        self.assertTrue(verdict.blocked,
                        "应被拦截但放行了：%s" % (kwargs,))
        return verdict

    def assert_allowed(self, **kwargs):
        verdict = self.block(**kwargs)
        self.assertFalse(verdict.blocked,
                         "应放行但被拦截：%s → %s" % (kwargs, verdict.reason))
        return verdict


# ====================================================================
class TestProxyServer(BaseWafTest):
    """验证代理能拦下命中敏感词的请求，并正常转发放行请求。"""

    def test_proxy_blocks(self):
        import socket
        import threading
        from waf.proxy import ProxyServer

        port = 18999
        # 代理遵从激活态（心跳 + 总开关双条件），而总开关读的是
        # data/rules.json —— 那是用户自己的文件，可能正处于"已暂停"。
        # 不隔离的话，这条测试的结果会跟着用户当前开没开控制台变，
        # 表现为"超时/放行穿透"这种看起来像功能坏了的假失败。
        # 换成 BaseWafTest 造的临时规则（enabled=true）才可预期。
        rules_path_backup = os.environ.get("AGENTWAF_RULES_FILE")
        os.environ["AGENTWAF_RULES_FILE"] = self.rules_path
        os.environ["WAF_ALWAYS_ON"] = "1"
        os.environ["WAF_NO_LOG"] = "1"
        # 引擎是全局单例，此时可能已经加载了用户真实的 rules.json
        # （那份通常 enabled=false，于是代理直接透传、测试拿到 404）。
        # 必须清掉缓存，让它按刚设的临时规则重建。
        from waf import engine as _engine_mod
        _engine_mod._ENGINE = None
        server = ProxyServer(host="127.0.0.1", port=port, mitm=False)
        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        time.sleep(0.5)

        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=10)
            sock.sendall(b"GET http://127.0.0.1/delete.php HTTP/1.1\r\n"
                         b"Host: 127.0.0.1\r\n"
                         b"Connection: close\r\n\r\n")
            data = b""
            sock.settimeout(6)
            # 不能一直读到连接关闭：代理在 keep-alive 下不会主动关连接
            # （这是正常 HTTP 行为，不是 bug），死等会把测试卡超时。
            # 按 Content-Length 判断收完即可，另外留个兜底超时。
            while True:
                try:
                    chunk = sock.recv(65536)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                head, _, rest = data.partition(b"\r\n\r\n")
                match = re.search(rb"Content-Length:\s*(\d+)", head, re.I)
                if match and len(rest) >= int(match.group(1)):
                    break
            sock.close()

            text = data.decode("utf-8", "replace")
            self.assertIn("403", text.split("\r\n", 1)[0],
                          "代理应返回 403：%s" % text[:200])
            self.assertIn("命中敏感词", text)
            self.assertIn("X-HuntGuard", text)
        finally:
            server.shutdown()
            os.environ.pop("WAF_ALWAYS_ON", None)
            os.environ.pop("WAF_NO_LOG", None)
            # 还原规则文件指向，避免影响同进程内其它测试
            if rules_path_backup is None:
                os.environ.pop("AGENTWAF_RULES_FILE", None)
            else:
                os.environ["AGENTWAF_RULES_FILE"] = rules_path_backup
            # 引擎是全局单例，清掉缓存让下条测试重新读自己的规则文件
            from waf import engine as _engine
            _engine._ENGINE = None



class TestAllowlistBypass(unittest.TestCase):
    """回归：白名单/排除机制不能被构造性绕过。

    这三个 bug 是叠加的，单独看每个都不显眼，合起来等于"在 payload
    前面塞一个正常业务字段名就免检"。实测发现，已修：

      a) 去重发生在排除之前、且去重键不含位置 → 被抑制的那条
         在去重表里占位，真命中被当重复丢弃
      b) 每个变体只匹配第一个出现位置 → 同字段第二次出现不被检查
      c) exclude 是"附近 24 字符即豁免"→ 相距稍远就整条放过

    下面每个用例都是实际能用的绕过 payload。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-bypass-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)
        self.engine = RuleEngine(self.rules_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _scan(self, url="", body=""):
        from urllib.parse import urlsplit
        target = ScanTarget(kind="request",
                            method="POST" if body else "GET",
                            url=url, body=body, raw_cmd=url, tool="test")
        if url:
            parts = urlsplit(url)
            target.host, target.path, target.query = (
                parts.netloc, parts.path, parts.query)
        return self.engine.scan(target, log=False)

    def test_soft_delete_field_does_not_shield_payload(self):
        """body 里有 deleted_at 不能保护后面的 delete。"""
        verdict = self._scan(
            url="http://t/api",
            body='{"deleted_at":null,"action":"delete","id":9}')
        self.assertTrue(verdict.blocked,
                        "正常业务字段名把整个 body 变成免检区")

    def test_is_deleted_does_not_shield_remove(self):
        verdict = self._scan(
            url="http://t/api",
            body='{"is_deleted":false,"op":"remove","id":1}')
        self.assertTrue(verdict.blocked)

    def test_soft_delete_flag_does_not_shield_purge(self):
        verdict = self._scan(
            url="http://t/api",
            body='{"soft_delete":true,"op":"purge_all"}')
        self.assertTrue(verdict.blocked)

    def test_second_occurrence_still_checked(self):
        """同字段里敏感词出现两次，第一次在白名单语境、第二次是攻击。"""
        verdict = self._scan(
            url="http://t/api?a=delete&b=deleted_at&c=delete")
        self.assertTrue(verdict.blocked)

    def test_exclude_does_not_cover_distant_word(self):
        """exclude 只抑制重叠命中，不是"附近有就算"。"""
        verdict = self._scan(url="http://t/api?action=delete&ref=deleted_at")
        self.assertTrue(verdict.blocked)

    # ---- 反向：白名单本身必须仍然有效（不能为了修绕过而误报）----

    def test_soft_delete_field_alone_allowed(self):
        self.assertFalse(self._scan(
            url="http://127.0.0.1/api?deleted_at=2024-01-01").blocked,
            "软删除字段本身不该报警")
        self.assertFalse(self._scan(
            url="http://t/api", body='{"deleted_at":null,"page":1}').blocked)
        self.assertFalse(self._scan(
            url="http://t/api", body='{"is_deleted":0,"deletable":false}').blocked)


class TestNormalizeOffsetMapping(unittest.TestCase):
    """回归：归一化 offset 必须能翻译回原文。

    早先拿归一化后的 offset 直接切原文 / 判断 exclude，
    归一化会改变长度（url_decode 变短、compact 删字符），于是：
      * matched_text 指向错误上下文
      * exclude 按错误位置判断 → 误拦漏拦双向
    实测 `?deleted_at=2024-01-01` 本该放行却被拦（compact 变体上
    offset=13 落在原文别处）。
    """

    def test_map_points_to_real_occurrence(self):
        from waf import normalize as _norm
        ops = ["url_decode", "html_unescape", "unicode_unescape",
               "fold_fullwidth", "strip_invisible", "collapse_ws",
               "compact", "lower"]

        cases = [
            "deleted_at=2024-01-01",
            '{"deleted_at":null,"action":"delete","id":9}',
            "http://x/api?name=hello%20world&action=delete",
            "a a a  delete",
        ]
        for text in cases:
            for label, variant, index_map in _norm.build_variants_with_map(text, ops):
                self.assertEqual(len(variant), len(index_map),
                                 "%s 的映射长度与文本不一致" % label)
                pos = variant.find("delete")
                while pos >= 0:
                    origin = index_map[pos]
                    # 映射回原文的位置必须真的是 delete 的开头
                    self.assertTrue(
                        text[origin:origin + 6].lower() == "delete",
                        "变体 %s 位置 %d 映射到原文 %d，那里是 %r "
                        "而不是 delete" % (label, pos, origin,
                                          text[origin:origin + 6]))
                    pos = variant.find("delete", pos + 1)

    def test_encoded_payload_still_blocked(self):
        """带 URL 编码的敏感词仍要拦（映射不能把命中弄丢）。"""
        tmp = tempfile.mkdtemp(prefix="agentwaf-map-")
        try:
            rp = os.path.join(tmp, "rules.json")
            rules.save_document(rules.default_document(), rp)
            engine = RuleEngine(rp)
            from urllib.parse import urlsplit
            url = "http://x/api?name=hello%20world%20foo&action=delete"
            target = ScanTarget(kind="request", method="GET", url=url,
                                raw_cmd=url, tool="test")
            parts = urlsplit(url)
            target.host, target.path, target.query = (
                parts.netloc, parts.path, parts.query)
            verdict = engine.scan(target, log=False)
            self.assertTrue(verdict.blocked)
            # 断言方式说明（改过两次，两次都因为断言本身写得太脆）：
            #
            # 1. 最早用 hit.matched_text[20:26] == 'delete' ——
            #    matched_text 是"命中点前后各 20 字符"的片段，同一个
            #    关键词可能产生多个偏移不同的命中，一加规则就红（假失败）。
            #
            # 2. 改成比对 url[offset:offset+6] —— 又错了：
            #    offset 是**相对该字段文本**的（url / query / path 各算各的），
            #    拿全 URL 去切必然错位。实测 `?name=hello%20world%20foo&
            #    action=delete` 里 query 字段的 offset 31 在 URL 上指向
            #    别的字符。
            #
            # 现在按"命中所在的源字段"取文本再比对。
            #
            # 注意两套坐标容易混：
            #   hit.source    —— 字段名（url / query / path …）
            #   hit.field_name —— **归一化变体标签**（normalized / compact）
            # offset 是相对 hit.source 那个字段的原始文本。
            source_text = {}
            for src, txt in target.fields():
                source_text[src] = txt
            checked = 0
            for hit in verdict.hits:
                if "delete" not in hit.keyword.lower():
                    continue
                text = source_text.get(hit.source, "")
                if not text:
                    continue
                checked += 1
                pos = hit.offset + (1 if hit.keyword.startswith("=") else 0)
                self.assertEqual(
                    text[pos:pos + 6].lower(), "delete",
                    "offset 没指向该字段里的真实命中点"
                    "（source=%s offset=%d → %r，matched_text=%r）"
                    % (hit.source, hit.offset, text[pos:pos + 8],
                       hit.matched_text))
            self.assertGreater(checked, 0, "没有任何 delete 命中")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)



class TestCurlStdinAndMisc(unittest.TestCase):
    """回归：stdin 接管与 MISC 参数。

    这几条都是实测确认的缺口，修完后必须有测试盯着 ——
    否则下次改动又会静默退化（前两轮的教训：改代码不补闸）。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-stdin-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)
        self.engine = RuleEngine(self.rules_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ---------- argv 回写：stdin 被消费后 curl 必须仍能拿到内容 ----------

    def _fake_curl_env(self, name="fakecurl.py"):
        """造一个"假真实 curl"，让它打印收到的 argv 与文件内容。

        为什么需要：stdin 接管最危险的失败模式不是"漏拦"，而是
        **argv 没回写、curl 去读已被消费空的 stdin** ——
        用户上传的内容静默变空。这个错误只有看"curl 实际收到什么"
        才能发现，光测拦截与否看不出来。
        """
        fake = os.path.join(self.tmp, name)
        with open(fake, "w", encoding="utf-8") as fh:
            fh.write(
                "import json, sys\n"
                "a = sys.argv[1:]\n"
                "print('ARGV=' + json.dumps(a))\n"
                "print('STDIN_LEN=%d' % len(sys.stdin.buffer.read()))\n"
                "for i, x in enumerate(a):\n"
                "    if x in ('-T', '--upload-file', '-K', '--config') "
                "and i + 1 < len(a):\n"
                "        try:\n"
                "            with open(a[i+1], 'rb') as f:\n"
                "                print('FILE=%r' % f.read()[:60])\n"
                "        except Exception as exc:\n"
                "            print('FILE_ERR=%r' % exc)\n"
                "    if x in ('-d', '--data') and i + 1 < len(a):\n"
                "        v = a[i+1]\n"
                "        if v.startswith('@'):\n"
                "            try:\n"
                "                with open(v[1:], 'rb') as f:\n"
                "                    print('FILE=%r' % f.read()[:60])\n"
                "            except Exception as exc:\n"
                "                print('FILE_ERR=%r' % exc)\n")
        if os.name == "nt":
            wrap = os.path.join(self.tmp, name + ".cmd")
            with open(wrap, "w", encoding="ascii") as fh:
                fh.write('@echo off\r\n"%s" "%s" %%*\r\n'
                         % (sys.executable, fake))
        else:
            wrap = os.path.join(self.tmp, name + ".sh")
            with open(wrap, "w", encoding="utf-8") as fh:
                fh.write('#!/bin/sh\nexec "%s" "%s" "$@"\n'
                         % (sys.executable, fake))
            os.chmod(wrap, 0o755)
        env = dict(os.environ)
        env["AGENTWAF_RULES_FILE"] = self.rules_path
        env["WAF_ALWAYS_ON"] = "1"
        env["WAF_NO_LOG"] = "1"
        env["WAF_REAL_CURL"] = wrap
        return env

    def _run_shim(self, args, stdin_data, name="fakecurl.py"):
        env = self._fake_curl_env(name)
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "waf", "curlshim.py")] + args,
            input=stdin_data, capture_output=True, env=env, timeout=90)

    def test_upload_stdin_argv_rewritten(self):
        """-T - ：stdin 内容要落盘，argv 要改写成临时文件路径。

        这里踩过一个 bug：接管了 stdin 但没回写 argv，
        curl 去读已空的 stdin，**用户上传的东西静默变空**。
        """
        proc = self._run_shim(["-s", "-T", "-", "http://t/upload"],
                              b"id=1&name=test")
        out = proc.stdout.decode("utf-8", "replace")
        self.assertIn("ARGV=", out, "假 curl 没被调用：%s" % out[:200])
        self.assertNotIn('"-T","-"', out.replace(" ", ""),
                         "-T 的 argv 没回写成临时文件，curl 会读到空 stdin")
        self.assertIn("FILE=b'id=1&name=test'", out,
                      "curl 从临时文件读到的内容不对：%s" % out[:300])

    def test_body_stdin_argv_rewritten(self):
        """-d @- ：body 走 stdin，同样要回写 argv。"""
        proc = self._run_shim(["-s", "-d", "@-", "http://t/api"],
                              b"id=1&name=test")
        out = proc.stdout.decode("utf-8", "replace")
        self.assertNotIn("@-", out,
                         "-d @- 的 argv 没回写（应变成 @<tmp>）")
        self.assertIn("FILE=b'id=1&name=test'", out,
                      "curl 读到的 body 不对：%s" % out[:300])

    def test_config_stdin_argv_rewritten(self):
        """-K - ：配置走 stdin，同样要回写 argv。"""
        proc = self._run_shim(["-s", "-K", "-"],
                              b"url = http://127.0.0.1:1/ok\n")
        out = proc.stdout.decode("utf-8", "replace")
        self.assertNotIn('"-K","-"', out.replace(" ", ""),
                         "-K 的 argv 没回写成临时文件")
        self.assertIn("url = http://127.0.0.1:1/ok", out,
                      "curl 读到的配置不对：%s" % out[:300])

    def test_stdin_consumed_by_us_not_curl(self):
        """stdin 应当被我们读完（STDIN_LEN=0），内容才算真的被扫过。"""
        proc = self._run_shim(["-d", "@-", "http://t/api"], b"x=1")
        out = proc.stdout.decode("utf-8", "replace")
        self.assertIn("STDIN_LEN=0", out,
                      "stdin 没被 shim 消费，说明内容没进扫描面")

    def test_inline_long_option_keeps_equals(self):
        """--config=- 改写后必须保住等号，否则 curl 报 unknown option。"""
        env = self._fake_curl_env(name="fc.py")
        proc = subprocess.run(
            [sys.executable, os.path.join(ROOT, "waf", "curlshim.py"),
             "-s", "--config=-"],
            input=b"url = http://127.0.0.1:1/ok\n",
            capture_output=True, env=env, timeout=90)
        err = proc.stderr.decode("utf-8", "replace").lower()
        self.assertNotIn("unknown option", err,
                         "argv 被改写坏了（丢了 =）：%s" % err[:200])
        out = proc.stdout.decode("utf-8", "replace")
        self.assertIn("--config=", out,
                      "长选项的等号没保住：%s" % out[:200])

    # ---------- MISC / 目标改写 ----------

    def test_url_query_goes_into_query_field(self):
        """--url-query 的值要拼进 query 字段（不只是 raw 兜底）。"""
        from waf.curlshim import parse_curl_args
        target, _info = parse_curl_args(
            ["--url-query", "a=delete_all", "http://t/api"])
        self.assertIn("delete_all", target.query or "",
                      "--url-query 的值没进 query 字段")

    def test_connect_to_overrides_host(self):
        """--connect-to 改写出的真实主机必须可见（否则 host 白名单被骗）。"""
        from waf.curlshim import parse_curl_args
        target, _info = parse_curl_args([
            "--connect-to", "good.com:443:evil.com:443",
            "https://good.com/x"])
        self.assertEqual(target.host, "evil.com",
                         "别名匹配时 host 应换成真实主机")
        self.assertIn("evil.com", target.headers.get("X-WAF-Real-Host", ""),
                      "真实主机没进扫描面")

    def test_multiple_connect_to_all_recorded(self):
        """多个 --connect-to 时每个真实主机都要记下来。"""
        from waf.curlshim import parse_curl_args
        target, _info = parse_curl_args([
            "--connect-to", "a.com:443:x1.evil.com:443",
            "--connect-to", "b.com:443:x2.evil.com:443",
            "http://a.com/x"])
        header = target.headers.get("X-WAF-Real-Host", "")
        self.assertIn("x1.evil.com", header)
        self.assertIn("x2.evil.com", header,
                      "第二个 --connect-to 的真实主机丢了")

    def test_connect_to_cannot_spoof_host_allowlist(self):
        """核心安全断言：URL 命中白名单但真实目标不在，就不能豁免。"""
        doc = rules.load_document(self.rules_path)
        for entry in doc["allowlist"]:
            if entry["id"] == "A-001":
                entry["enabled"] = True
        rules.save_document(doc, self.rules_path)
        engine = RuleEngine(self.rules_path)

        from waf.curlshim import parse_curl_args
        from urllib.parse import urlsplit

        def blocked(argv):
            target, _ = parse_curl_args(argv)
            parts = urlsplit(target.url or "")
            target.path = parts.path or target.path
            target.query = parts.query or target.query
            return engine.scan(target, log=False).blocked

        self.assertFalse(blocked(["http://127.0.0.1:8898/api/x"]),
                         "纯白名单靶场应放行")
        self.assertTrue(blocked([
            "--connect-to", "127.0.0.1:8898:evil.com:443",
            "http://127.0.0.1:8898/delete"]),
            "--connect-to 骗过了 host 级白名单")



class TestRegexGuard(unittest.TestCase):
    """回归：病态正则会拖死整个工具，必须在编译期挡住。

    实测（本机 Python 3.8）：
      (a+)+$    对 "a"*26+"!"  →  4.69s
      (\w+)+$   对 "a"*26+"!"  →  5.42s
      ([a-z]+)*$ 对 "a"*26+"!"  →  7.08s
      (a|a)*$    对 "a"*26+"!"  →  9.94s
    而这类规则可以由用户在 UI 里直接添加。加上之后每个请求都会卡在
    engine.scan 里 —— 拦截器形同瘫痪，而且 Python 的 re 没有超时机制，
    主线程一旦进去连 Ctrl+C 都出不来。

    所以检测放在**子进程**里做，超时直接 kill。
    """

    def setUp(self):
        from waf import regexguard
        regexguard.clear_cache()
        self.rg = regexguard

    def test_dangerous_patterns_rejected(self):
        """真正会爆炸的形态必须被识别。

        注意这些形态的共同点：**整体匹配必然失败**（锚点 $ 或末尾
        字面量终止符）。CPython 的 re 只在失败时才走满回溯 ——
        这也是为什么采样输入必须带终止符（实测：纯 "aaaa" 是 0.0000s）。
        """
        dangerous = ["(a+)+$", "(a+)*b", r"(\w+)+$", r"(\d+)+$",
                     "([a-z]+)*$", "(a|a)*$", "(x+x+)+y"]
        for pattern in dangerous:
            reason = self.rg.check_pattern(pattern)
            self.assertTrue(reason,
                            "病态正则 %r 未被识别" % pattern)

    def test_normal_rules_not_rejected(self):
        """现有内置规则一条都不能被误杀（否则会静默降低防护）。"""
        from waf import rules as _rules
        doc = _rules.default_document()
        flagged = []
        for rule in doc["rules"]:
            for key in ("regex", "exclude"):
                for pattern in (rule.get(key) or []):
                    if self.rg.check_pattern(pattern):
                        flagged.append((rule["id"], pattern))
        self.assertEqual(flagged, [],
                         "内置规则被误判为危险：%s" % flagged[:3])

    def test_engine_still_scans_when_a_regex_is_rejected(self):
        """被拒的正则不该影响同规则的其它正则，也不该让扫描卡死。"""
        import tempfile as _tf
        import shutil as _sh
        from waf import rules as _rules
        from waf.engine import RuleEngine
        from waf.models import ScanTarget

        tmp = _tf.mkdtemp(prefix="agentwaf-redos-")
        try:
            rp = os.path.join(tmp, "rules.json")
            doc = _rules.default_document()
            doc["rules"].append({
                "id": "R-999", "name": "redos", "enabled": True,
                "severity": "high", "action": "block", "match_mode": "regex",
                "keywords": [],
                "regex": ["(a+)+$", r"\btruncate\s+table\b"],
                "exclude": [], "note": "t",
            })
            _rules.save_document(doc, rp)
            engine = RuleEngine(rp)

            # 病态正则被停用
            rejected = [r[1] for r in getattr(engine, "_rejected_regexes", [])]
            self.assertIn("(a+)+$", rejected)

            # 同规则里正常的正则仍然生效
            url = "http://x/?q=truncate+table+users"
            target = ScanTarget(kind="request", method="GET", url=url,
                                raw_cmd=url, tool="test")
            target.host, target.path, target.query = "x", "/", "q=truncate table users"
            started = time.time()
            verdict = engine.scan(target, log=False)
            elapsed = time.time() - started
            self.assertTrue(verdict.blocked, "正常正则被误停用")
            self.assertLess(elapsed, 2.0,
                            "扫描耗时 %.1fs —— 病态正则没被挡住" % elapsed)

            # 关键：病态载荷不会卡死
            bad = "a" * 30 + "!"
            target2 = ScanTarget(kind="request", method="GET",
                                 url="http://x/?q=" + bad, raw_cmd="x", tool="t")
            target2.host, target2.path, target2.query = "x", "/", "q=" + bad
            started = time.time()
            engine.scan(target2, log=False)
            self.assertLess(time.time() - started, 2.0,
                            "病态载荷导致扫描卡住")
        finally:
            _sh.rmtree(tmp, ignore_errors=True)


class TestCaseSensitive(unittest.TestCase):
    """回归：case_sensitive 开关必须真的生效。

    早先正则硬编码 re.I、归一化又带 lower —— 两个动作叠加的结果是
    不管怎么设置，匹配永远忽略大小写，开关形同虚设。
    现在只有在"不敏感"（默认）时才加 re.I，同时敏感模式下不做 lower，
    两边保持一致。
    """

    def _engine(self, case_sensitive):
        tmp = tempfile.mkdtemp(prefix="agentwaf-case-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        rp = os.path.join(tmp, "rules.json")
        doc = rules.default_document()
        doc["settings"]["case_sensitive"] = case_sensitive
        rules.save_document(doc, rp)
        return RuleEngine(rp)

    def _blocked(self, engine, url):
        from urllib.parse import urlsplit
        target = ScanTarget(kind="request", method="GET", url=url,
                            raw_cmd=url, tool="test")
        parts = urlsplit(url)
        target.host, target.path, target.query = (
            parts.netloc, parts.path, parts.query)
        return engine.scan(target, log=False).blocked

    def test_insensitive_by_default(self):
        """默认不区分大小写（原有行为不能变）。"""
        engine = self._engine(False)
        for url in ("http://x/?op=delete", "http://x/?op=DELETE",
                    "http://x/?op=DeLeTe"):
            self.assertTrue(self._blocked(engine, url),
                            "默认模式下 %s 应被拦" % url)

    def test_sensitive_mode_respected(self):
        """开启后，大小写不同就不该命中。"""
        engine = self._engine(True)
        self.assertTrue(self._blocked(engine, "http://x/?op=delete"),
                        "小写仍应命中")
        for url in ("http://x/?op=DELETE", "http://x/?op=DeLeTe"):
            self.assertFalse(self._blocked(engine, url),
                             "敏感模式下 %s 不该命中（开关没生效）" % url)


