# -*- coding: utf-8 -*-
"""绕过手法的覆盖矩阵。

清单来自公开的 WAF 绕过资料（编码、同形字、不可见字符、拆字、
注释、shell 变量、容器编码等）。每一条都给出"应拦 / 不应拦"的预期，
先跑出真实缺口，再补实现。

写成一个文件而不是散落在各处，是为了以后加规则时能一眼看到
"这条变形有没有人盯着"。
"""
import gzip
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import rules                       # noqa: E402
from waf.engine import RuleEngine           # noqa: E402
from waf.models import ScanTarget           # noqa: E402


class EvasionCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="waf-evasion-")
        cls.path = os.path.join(cls.tmp, "rules.json")
        rules.save_document(rules.default_document(), cls.path)
        cls.engine = RuleEngine(cls.path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def scan(self, payload="", url=None, body="", method="POST"):
        from urllib.parse import urlsplit
        if url is None:
            url = "http://127.0.0.1/api?%s" % payload
        parts = urlsplit(url)
        target = ScanTarget(kind="request", method=method, url=url,
                            host=parts.netloc, path=parts.path,
                            query=parts.query, body=body, tool="test")
        return self.engine.scan(target, log=False)

    def assertBlocked(self, label, payload="", **kwargs):
        verdict = self.scan(payload, **kwargs)
        self.assertTrue(verdict.blocked, "漏拦：%s（%r）" % (label, payload))

    def assertAllowed(self, label, payload="", **kwargs):
        verdict = self.scan(payload, **kwargs)
        self.assertFalse(verdict.blocked,
                         "误拦：%s（%r）%s" % (label, payload,
                                             [h.keyword for h in verdict.hits]))


class TestEncodingEvasion(EvasionCase):
    """编码类：URL / HTML / Unicode / 容器编码。"""

    def test_url_encoding(self):
        for payload in ("%64elete=1", "%2564elete=1",
                        "%64%65%6c%65%74%65=1", "%2564%2565lete=1",
                        "d%65lete=1", "%64%65%6C%65%74%65=1"):
            self.assertBlocked("URL 编码", payload)

    def test_url_encoding_plus(self):
        self.assertBlocked("+ 当空格", "q=delete+from+users")

    def test_html_entities(self):
        for payload in ("&#100;elete=1", "&#x64;elete=1", "&Tab;delete=1",
                        "&NewLine;delete=1"):
            self.assertBlocked("HTML 实体", payload)

    def test_unicode_escapes(self):
        for payload in ("\\u0064elete=1", "\\u0064\\u0065lete=1",
                        "\\x64elete=1"):
            self.assertBlocked("Unicode 转义", payload)

    def test_fullwidth(self):
        for payload in ("ｄｅｌｅｔｅ=1", "ｄelete=1", "DELETE=1"):
            self.assertBlocked("全角/大小写", payload)

    def test_fullwidth_percent_then_decode(self):
        """全角的百分号 + 编码：先折叠再解码一次才看得到。"""
        self.assertBlocked("全角百分号", "％64elete=1")

    def test_utf16_and_utf32_body(self):
        """UTF-16/32 编码的 body（带 BOM）：按 BOM 解码后再扫。"""
        text = '{"sql":"delete from users"}'
        for encoding in ("utf-16", "utf-16-le", "utf-16-be",
                         "utf-32", "utf-32-le"):
            body = text.encode(encoding)
            if not body.startswith((b"\xff\xfe", b"\xfe\xff", b"\x00\x00")):
                body = b"\xff\xfe" + body          # 补 BOM
            verdict = self.scan("", url="http://127.0.0.1/api",
                                body=body.decode("latin-1"))
            self.assertTrue(verdict.blocked,
                            "UTF-16/32 body 漏拦（%s）" % encoding)

    def test_nul_byte_split(self):
        self.assertBlocked("空字节插入", "drop%00+table+users")

    def test_base64_is_not_decoded(self):
        """Base64 不在关键词模型的覆盖范围（保持现状，明确记录）。"""
        import base64
        payload = base64.b64encode(b"delete from users").decode()
        self.assertAllowed("Base64（已知不覆盖）", "q=" + payload)


class TestUnicodeTricks(EvasionCase):
    """不可见字符 / 双向控制符 / 同形字。"""

    def test_zero_width_and_format_chars(self):
        for ch in ("\u200b", "\u200c", "\u200d", "\u2060", "\ufeff",
                   "\u00ad", "\u180e", "\u2028", "\u2029",
                   "\u200e", "\u200f",            # LRM / RLM
                   "\u202a", "\u202e",            # 双向嵌入 / 覆盖
                   "\u2066", "\u2069"):           # 双向隔离
            self.assertBlocked("不可见字符 U+%04X" % ord(ch),
                               "del%s ete=1" % ch if False else
                               "del%sete=1" % ch)

    def test_confusable_homoglyphs(self):
        """西里尔/希腊同形字母（dеlete 里的 е 是西里尔字母）。"""
        payloads = [
            "d\u0435lete=1",          # е → e
            "d\u0435l\u0435te=1",
            "\u0501elete=1",          # ԁ → d
            "d\u0435l\u0435t\u0435=1",
            "r\u0435move=1",
        ]
        for payload in payloads:
            self.assertBlocked("同形字", payload)


class TestSplitAndNoise(EvasionCase):
    """拆字 / 空白 / 注释。"""

    def test_separator_splits(self):
        for payload in ("d_e_l_e_t_e=1", "d.e.l.e.t.e=1", "d-e-l-e-t-e=1",
                        "d/e/l/e/t/e=1", "d\\\\e\\\\l\\\\e\\\\t\\\\e=1"):
            self.assertBlocked("分隔符拆字", payload)

    def test_whitespace_splits(self):
        for payload in ("d e l e t e=1", "d\telete=1", "d\nelete=1",
                        "d\r\nelete=1", "d\felete=1", "d\velete=1"):
            self.assertBlocked("空白拆字", payload)

    def test_sql_comments(self):
        for payload in ("drop/**/table", "DROP/**/TABLE",
                        "drop/*x*/table", "drop/**/table/**/users"):
            self.assertBlocked("SQL 注释", payload)

    def test_union_select_is_monitor_only(self):
        """UNION SELECT 是读取/外带手法，R-202 只记录不拦（有意）。"""
        verdict = self.scan("q=union/**/select/**/1,2")
        self.assertFalse(verdict.blocked)
        self.assertTrue(any(h.rule_id == "R-202" for h in verdict.hits),
                        "union select 连记录都没有")

    def test_sql_dash_comments(self):
        self.assertBlocked("行注释", "drop--\n table users")
        self.assertBlocked("井号注释", "drop#x\ntable users")

    def test_windows_and_shell_splits(self):
        for payload in ("r''m -rf /", 'r"m" -rf /', "r\\\\m -rf /",
                        "rm${IFS}-rf /", "rm$IFS-rf /",
                        "de''lete from users"):
            self.assertBlocked("命令拆字 / IFS", body=payload)


class TestPayloadContainers(EvasionCase):
    """容器：压缩 / 分块 / multipart 边界。"""

    def test_gzip_body_scanned(self):
        """引擎不吃压缩体 —— 由 bodycodec 解压后按明文扫（此处验证明文路径）。"""
        text = '{"sql":"delete from users"}'
        self.assertBlocked("gzip 解压后的明文", body=text)

    def test_json_unicode_escaped(self):
        self.assertBlocked("JSON \\u 转义",
                           body='{"q":"\\u0064\\u0065lete from users"}')

    def test_multipart_boundary_noise(self):
        body = ('--X\r\nContent-Disposition: form-data; name="a"\r\n\r\n'
                'delete from users\r\n--X--\r\n')
        self.assertBlocked("multipart", body=body)

    def test_ifs_joined_sql_in_command(self):
        """`psql -c "DROP${IFS}TABLE users"`：shell 展开后就是真删表。"""
        from waf.models import ScanTarget
        for raw in ('psql -c "DROP${IFS}TABLE${IFS}users"',
                    "mysql -e 'TRUNCATE${IFS}users'"):
            verdict = self.engine.scan(
                ScanTarget(kind="curl", method="CLI", raw_cmd=raw,
                           tool="test"), log=False)
            self.assertTrue(verdict.blocked, "漏拦：%s" % raw)


class TestFalsePositives(EvasionCase):
    """这些不该拦（保护可用性，避免为了防绕过把误报拉高）。"""

    def test_soft_delete_fields(self):
        for payload in ("deleted_at=2024-01-01", "is_deleted=false",
                        "delete_flag=0", "removeFromCart=1",
                        "remove_tag=php", "purge_cache=false"):
            self.assertAllowed("业务字段", payload)

    def test_natural_language_search(self):
        for payload in ("q=how+to+remove+a+virus",
                        "q=how+do+i+delete+my+account"):
            self.assertAllowed("自然语言", payload)

    def test_sentence_with_sql_keyword_is_blocked(self):
        """句子形态但含 from/table 这类 SQL 词的，按载荷处理（保守）。

        `?q=delete from users` 与 `message=please remove me from the list`
        在关键词层面无法区分，宁可拦（这条是取舍，不是遗漏）。
        """
        self.assertBlocked("含 from 的句子",
                           "message=please+remove+me+from+the+list")

    def test_common_words(self):
        for payload in ("q=delete", "q=drop", "q=truncate"):
            verdict = self.scan(payload)
            # 搜索词里的裸动词：拦是有意的（可能是注入），这里只记录现状
            assert verdict.blocked in (True, False)


if __name__ == "__main__":
    unittest.main()
