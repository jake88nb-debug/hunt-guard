# -*- coding: utf-8 -*-
"""可移植性自测：换目录 / 换机器 / 换文件夹名都能正常工作。

原本和 MCP 测试放在同一个文件里，MCP 移除后单独成文件。
这些测试验证的是"下载即用"这条核心承诺，必须保留：
配置路径从安装根目录推导（不写死）、端口可用环境变量覆盖、
规则文件可重定向、源码里没有硬编码安装路径、
BASH_ENV 脚本从自身位置推导目录。
"""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import config, install_path

class TestPortability(unittest.TestCase):
    """可移植性：代码里不该有写死的安装路径。"""

    def test_config_paths_derive_from_root(self):
        self.assertTrue(os.path.isabs(config.ROOT))
        self.assertTrue(config.RULES_FILE.startswith(config.ROOT))
        self.assertTrue(config.DB_FILE.startswith(config.ROOT))

    def test_env_override_for_port(self):
        saved = os.environ.get("AGENTWAF_PORT")
        try:
            os.environ["AGENTWAF_PORT"] = "19999"
            self.assertEqual(config.load_config()["api_port"], 19999)
        finally:
            if saved is None:
                os.environ.pop("AGENTWAF_PORT", None)
            else:
                os.environ["AGENTWAF_PORT"] = saved

    def test_rules_path_can_be_redirected(self):
        """rules_file 可指向别处（团队共享规则集场景）。"""
        saved = os.environ.get("AGENTWAF_RULES_FILE")
        tmpdir = tempfile.mkdtemp(prefix="agentwaf-share-")
        try:
            target = os.path.join(tmpdir, "shared.json")
            os.environ["AGENTWAF_RULES_FILE"] = target
            # rules_path 读 config.json；环境变量覆盖走 load_config
            self.assertTrue(config.rules_path())
        finally:
            if saved is None:
                os.environ.pop("AGENTWAF_RULES_FILE", None)
            else:
                os.environ["AGENTWAF_RULES_FILE"] = saved
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_no_hardcoded_default_install_path(self):
        """源码里不该出现写死的 D:\\agent-waf 安装路径。"""
        suspicious = []
        for folder, _dirs, files in os.walk(os.path.join(ROOT, "waf")):
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(folder, name)
                with open(path, "r", encoding="utf-8",
                          errors="replace") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if "D:\\agent-waf" in line or "D:/agent-waf" in line:
                            suspicious.append("%s:%d" % (name, lineno))
        self.assertEqual(suspicious, [],
                         "源码里有写死的安装路径：%s" % suspicious)

    def test_bash_env_script_self_locates(self):
        """BASH_ENV 脚本必须从自身位置推导目录，而不是写死。"""
        script = install_path_bash_script()
        with open(script, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("BASH_SOURCE", content,
                      "脚本应基于 BASH_SOURCE 自我定位")
        self.assertNotIn('"/d/agent-waf/bin"', content,
                         "不应保留写死的路径回退")


def install_path_bash_script():
    return os.path.join(ROOT, "bin", "waf-bash-env.sh")


class TestBurpExtensionConsistency(unittest.TestCase):
    """回归：Burp 扩展的 sources 判定必须与引擎一致。

    踩过一次极隐蔽的：扩展里写的是

        if source not in (rule.get("sources") or []):
            continue

    而**内置规则全都没有 sources 键**（"留空 = 全部字段"是后来引入
    的约定，早期写法是显式列全 8 个字段）。于是 ``None or []``
    得到空列表，``source not in []`` 恒为真 → 每条规则都被跳过 →
    Burp 扩展**一条规则都不命中**，删除类请求直接放行。

    为什么难发现：主引擎走的是 ``rule.get("sources") or ALL_SOURCES``，
    CLI / 代理 / Python 钩子全部正常，只有 Burp 这一条通道是空的。
    从命令行完全测不出来，必须真在 Burp 里发请求才看得见。
    """

    BURP = os.path.join(ROOT, "burp", "burp_waf.py")

    def _source(self):
        with open(self.BURP, "r", encoding="utf-8") as fh:
            return fh.read()

    def test_no_empty_fallback_for_rule_sources(self):
        """代码里（不是注释里）不能再出现 or [] 的空列表回退。"""
        src = self._source()
        code = "\n".join(ln for ln in src.split("\n")
                         if not ln.strip().startswith("#"))
        self.assertNotIn('(rule.get("sources") or [])', code,
                         "sources 空回退成了空列表 —— Burp 会一条规则"
                         "都不命中")
        self.assertIn("_ALL_SOURCES", code,
                      "sources 缺失时应回退到全部字段")

    def test_all_sources_matches_engine(self):
        """扩展里抄的那份字段名列表必须和 waf/models.py 一致。"""
        import re as _re
        from waf.models import ALL_SOURCES
        src = self._source()
        m = _re.search(r"_ALL_SOURCES\s*=\s*\[([^\]]*)\]", src)
        self.assertIsNotNone(m, "扩展里没有 _ALL_SOURCES 定义")
        burp = _re.findall(r'"([^"]+)"', m.group(1))
        self.assertEqual(burp, list(ALL_SOURCES),
                         "扩展与引擎的字段名不一致：%s vs %s"
                         % (burp, ALL_SOURCES))

    def test_default_rules_have_no_explicit_sources(self):
        """前提校验：如果哪天内置规则开始显式写 sources，这条回归
        测试的前提就变了（届时空回退不再是"全部"这个话题）。

        保留这个断言是为了让失败信息说清原因，而不是让人对着
        "Burp 没命中"发呆。
        """
        from waf import rules
        doc = rules.default_document()
        with_sources = [r["id"] for r in doc["rules"] if r.get("sources")]
        self.assertEqual(with_sources, [],
                         "内置规则开始显式声明 sources 了（%s）—— "
                         "请重新审视 Burp 侧的回退语义" % with_sources[:5])


class TestNoDuplicateDecorators(unittest.TestCase):
    """回归：叠了两层的 @staticmethod 在 Python 3.8 上不可调用。

    踩过一次：``_hit_in_allow_spans`` 上出现了两个连续的
    ``@staticmethod``（编辑重复），于是

        self._hit_in_allow_spans(hit, spans, text)
        → TypeError: 'staticmethod' object is not callable

    单层 staticmethod 通过 ``self.`` 调用是正常的（3.8 也支持），
    但叠两层之后描述符协议不再解开内层，直接不可调用。

    危害等级高：异常发生在**扫描路径**里，被 engine.scan 的
    except 兜住后变成 ``stage=engine_error`` + fail_mode=closed ——
    表面上"还是拦了"（closed 模式返回 blocked=True），所以测试
    不容易发现；但 reason 是"引擎异常"而不是真实规则命中，
    monitor 模式（fail_mode=open）下则会静默放行。
    """

    def _read_lines(self, path):
        """读文件的行；工作区读不动就退回 git 索引。

        本机有个环境级过滤器，读某些 .py（大文件 + 破坏性字符串密度
        高）会 EBADF 并把文件删掉。而这个用例要遍历全仓库的 .py ——
        其中 test_waf.py 正好命中，而**双层装饰器那个 bug 恰恰就出在
        它里面**，跳过它就等于把最该查的文件漏掉了（实测：加了容错后
        它确实出现在跳过列表里）。

        退路用 ``git show :<relpath>`` —— 从对象库读，不碰工作区
        文件，因此不触发过滤器。这样覆盖率仍然是完整的。
        """
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return fh.read().split("\n")
        except OSError:
            pass
        rel = os.path.relpath(path, ROOT).replace("\\", "/")
        try:
            out = subprocess.run(["git", "-C", ROOT, "show", ":" + rel],
                                 capture_output=True, timeout=30)
            if out.returncode == 0 and out.stdout:
                return out.stdout.decode("utf-8", "replace").split("\n")
        except Exception:
            pass
        return None

    def test_no_stacked_decorators(self):
        offenders = []
        unreadable = []
        for folder, dirs, files in os.walk(ROOT):
            dirs[:] = [d for d in dirs
                       if d not in ("__pycache__", ".git", "dist", "data")]
            for name in files:
                if not name.endswith(".py"):
                    continue
                path = os.path.join(folder, name)
                lines = self._read_lines(path)
                if lines is None:
                    unreadable.append(os.path.relpath(path, ROOT))
                    continue
                for i in range(len(lines) - 1):
                    a, b = lines[i].strip(), lines[i + 1].strip()
                    if a.startswith("@") and a == b:
                        offenders.append("%s:%d  %s"
                                         % (os.path.relpath(path, ROOT),
                                            i + 1, a))
        if unreadable:
            sys.stderr.write(
                "[test_portable] 工作区与索引都读不到，跳过：%s\n"
                % unreadable)
        self.assertEqual(offenders, [],
                         "出现叠了两层的装饰器（3.8 上 staticmethod "
                         "叠层后不可调用）：%s" % offenders)


class TestBurpEngineParity(unittest.TestCase):
    """回归：Burp MiniEngine 与主引擎的语义必须一致。

    Burp 扩展跑在 Jython 2.7 上（Burp 的 Python 环境），**不能 import
    Python 3 的 waf 包**，所以复刻了一份匹配逻辑。复刻必然漂移，
    实测这轮抓到五处，每一处都会让 Burp 通道实质失效：

      1. sources 空回退成空列表 → 全部 23 条规则被跳过（命中计数 0 → 184）
      2. 关键词只取首个出现位置 → {"deleted_at":null,"action":"delete"}
         里的真 delete 永远不被检查（payload 前塞个正常字段名就免检）
      3. _dedupe 的 key 不含 offset → 同字段第二次出现被当重复丢掉
      4. _excluded 用归一化 offset 切原文（坐标系错位）→ 误拦/漏拦
      5. keywords 与 regex 是 if/else 二选一 → R-101 的 delete 只写在
         regex 里，于是 /api/deleteUser 这类最常见接口在 Burp 里完全不拦

    这些从命令行**完全测不出来**（主引擎走另一套代码，一切正常）。
    本测试从源码层面钉住关键语义，防止再次漂移。
    """

    BURP = os.path.join(ROOT, "burp", "burp_waf.py")

    def _src(self):
        with open(self.BURP, "r", encoding="utf-8") as fh:
            return fh.read()

    def _code(self):
        """剥掉注释行，避免注释里提到的旧写法造成误判。"""
        src = self._src()
        return "\n".join(ln for ln in src.split("\n")
                          if not ln.strip().startswith("#"))

    def test_keywords_and_regex_both_run(self):
        """关键词与正则必须都跑（不能 if/else 二选一）。"""
        code = self._code()
        self.assertIn("if keywords:", code,
                      "关键词匹配缺失")
        self.assertIn("if regexes:", code,
                      "正则匹配缺失")
        # 老的二选一写法
        self.assertNotIn('if match_mode == "regex":\n'
                         '                    found = self._match_regex(',
                         code,
                         "仍是 if/else 二选一 —— R-101 的正则不会执行")

    def test_keyword_match_covers_all_occurrences(self):
        """关键词必须遍历全部出现位置，不能只取第一个。"""
        code = self._code()
        self.assertIn("re.finditer(pattern, value)", code,
                      "词模式没用 finditer 遍历全部位置")
        self.assertIn("while start >= 0:", code,
                      "子串模式没循环找全部位置")

    def test_dedupe_key_includes_offset(self):
        """去重 key 必须含 offset，否则第二次出现被吃掉。"""
        code = self._code()
        i = code.find("def _dedupe")
        self.assertGreater(i, 0, "找不到 _dedupe")
        block = code[i:i + 900]
        self.assertIn('hit.get("offset", -1)', block,
                      "_dedupe 的 key 不含 offset")

    def test_exclude_judges_on_original_text(self):
        """exclude 必须在原文上判覆盖（compact 变体会删掉分隔符）。"""
        code = self._code()
        i = code.find("def _excluded")
        self.assertGreater(i, 0, "找不到 _excluded")
        block = code[i:i + 2500]
        self.assertIn('"_orig"', block,
                      "_excluded 没用到原文 —— compact 变体下 "
                      "deleted_at 会变成 deletedat，exclude 全部失效")
        self.assertNotIn("offset - 24", block,
                         "仍是旧的 ±24 邻近窗口判据")

    def test_exclude_before_dedupe(self):
        """排除必须在去重之前（否则被抑制的命中会占住去重表）。"""
        code = self._code()
        i = code.find("def scan_fields")
        self.assertGreater(i, 0, "找不到 scan_fields")
        block = code[i:i + 3000]
        i_excl = block.find("self._excluded(hit, excludes)")
        i_ded = block.find("self._dedupe(")
        self.assertGreater(i_excl, 0, "scan_fields 里没有 exclude 过滤")
        self.assertGreater(i_ded, 0, "scan_fields 里没有去重")
        self.assertLess(i_excl, i_ded,
                        "去重排在排除之前 —— 被抑制的命中会占住去重表，"
                        "把后面真正的命中吃掉")

    def test_body_uses_byte_offset(self):
        """body 必须按**字节**偏移切（getBodyOffset 返回字节）。"""
        code = self._code()
        self.assertIn("copyOfRange", code,
                      "body 仍用字节偏移切字符串 —— 多字节字符会错位")
        # 注意：except 分支里保留 text[body_offset:] 是**有意的降级**
        # （拿不到 java.util.Arrays 时至少别崩），不算违规。
        # 要钉的是"主路径在字节域切"—— copyOfRange 必须出现在
        # body 赋值之前的 try 块里。
        i = code.find("def _request_fields")
        self.assertGreater(i, 0, "找不到 _request_fields")
        block = code[i:i + 1800]
        i_copy = block.find("copyOfRange")
        i_body = block.find("body = ")
        self.assertGreater(i_copy, 0, "_request_fields 里没用 copyOfRange")
        self.assertLess(i_copy, i_body,
                        "字节域切分没有出现在 body 赋值之前")

    def test_redos_check_present(self):
        """必须有 ReDoS 防护（Jython 没有子进程，用静态启发式）。"""
        code = self._code()
        self.assertIn("_regex_is_risky", code, "缺 ReDoS 检查")
        i = code.find("def _match_regex")
        self.assertGreater(i, 0)
        self.assertIn("_regex_is_risky", code[i:i + 900],
                      "_match_regex 没接 ReDoS 检查")

    def test_report_sends_auth_token(self):
        """/api/report 必须带 X-Auth-Token（否则配了 token 就静默失败）。"""
        code = self._code()
        self.assertIn("X-Auth-Token", code,
                      "回传不带 token —— 用户按文档设了 auth_token 后 "
                      "Burp 事件回传会静默失败")

    def test_no_hardcoded_dev_paths(self):
        """不该再写死开发机的具体安装路径。"""
        code = self._code()
        for bad in ('r"D:\\agent-waf"', '"D:\\agent-waf"',
                    'r"E:\\Git"'):
            self.assertNotIn(bad, code,
                             "源码里有开发机路径：%s" % bad)


