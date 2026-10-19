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
class TestGuardCoverage(unittest.TestCase):
    """回归：guard 必须覆盖各类 HTTP 客户端与破坏性 subprocess。

    这几处都漏过（实测发现，均已修）：
      * httpx.AsyncClient —— 早先只补 httpx.Client，异步完全没覆盖
        （AsyncClient 是独立类，不走 Client 的方法解析）
      * urllib3 —— requests 的底座，也是很多爬虫的直接依赖，
        之前零覆盖
      * subprocess 破坏类命令 —— 门槛只看 curl/http/wget，于是
        subprocess.run(["rm","-rf","/"]) 完全不被检查，
        而"拦住删除"正是这个工具的核心目的
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-guardcov-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, body, timeout=90, extra_env=None):
        code = ('import sys\n'
                'sys.path.insert(0, %r)\n'
                'import waf.guard as g\n'
                'g.install_guard(patch_subprocess=True)\n' % ROOT) + body
        env = dict(os.environ)
        env["AGENTWAF_RULES_FILE"] = self.rules_path
        env["WAF_ALWAYS_ON"] = "1"
        env["WAF_NO_LOG"] = "1"
        if extra_env:
            env.update(extra_env)
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, env=env, timeout=timeout)
        return proc.stdout.decode("utf-8", "replace").strip()

    def test_httpx_sync_and_async(self):
        out = self._run(
            "import httpx\n"
            "try:\n"
            "    httpx.Client().get('http://127.0.0.1/delete.php', timeout=2)\n"
            "    print('SYNC_NOT_BLOCKED')\n"
            "except Exception as exc:\n"
            "    print('SYNC_BLOCKED' if 'WafBlocked' in type(exc).__name__ else 'SYNC_OTHER')\n"
            "import asyncio\n"
            "async def go():\n"
            "    async with httpx.AsyncClient() as c:\n"
            "        await c.get('http://127.0.0.1/delete.php', timeout=2)\n"
            "try:\n"
            "    asyncio.run(go())\n"
            "    print('ASYNC_NOT_BLOCKED')\n"
            "except Exception as exc:\n"
            "    print('ASYNC_BLOCKED' if 'WafBlocked' in type(exc).__name__ else 'ASYNC_OTHER')\n")
        if "SKIP" in out or not out:
            self.skipTest("环境缺 httpx")
        self.assertIn("SYNC_BLOCKED", out, "httpx.Client 未拦：%s" % out)
        self.assertIn("ASYNC_BLOCKED", out,
                      "httpx.AsyncClient 未拦（异步是独立类，必须单独补）：%s"
                      % out)

    def test_urllib3_pool_manager(self):
        out = self._run(
            "import urllib3\n"
            "try:\n"
            "    urllib3.PoolManager().request('GET',"
            " 'http://127.0.0.1/delete.php', timeout=2)\n"
            "    print('NOT_BLOCKED')\n"
            "except Exception as exc:\n"
            "    print('BLOCKED' if 'WafBlocked' in type(exc).__name__ else 'OTHER')\n")
        if "OTHER" in out or "ImportError" in out:
            self.skipTest("环境缺 urllib3")
        self.assertIn("BLOCKED", out, "urllib3 未拦：%s" % out)

    def _sandbox_path(self, name):
        """一个**保证不存在**的可执行文件路径。

        为什么必须这样：
        原来这里直接

            subprocess.run(["shutdown", "/s"])
            subprocess.run(["userdel", "bob"])

        意图是"护栏应该拦住它"。可护栏一旦失效（同一轮我把门槛词表
        改成纯派生，`\bshutdown\b` 被切成 "bshutdown"，shutdown 反而
        不在词表里，破坏性命令因此未被拦截。

        测试**不能以"被测代码是对的"为前提** —— 那恰恰是它要验证的东西。

        我试过"往 PATH 前面放假的 shutdown.cmd"，**实测无效**：
        Windows 上 CreateProcess 对 .exe 的解析优先于 .cmd，
        假 .cmd 遮不住 C:\Windows\System32\shutdown.exe。

        现在改成结构上不可能执行：可执行文件指向不存在的绝对路径，
        破坏性词只出现在路径与参数里。护栏正常就拦在 Popen 之前；
        万一护栏失效，得到 FileNotFoundError —— 碰不到真命令。
        扫描面仍然完整（路径里带着 "shutdown" 这类词），
        "必须拦住"的语义不变。
        """
        return os.path.join(self.tmp, "waf-nonexistent", name)

    def test_destructive_subprocess_blocked(self):
        """破坏类命令必须拦 —— 这是工具的核心目的。

        可执行文件全部指向**不存在**的绝对路径（见 _sandbox_path）：
        护栏正常就拦在 Popen 之前；万一护栏失效，得到的是
        FileNotFoundError（打印 OTHER）→ 断言失败变红，
        而**不是**真的执行系统级破坏操作。

        路径里带着 "shutdown" / "rm" 这些词，所以扫描面与真实命令
        完全一致，"必须拦住"的语义没被削弱。
        """
        for name, args, label in [
            ("rm", ["-rf", "/tmp/waf-nonexistent"], "rm -rf"),
            ("rmdir", ["/waf-nonexistent"], "rmdir"),
            ("shutdown", ["/s"], "shutdown"),
            ("userdel", ["bob"], "userdel"),
            ("taskkill", ["/F", "/IM", "waf-nonexistent.exe"], "taskkill"),
        ]:
            argv_src = repr([self._sandbox_path(name)] + args)
            out = self._run(
                "import subprocess\n"
                "try:\n"
                "    subprocess.run(%s, timeout=3, capture_output=True)\n"
                "    print('NOT_BLOCKED')\n"
                "except Exception as exc:\n"
                "    print('BLOCKED' if 'WafBlocked' in type(exc).__name__ else 'OTHER')\n" % argv_src)
            self.assertNotIn("OTHER", out,
                             "%s 没被护栏拦下，而是尝试执行后失败 —— "
                             "说明检查逻辑失效了（%s）" % (label, out))
            self.assertIn("BLOCKED", out,
                          "破坏命令 %s 未被拦：%s" % (label, out))

    def test_normal_subprocess_allowed(self):
        """正常本地命令不能误拦。"""
        # 只能用两个平台都有的命令。早先用 ls -la，Windows 上必然
        # FileNotFoundError，测试在开发机就红（实测发现）。
        for argv_src, label in [
            ('["git", "status"]', "git status"),
            ('[sys.executable, "--version"]', "python --version"),
            ('["git", "--version"]', "git --version"),
        ]:
            out = self._run(
                "import subprocess\n"
                "try:\n"
                "    subprocess.run(" + argv_src + ", timeout=5,"
                " capture_output=True)\n"
                "    print('ALLOWED')\n"
                "except Exception as exc:\n"
                "    print('BLOCKED:' + type(exc).__name__)\n")
            self.assertIn("ALLOWED", out,
                          "正常命令 %s 被误拦：%s" % (label, out))


class TestR101TerminalRegressions(unittest.TestCase):
    """回归：delete / remove 的动作位匹配（踩过三次，每次漏一族）。

    历史：
      1. ``\\bdelete(?![a-zA-Z0-9_]*(?:d|_at|_flag))``
         —— 断言里的 d 是"任意位置的 d"，可回溯匹配，
         deleteRecord 的 Recor**d** 就触发豁免。
      2. ``\\bdelete(?!d)``
         —— 只排除紧跟小写 d；re.I 下 deleteDomain / deleteDraft /
         deleteData / deleteDevice / deleteDoc / deleteDepartment 全漏。
      3. ``\\b`` 在 ``item_delete`` 里根本不成立（下划线是词字符），
         所以动作位正则的分隔符集合必须显式含 ``_`` 和 ``-``。

    本测试把这三类形态一起钉死。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-r101-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)
        self.engine = RuleEngine(self.rules_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _blocked(self, url):
        target = ScanTarget(kind="request", method="GET", url=url,
                            raw_cmd=url, tool="test")
        return self.engine.scan(target, log=False).blocked

    def test_delete_camel_case_family_blocked(self):
        """deleteXxx 一族（含大写的 D 前缀）一个都不能漏。"""
        for path in ["/api/deleteById", "/api/deleteRecord",
                     "/api/deleteUser", "/api/deleteDomain",
                     "/api/deleteDraft", "/api/deleteData",
                     "/api/deleteDevice", "/api/deleteDoc",
                     "/api/deleteDepartment"]:
            self.assertTrue(self._blocked("http://x" + path),
                            "%s 漏拦 —— deleteXxx 家族被豁免了" % path)

    def test_underscore_and_dash_naming_blocked(self):
        """下划线/连字符命名要算动作位（\\b 在这里不成立）。"""
        for path in ["/api/item_delete", "/api/batch_delete",
                     "/api/user-delete", "/api/item_remove",
                     "/api/user_remove", "/api/batch_remove"]:
            self.assertTrue(self._blocked("http://x" + path),
                            "%s 漏拦 —— 动作位分隔符少了 _ 或 -" % path)

    def test_state_fields_not_blocked(self):
        """状态字段（过去式/标志位）必须放行，否则误报会淹没告警。"""
        for path in ["/api/items?deleted_at=2024-01-01",
                     "/api/items?deleted=true",
                     "/api/items?deletedAt=null",
                     "/api/items?is_deleted=0",
                     "/api/items?excludeDeleted=1"]:
            self.assertFalse(self._blocked("http://x" + path),
                             "%s 被误拦 —— 状态字段不该算删除动作" % path)


class TestDefaultsRevMigration(unittest.TestCase):
    """回归：改了内置规则必须 bump DEFAULTS_REV，否则已经装了的机器
    永远拿不到新规则（迁移靠 rev 比较触发）。

    实测踩过：R-101 的正则改了，但 DEFAULTS_REV 忘了 +1 →
    ``if current_rev >= DEFAULTS_REV: return`` 直接返回，
    **磁盘上的旧正则一直在用**，实测报的 deleteById 族仍漏拦，
    而源码看起来是"已修"。这个 bug 没有任何测试能发现，因为测试
    总是从 default_document() 新建文件（rev 已是新版）。
    """

    def test_rev13_install_gets_new_r101(self):
        tmp = tempfile.mkdtemp(prefix="agentwaf-mig-")
        try:
            doc = rules.default_document()
            doc["defaults_rev"] = 13
            old_re = r"\bdelete(?!d)"
            for rule in doc["rules"]:
                if rule["id"] == "R-101":
                    rule["regex"] = [old_re]
                    # 模拟真实历史文件：指纹按改动后的内容重算，
                    # 否则会被当成"用户改过"而拒绝升级
                    rule["_builtin_hash"] = rules._content_fingerprint(rule)
                    break

            path = os.path.join(tmp, "rules.json")
            rules.save_document(doc, path)

            engine = RuleEngine(path)       # 构造即触发迁移
            after = rules.load_document(path)

            self.assertEqual(after.get("defaults_rev"), rules.DEFAULTS_REV,
                             "defaults_rev 没被迁移到最新值")
            new_re = [r["regex"] for r in after["rules"]
                      if r["id"] == "R-101"][0]
            self.assertNotEqual(new_re, [old_re],
                                "R-101 仍是旧正则 —— DEFAULTS_REV 漏 bump "
                                "时就是这个症状")

            for path_ in ["/api/deleteDomain", "/api/deleteRecord",
                          "/api/item_delete"]:
                url = "http://x" + path_
                target = ScanTarget(kind="request", method="GET", url=url,
                                    raw_cmd=url, tool="test")
                self.assertTrue(engine.scan(target, log=False).blocked,
                                "迁移后 %s 仍漏拦" % path_)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestRegexGuardLoadPath(unittest.TestCase):
    """回归：两条 fail-open 通道（实测发现，均已修）。

    1. 超长 pattern 原来 ``continue``（跳过探测）→ 调用方视为安全并
       编译使用，一条 4001 字符的病态正则可绕过整个 ReDoS 防护。
       现在直接判危险。
    2. allowlist 保存时会查 ReDoS，但**加载时**不查 —— 手工编辑
       rules.json、或用团队共享规则集时走不到保存路径，病态 pattern
       会被编译且在**每个字段**上跑。
    """

    def setUp(self):
        from waf import regexguard
        regexguard.clear_cache()

    def test_overlong_pattern_rejected_not_skipped(self):
        from waf import regexguard
        # 长度超限但含明确的病态形态；判据应是"拒绝"而不是"放行"
        pattern = "(a+)+$" + "x" * (regexguard.MAX_PATTERN_LEN + 10)
        reason = regexguard.check_pattern(pattern)
        self.assertTrue(reason, "超长正则被 fail-open 放行了：%r" % pattern[:40])
        self.assertIn("过长", reason)

    def test_allowlist_regex_checked_at_load(self):
        """allowlist 里的病态正则必须在加载时被剔除。"""
        from waf.engine import RuleEngine
        tmp = tempfile.mkdtemp(prefix="agentwaf-allowredos-")
        try:
            doc = rules.default_document()
            doc.setdefault("allowlist", []).append({
                "id": "A-999", "enabled": True, "source": "any",
                "note": "redos in allowlist", "pattern": "(a+)+$",
            })
            path = os.path.join(tmp, "rules.json")
            rules.save_document(doc, path)

            engine = RuleEngine(path)
            rejected = [r[1] for r in
                        getattr(engine, "_rejected_allow_regexes", [])]
            self.assertIn("(a+)+$", rejected,
                          "allowlist 里的病态正则没在加载时被剔除")

            # 关键：带病态载荷的请求不能卡死
            bad = "a" * 30 + "!"
            url = "http://x/?q=" + bad
            target = ScanTarget(kind="request", method="GET", url=url,
                                raw_cmd=url, tool="test")
            target.host, target.path, target.query = "x", "/", "q=" + bad
            started = time.time()
            engine.scan(target, log=False)
            self.assertLess(time.time() - started, 2.0,
                            "allowlist 病态正则让扫描卡住了")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestSelfContained(unittest.TestCase):
    """回归：不许在用户主目录留东西（"所有文件必须在自己目录里"）。

    实测发现 regexguard 的磁盘缓存会 fallback 到 ~/.huntguard ——
    配置读不到时就在用户主目录建目录，违反自包含约束。
    """

    def test_regexguard_cache_stays_inside_package(self):
        from waf import regexguard
        path = regexguard._cache_path()
        if not path:
            return                      # 配置不可用时跳过缓存，合规
        inside = os.path.abspath(path).lower()
        home = os.path.expanduser("~").lower()
        self.assertFalse(inside.startswith(home) and "agent-waf" not in inside,
                         "regexguard 缓存写到用户主目录了：%s" % path)
        self.assertIn("agent-waf", inside,
                      "缓存不在工具目录内：%s" % path)

    def test_no_huntguard_dotdir_reference(self):
        """源码里不该再有 ~/.huntguard 这种主目录 fallback。"""
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        offenders = []
        for folder, dirs, files in os.walk(os.path.join(root, "waf")):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                if not name.endswith(".py"):
                    continue
                full = os.path.join(folder, name)
                with open(full, encoding="utf-8", errors="ignore") as fh:
                    for lineno, line in enumerate(fh, 1):
                        if ".huntguard" in line and "expanduser" in line:
                            offenders.append("%s:%d" % (full, lineno))
        self.assertEqual(offenders, [],
                         "仍有主目录 fallback：%s" % offenders[:5])

    def test_scanner_has_no_hardcoded_install_path(self):
        """``install_path`` 里不该再写死开发机的盘符路径。

        踩过：``resolve_curl_in_bash()`` 的候选列表第一项是
        ``r"E:\\Git\\bin\\bash.exe"`` —— 开发机上确实装在那儿，
        但这是开发机痕迹，且排在 ``C:\\Program Files\\Git`` **前面**，
        会让别的机器优先去探一个不存在的路径。

        ``autodetect.py`` 里的同类字符串**不算**违规：那是"对方可能
        把 Git 装在哪个盘"的穷举探测列表（见其 docstring），
        顺序上 ``C:\\Program Files\\Git`` 优先，是无害的搜索空间。
        """
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        target = os.path.join(root, "waf", "install_path.py")
        offenders = []
        with open(target, encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                for bad in ("E:\\Git", "E:/Git", "D:\\Git", "D:/Git"):
                    if bad in line:
                        offenders.append("%s:%d %s"
                                         % (target, lineno, stripped))
        self.assertEqual(offenders, [],
                         "install_path 里有写死的开发机路径：%s"
                         % offenders[:5])


class TestGuardNoSelfRecursion(unittest.TestCase):
    """回归：护栏不能把自己的内部子进程当"待检命令"扫。

    实测复现的递归链（冷缓存时 100% 触发）：

      regexguard 的探测子进程 argv 形如
        python -c "<1024 字符探测源码>" '["(a+)+$","drop table"]' '[...]'
      里面**带着正在被探测的正则与样本文本**。而 guard 的
      _needs_cmd_scan 认破坏性动词，`drop` / `truncate` 正好在样本里
      → 判定"需要扫描" → get_engine() → 引擎加载 → check_patterns()
      → 又起探测子进程 → 无限套娃。

    表现不是卡死，而是 stderr 刷满 ``stage=engine_error``
    （每条都被 fail_mode=closed 兜住，所以看起来"还是在拦"，
    容易忽略）。

    三层闸都要在：autohook.bootstrap（最早）、guard._check_cmd
    （重入闸）、regexguard._run_probe（给子进程打标记）。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-recursion-")
        rules.save_document(rules.default_document(),
                            os.path.join(self.tmp, "rules.json"))

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _sandbox_path(self, name):
        """一个**保证不存在**的可执行文件路径。

        为什么必须这样：
        原来这里直接

            subprocess.run(["shutdown", "/s"])
            subprocess.run(["userdel", "bob"])

        意图是"护栏应该拦住它"。可护栏一旦失效（同一轮我把门槛词表
        改成纯派生，`\bshutdown\b` 被切成 "bshutdown"，shutdown 反而
        不在词表里，破坏性命令因此未被拦截。

        测试**不能以"被测代码是对的"为前提** —— 那恰恰是它要验证的东西。

        我试过"往 PATH 前面放假的 shutdown.cmd"，**实测无效**：
        Windows 上 CreateProcess 对 .exe 的解析优先于 .cmd，
        假 .cmd 遮不住 C:\Windows\System32\shutdown.exe。

        现在改成结构上不可能执行：可执行文件指向不存在的绝对路径，
        破坏性词只出现在路径与参数里。护栏正常就拦在 Popen 之前；
        万一护栏失效，得到 FileNotFoundError —— 碰不到真命令。
        扫描面仍然完整（路径里带着 "shutdown" 这类词），
        "必须拦住"的语义不变。
        """
        return os.path.join(self.tmp, "waf-nonexistent", name)

    def _run_with_guard(self, body, extra_env=None, timeout=120):
        env = dict(os.environ)
        env["WAF_ALWAYS_ON"] = "1"
        env["WAF_NO_LOG"] = "1"
        env["AGENTWAF_RULES_FILE"] = os.path.join(self.tmp, "rules.json")
        for key in ("WAF_DISABLE", "HUNTGUARD_NO_HOOK",
                    "AGENTWAF_NO_HOOK", "WAF_INTERNAL_PROC"):
            env.pop(key, None)
        if extra_env:
            env.update(extra_env)
        code = ("import sys\n"
                "sys.path.insert(0, %r)\n"
                "import waf.guard as g\n"
                "g.install_guard(patch_subprocess=True)\n" % ROOT) + body
        proc = subprocess.run([sys.executable, "-c", code],
                              capture_output=True, env=env, timeout=timeout)
        return (proc.stdout.decode("utf-8", "replace"),
                proc.stderr.decode("utf-8", "replace"))

    def test_probe_child_is_marked_internal(self):
        """探测子进程必须带 WAF_INTERNAL_PROC=1。"""
        from waf import regexguard
        captured = {}
        original = subprocess.run

        # 替身必须输出**合法的探测结果 JSON** —— _run_probe 会把
        # 子进程 stdout 逐行 json.loads，早先这里图省事用 print(1)，
        # 解析出 int 之后 data.get() 直接 AttributeError（测试自己的
        # bug，不是被测代码的）。
        fake_out = '{"i": 0, "safe": true, "worst": 0.0}'

        def spy(cmd, *a, **kw):
            captured["env"] = kw.get("env")
            return original([sys.executable, "-c",
                             "print(%r)" % fake_out],
                            capture_output=True)

        subprocess.run = spy
        try:
            regexguard.clear_cache()
            regexguard._run_probe(["a+$"], timeout=10, budget=0.05)
        finally:
            subprocess.run = original

        env = captured.get("env") or {}
        self.assertEqual(env.get("WAF_INTERNAL_PROC"), "1",
                         "探测子进程没被打上内部标记 —— 它会被自己的"
                         "护栏当破坏性命令扫，触发无限递归")

    def test_internal_marker_disables_scan(self):
        """带内部标记时，破坏性命令不再触发拦截。"""
        # 本用例期望**放行**，即命令真的会执行 —— 所以用
        # sys.executable 跑一行 print：python 一定存在，且只打印
        # 一个字面量，物理上无害。文本里带 rm -rf 是为了让护栏
        # "本来会拦"，从而验证内部标记确实解除了拦截。
        out, _err = self._run_with_guard(
            "import subprocess, sys\n"
            "try:\n"
            "    subprocess.run([sys.executable, '-c',\n"
            "                    \"print('rm -rf /tmp/x')\"], timeout=5,\n"
            "                   capture_output=True)\n"
            "    print('ALLOWED')\n"
            "except Exception as exc:\n"
            "    print('BLOCKED:' + type(exc).__name__)\n",
            extra_env={"WAF_INTERNAL_PROC": "1"})
        self.assertIn("ALLOWED", out,
                      "内部子进程仍被自己的护栏拦了：%s" % out)

    def test_real_destructive_command_still_blocked(self):
        """不加内部标记时，破坏性命令必须照常拦（闸不能开太大）。"""
        # 可执行文件指向不存在的绝对路径：护栏正常就拦在 Popen 之前；
        # 万一护栏失效，得到 FileNotFoundError 而不是真的删除文件。
        argv_src = repr([self._sandbox_path("rm"), "-rf", "/tmp/x"])
        out, _err = self._run_with_guard(
            "import subprocess\n"
            "try:\n"
            "    subprocess.run(%s, timeout=3, capture_output=True)\n"
            "    print('ALLOWED')\n"
            "except Exception as exc:\n"
            "    print('BLOCKED:' + type(exc).__name__)\n" % argv_src)
        self.assertIn("BLOCKED:WafBlocked", out,
                      "正常进程里的 rm -rf 没被拦：%s" % out)

    def test_no_recursive_engine_error(self):
        """装了护栏后扫描不应刷出 engine_error（递归的症状）。"""
        out, err = self._run_with_guard(
            "from waf.engine import RuleEngine\n"
            "from waf.models import ScanTarget\n"
            "import os\n"
            "eng = RuleEngine(os.path.join(%r,'rules.json'))\n"
            "t = ScanTarget(kind='curl', method='CLI',"
            " raw_cmd='rm -rf /tmp/x', tool='t')\n"
            "v = eng.scan(t, log=False)\n"
            "print('STAGE=' + v.stage)\n" % self.tmp)
        self.assertIn("STAGE=content_scan", out,
                      "扫描走了异常分支（应为真实规则命中）：%s" % out)
        self.assertNotIn("engine_error", err,
                         "出现 engine_error —— 自激递归又回来了：%s"
                         % err[:400])


class TestGuardGateCoversRules(unittest.TestCase):
    r"""回归：`guard._needs_cmd_scan` 的门槛词表必须覆盖规则集。

    踩过一次（A 级）：门槛是一份**手写的 22 动词小词表**，而规则集有
    200+ 关键词。两套清单必然漂移，方向是"门槛更窄、规则更宽" ——
    实测 19 条命令规则能拦、门槛却放行：

        Remove-Item C:\important -Recurse -Force
        shutil.rmtree('D:/data')      npx rimraf dist
        kubectl delete ns prod        rd /s /q C:\data
        deltree C:\x                 git clean -fdx
        git push --force              terraform destroy -auto-approve
        docker system prune -a        find . -name '*.log' -delete
        kill -9 1                     pkill -f python
        Remove-ItemProperty ...       zfs destroy pool/data
        lvremove /dev/vg0/lv0         > /etc/sudoers
        aws s3 rb s3://bucket         helm uninstall release

    规则在源码和测试里都"存在"，实际却空转 —— 比少拦几条更糟。
    现在门槛从规则集动态派生，本测试钉住"派生确实覆盖得到"。
    """

    def test_gate_accepts_every_command_the_rules_block(self):
        import tempfile
        import shutil as _sh
        from waf import guard, rules as _rules
        from waf.engine import RuleEngine
        from waf.models import ScanTarget

        # 先确认词表能被派生出来（拿不到就该一律扫描，不能是 None）
        words = guard._gate_words()
        self.assertIsNotNone(words, "门槛词表派生失败 —— 会退化成全扫")
        self.assertTrue(len(words) > 50,
                        "派生词表太小（%d 个），疑似解析规则失败"
                        % len(words))

        cmds = [
            "Remove-Item C:\\important -Recurse -Force",
            "shutil.rmtree('D:/data')",
            "npx rimraf dist",
            "kubectl delete ns prod",
            "rd /s /q C:\\data",
            "deltree C:\\x",
            "git clean -fdx",
            "git push --force",
            "terraform destroy -auto-approve",
            "docker system prune -a",
            "find . -name '*.log' -delete",
            "kill -9 1",
            "pkill -f python",
            "Remove-ItemProperty -Path 'HKLM:\\x'",
            "zfs destroy pool/data",
            "lvremove /dev/vg0/lv0",
            "> /etc/sudoers",
            "aws s3 rb s3://bucket",
            "helm uninstall release",
        ]

        tmp = tempfile.mkdtemp(prefix="agentwaf-gate-")
        try:
            rp = os.path.join(tmp, "rules.json")
            _rules.save_document(_rules.default_document(), rp)
            engine = RuleEngine(rp)

            missed = []
            for cmd in cmds:
                target = ScanTarget(kind="curl", method="CLI",
                                    raw_cmd=cmd, tool="test")
                if not engine.scan(target, log=False).blocked:
                    continue          # 规则没拦，不是门槛的问题
                if not guard._needs_cmd_scan(cmd):
                    missed.append(cmd)
            self.assertEqual(
                missed, [],
                "这些命令规则能拦、却被门槛跳过（规则空转）：%s" % missed)
        finally:
            _sh.rmtree(tmp, ignore_errors=True)

    def test_gate_derives_words_from_rules(self):
        """词表必须真的来自规则集，而不是又一份手写清单。"""
        from waf import guard, rules as _rules
        doc = _rules.default_document()
        words = guard._gate_words() or set()

        # 规则里每个 block 类关键词（长度 >= 3）都应能作为门槛词
        missing = []
        for rule in doc["rules"]:
            if str(rule.get("action") or "") != "block":
                continue
            for kw in (rule.get("keywords") or []):
                k = str(kw).strip().lower()
                if len(k) >= 3 and k not in words:
                    missing.append((rule["id"], k))
        self.assertEqual(missing, [],
                         "规则关键词没进门槛词表：%s" % missing[:5])

    def test_normal_commands_not_blocked_by_engine(self):
        """正常开发命令**不能被引擎拦**（那才是用户感受到的误报）。

        注意不断言"门槛必须为 False"—— 门槛是粗筛，派生词表比手写版宽
        （log / build / run / cat 这类短词也会被收进来），这是有意为之：
        宽一点的代价只是多扫几次（实测 1.5-8ms），漏收才是真漏。
        真正要保证的是引擎判定正确。
        """
        import tempfile
        import shutil as _sh
        from waf import rules as _rules
        from waf.engine import RuleEngine
        from waf.models import ScanTarget

        tmp = tempfile.mkdtemp(prefix="agentwaf-norm-")
        try:
            rp = os.path.join(tmp, "rules.json")
            _rules.save_document(_rules.default_document(), rp)
            engine = RuleEngine(rp)
            for cmd in ["ls -la /tmp", "git status", "git log --oneline -5",
                        "npm run build", "python -m unittest discover",
                        "docker ps -a", "kubectl get pods", "cat /etc/hosts",
                        "pip install -r requirements.txt", "git commit -m wip"]:
                target = ScanTarget(kind="curl", method="CLI",
                                    raw_cmd=cmd, tool="test")
                self.assertFalse(engine.scan(target, log=False).blocked,
                                 "正常命令被引擎误拦：%s" % cmd)
        finally:
            _sh.rmtree(tmp, ignore_errors=True)

class TestExcludeNotBypassable(unittest.TestCase):
    """回归：exclude 的"自然语言豁免"不能变成绕过通道（A 级）。

    实测 5 个 payload 全部放行，最短只有 9 个字符：

        op=a+b+c+delete
        op=just+do+it+delete
        op=delete+after+all+done
        action=just do it delete now&id=1
        api=1&action=do+it+now+delete

    根因：exclude 里两条"自然语言豁免"**没有锚定参数名**
        (?:^|[=\\s:])词(?:[\\s+]词){2,}[\\s+]delete
    本意是放过 ?q=how+to+delete+my+account 这类搜索描述，但不限定
    参数名 → 任意**动作参数**都能用 词+词+词+delete 触发豁免。
    这是核心规则失守，不是误报治理问题。

    修法：换成锚定搜索参数（q/query/search/…）的版本，并保留 SQL 守卫。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-excl-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)
        self.engine = RuleEngine(self.rules_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _blocked(self, body):
        target = ScanTarget(kind="request", method="POST",
                            url="http://target/api", body=body,
                            raw_cmd=body, tool="test")
        target.host, target.path, target.query = "target", "/api", ""
        return self.engine.scan(target, log=False).blocked

    def test_bypass_payloads_blocked(self):
        """实测给出的 5 个绕过 payload 必须全部拦下。"""
        for body in ["op=a+b+c+delete",
                     "op=just+do+it+delete",
                     "op=delete+after+all+done",
                     "action=just do it delete now&id=1",
                     "api=1&action=do+it+now+delete"]:
            self.assertTrue(self._blocked(body),
                            "exclude 仍可被反向利用：%r" % body)

    def test_sql_syntax_in_search_param_blocked(self):
        """搜索参数里的 SQL 语法照旧不豁免（守卫不能被削弱）。"""
        for body in ["q=delete+from+users",
                     "q=drop+table+users",
                     "search=delete+from+accounts+where+1=1"]:
            self.assertTrue(self._blocked(body),
                            "搜索参数里的 SQL 载荷被豁免了：%r" % body)

    def test_real_search_description_still_allowed(self):
        """真正该放行的自然语言描述仍要放行（豁免不能被删干净）。"""
        for body in ["q=how+to+remove+a+virus",
                     "q=how+do+i+delete+my+account"]:
            self.assertFalse(self._blocked(body),
                             "正常搜索描述被误拦：%r" % body)

    def test_natural_language_exclude_is_anchored(self):
        """两条自然语言 exclude 必须锚定参数名（防止再次退化成宽泛匹配）。"""
        doc = rules.default_document()
        rule = [r for r in doc["rules"] if r["id"] == "R-101"][0]
        for pattern in (rule.get("exclude") or []):
            if "remove|delete|purge|erase" not in pattern:
                continue
            self.assertIn("(?:^|[?&])", pattern,
                          "自然语言 exclude 没有锚定参数名，可被绕过：%s"
                          % pattern[:60])


class TestCmdFastPathSafety(unittest.TestCase):
    """回归：curl.cmd 的快路径不能短路强制拦截。

    加这条快路径是为了性能（WAF 关闭时不再付 Python 启动开销，
    review 指出每次 curl 慢 150-300ms）。但顺序必须是：

      1. WAF_ALWAYS_ON=1   -> 必须先走 shim
      2. WAF_DISABLE=1     -> 透传
      3. 心跳文件不存在    -> 快路径透传

    如果先查心跳，强制开启就会被静默降级成透传 —— 那是安全回归。
    """

    CMD = os.path.join(ROOT, "bin", "curl.cmd")

    def _src(self):
        with open(self.CMD, "r", encoding="ascii") as fh:
            return fh.read()

    def _heartbeat_line(self):
        return ('if not exist "%WAF_ROOT%' + chr(92) + 'data' + chr(92)
                + 'run' + chr(92) + 'active.json"')

    def test_cmd_is_ascii_only(self):
        """cmd.exe 按系统代码页解析，非 ASCII 会弄坏行结构。

        实测踩过：我写的诊断 .cmd 里带中文注释，第一个 echo 行被吞掉，
        goto 分支判断错位。curl.cmd 必须保持纯 ASCII。
        """
        with open(self.CMD, "rb") as fh:
            data = fh.read()
        bad = [(i, b) for i, b in enumerate(data) if b > 127]
        self.assertEqual(bad, [],
                         "curl.cmd 含非 ASCII 字节（cmd 解析会出错）：%s"
                         % bad[:5])

    def test_always_on_checked_before_heartbeat(self):
        """WAF_ALWAYS_ON 的判断必须排在心跳检查**之前**。"""
        src = self._src()
        i_on = src.find('if "%WAF_ALWAYS_ON%"=="1"')
        # 锚点必须精确到**心跳那一行**。
        # 踩过：早先用 find("if not exist")，结果匹配到 Python 缓存校验
        # 那行（if defined WAF_PY if not exist "%WAF_PY%" ...），
        # 于是断言测错了对象，误报"心跳排在前面"。
        i_hb = src.find(self._heartbeat_line())
        self.assertGreater(i_on, 0, "找不到 WAF_ALWAYS_ON 判断")
        self.assertGreater(i_hb, 0, "找不到心跳存在性检查")
        self.assertLess(i_on, i_hb,
                        "心跳检查排在 WAF_ALWAYS_ON 之前 —— "
                        "强制开启会被快路径静默降级成透传")

    def test_disable_checked_before_heartbeat(self):
        """WAF_DISABLE 也要在心跳之前（否则关不掉的场景会变慢）。"""
        src = self._src()
        i_dis = src.find('if "%WAF_DISABLE%"=="1"')
        i_hb = src.find(self._heartbeat_line())
        self.assertGreater(i_dis, 0, "找不到 WAF_DISABLE 判断")
        self.assertGreater(i_hb, 0, "找不到心跳存在性检查")
        self.assertLess(i_dis, i_hb, "WAF_DISABLE 排在心跳之后")

    def test_passthrough_uses_real_curl(self):
        """透传分支必须调真实 curl，而不是静默退出。"""
        src = self._src()
        # 用 "\n:passthrough" 找**标签定义**，而不是 goto 的引用。
        # 踩过：find(":passthrough") 先命中 `goto :passthrough`，
        # 往后 400 字符里根本没有 WAF_CURL，误报"透传分支没用真 curl"。
        i = src.find("\n:passthrough")
        self.assertGreater(i, 0, "找不到 :passthrough 标签定义")
        block = src[i:i + 500]
        self.assertIn("WAF_CURL", block,
                      "透传分支没用 WAF_CURL 调真实 curl")


class TestCrossProcessWriteLock(unittest.TestCase):
    """回归：rules.json 的并发读-改-写不能丢失更新（A 级）。

    实测（两个真实子进程）：A 关掉 R-101、B 暂停整体，最终
    settings.enabled 回到 True —— B"写入成功"了却完全没效果，
    因为后写者拿着自己读到的旧内容整体覆盖。

    修法：update_document 把「读-改-写」放进同一把跨进程文件锁。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-lock-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_update_document_is_atomic(self):
        """update_document 能读到别人的改动（不是拿旧副本覆盖）。"""
        def first(doc):
            for r in doc["rules"]:
                if r["id"] == "R-101":
                    r["enabled"] = False

        rules.update_document(first, self.rules_path)

        def second(doc):
            doc.setdefault("settings", {})["enabled"] = False

        rules.update_document(second, self.rules_path)

        final = rules.load_document(self.rules_path)
        r101 = [r for r in final["rules"] if r["id"] == "R-101"][0]
        self.assertIs(r101.get("enabled"), False,
                      "第一次的改动被覆盖 —— update_document 没读到最新内容")
        self.assertIs(final.get("settings", {}).get("enabled"), False,
                      "第二次的改动没落盘")

    def test_no_self_deadlock(self):
        """update_document 内部不能再取同一把文件锁（会自锁）。

        踩过：update_document 拿到锁后调 save_document，后者又取同一把
        锁 —— _CrossProcessLock 不可重入，acquire 抛 PermissionError，
        重试 5 秒后 fail-open 放行（锁等于白加，且每次写慢 5 秒）。
        实测耗时 5.05s；修好后 0.03s。
        """
        t0 = time.time()
        rules.update_document(lambda doc: None, self.rules_path)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 2.0,
                        "update_document 耗时 %.2fs —— 疑似又自锁了"
                        "（超时 fail-open 会耗时 ~5s）" % elapsed)

    def test_lock_file_does_not_leak_into_rules(self):
        """锁文件是 sidecar，不能被当成规则文件读。"""
        rules.update_document(lambda doc: None, self.rules_path)
        doc = rules.load_document(self.rules_path)
        self.assertIn("rules", doc)
        self.assertNotIn("lock", doc)

    def test_builtin_rules_still_load_after_lock(self):
        """加锁不能影响正常加载（回归保护）。"""
        doc = rules.load_document(self.rules_path)
        self.assertTrue(any(r["id"] == "R-101" for r in doc["rules"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
