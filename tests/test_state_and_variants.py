# -*- coding: utf-8 -*-
"""激活态（"我开了才生效"）与删除变种规则的自测。"""

import json
import os
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

from waf import config, rules, state                         # noqa: E402
from waf.engine import RuleEngine                            # noqa: E402
from waf.models import ALL_SOURCES, ScanTarget               # noqa: E402
from waf.rules import _content_fingerprint as fingerprint     # noqa: E402


def _scan(engine, url="", body="", raw_cmd=""):
    from urllib.parse import urlsplit
    target = ScanTarget(kind="request", method="GET", url=url, body=body,
                        raw_cmd=raw_cmd, tool="test")
    if url:
        parts = urlsplit(url)
        target.host, target.path, target.query = parts.netloc, parts.path, parts.query
    return engine.scan(target, log=False)


class TempRulesMixin(unittest.TestCase):
    """每个测试用临时规则文件，避免污染真实配置。

    必须继承 TestCase —— 否则 unittest 不会收集继承它的测试类
    （表现是"测试数对不上、新用例静默不跑"，很坑）。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-state-")
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)
        self.engine = RuleEngine(self.rules_path)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


# ====================================================================
# 1. 删除变种规则
# ====================================================================

class TestDeletionVariants(TempRulesMixin):
    """常见删除写法的变种都应被拦下。"""

    SHOULD_BLOCK = [
        # (说明, URL)
        ("delete 参数", "http://127.0.0.1/1.php?delete=test.txt"),
        ("delete 路径", "http://127.0.0.1/delete.php?id=1"),
        ("del 路径段（用户反馈）", "http://127.0.0.1/del/a.txt"),
        ("del 参数", "http://127.0.0.1/api?op=del"),
        ("dels", "http://127.0.0.1/api?op=dels"),
        ("rm 路径段", "http://127.0.0.1/api/rm/1"),
        ("rmdir", "http://127.0.0.1/api?c=rmdir"),
        ("rimraf", "http://127.0.0.1/api?c=rimraf"),
        ("remove", "http://127.0.0.1/api?action=remove"),
        ("removeAll", "http://127.0.0.1/api?action=removeAll"),
        ("removeFile", "http://127.0.0.1/api?f=removeFile"),
        ("Remove-Item", "http://127.0.0.1/api?c=Remove-Item"),
        ("unlink", "http://127.0.0.1/api?c=unlink"),
        ("os.remove", "http://127.0.0.1/api?c=os.remove(x)"),
        ("fs.unlink", "http://127.0.0.1/api?c=fs.unlink(x)"),
        ("shutil.rmtree", "http://127.0.0.1/api?c=shutil.rmtree(p)"),
        ("erase", "http://127.0.0.1/api?c=erase"),
        ("destroy", "http://127.0.0.1/api?c=destroy"),
        ("wipe", "http://127.0.0.1/api?c=wipe"),
        ("purge", "http://127.0.0.1/api?c=purge"),
        ("shred", "http://127.0.0.1/api?c=shred"),
        ("truncate table", "http://127.0.0.1/api?q=truncate%20table%20users"),
        ("drop table", "http://127.0.0.1/api?q=drop%20table%20users"),
        ("deleteMany", "http://127.0.0.1/api?c=deleteMany()"),
        ("obliterate", "http://127.0.0.1/api?c=obliterate"),
        ("annihilate", "http://127.0.0.1/api?c=annihilate"),
    ]

    SHOULD_ALLOW = [
        ("model（含 del）", "http://127.0.0.1/api?name=model"),
        ("delay（含 del）", "http://127.0.0.1/api?t=delay"),
        ("delta", "http://127.0.0.1/api?n=delta"),
        ("delegate", "http://127.0.0.1/api?n=delegate"),
        ("order（含 der）", "http://127.0.0.1/api?n=order"),
        ("handler", "http://127.0.0.1/api?h=handler"),
        ("border", "http://127.0.0.1/api?n=border"),
        ("format 单词（无盘符）", "http://127.0.0.1/api?fmt=format"),
        ("正常接口", "http://127.0.0.1/api?action=list&id=1"),
        ("deleted_at 软删除字段", "http://127.0.0.1/api?deleted_at=2024-01-01"),
    ]

    def test_should_block(self):
        for label, url in self.SHOULD_BLOCK:
            verdict = _scan(self.engine, url=url)
            self.assertTrue(verdict.blocked,
                            "应拦截但放行：%s (%s)" % (label, url))

    def test_should_allow(self):
        for label, url in self.SHOULD_ALLOW:
            verdict = _scan(self.engine, url=url)
            self.assertFalse(verdict.blocked,
                             "不应拦截：%s -> %s 规则=%s"
                             % (label, verdict.reason,
                                [h.rule_id for h in verdict.hits]))

    def test_commands_block(self):
        for raw in ("rm -rf /var/www", "rmdir /s /q C:\\temp",
                    "del /f C:\\temp\\a.txt", "rd /s C:\\data",
                    ":(){:|:&};:", "mkfs.ext4 /dev/sda1"):
            verdict = _scan(self.engine, raw_cmd=raw)
            self.assertTrue(verdict.blocked, "应拦截命令：%s" % raw)

    def test_body_variants(self):
        for body in ("action=delete", "op=remove", '{"cmd":"rm -rf /"}',
                     "action=del", "method=unlink"):
            verdict = _scan(self.engine, url="http://x/api", body=body)
            self.assertTrue(verdict.blocked, "应拦截 body：%s" % body)


# ====================================================================
# 2. 内置规则迁移
# ====================================================================

# ====================================================================
# 2.5 字段范围：默认全字段
# ====================================================================

class TestSourceScope(TempRulesMixin):
    """规则默认检查全部字段 —— 缩小范围是高级选项，不该是默认。"""

    def test_default_rules_have_empty_sources(self):
        for rule in self.engine.rules:
            self.assertEqual(
                list(rule.get("sources") or []), [],
                "内置规则 %s 不该限定字段（空 = 全部字段）" % rule.get("id"))

    def test_empty_sources_covers_every_field(self):
        """空 sources 必须覆盖 8 个维度，少一个就是漏拦。"""
        from waf.models import ALL_SOURCES
        probe = {
            "method": dict(method="DELETE"),
            "url": dict(url="http://x/api?q=delete"),
            "path": dict(url="http://x/delete", path="/delete"),
            "query": dict(url="http://x/api?op=delete", query="op=delete"),
            "body": dict(url="http://x/api", body="action=delete"),
            "headers": dict(url="http://x/api",
                            headers={"X-Op": "delete all"}),
            "host": dict(url="http://delete.internal/api",
                         host="delete.internal"),
            "raw_cmd": dict(raw_cmd="rm -rf /tmp/x"),
        }
        for source in ALL_SOURCES:
            kwargs = dict(probe[source])
            kwargs.setdefault("url", "http://x/api")
            target = ScanTarget(kind="request", tool="test", **kwargs)
            verdict = self.engine.scan(target, log=False)
            self.assertTrue(verdict.blocked,
                            "字段 %s 应被覆盖但漏拦了" % source)

    def test_narrowed_sources_still_honored(self):
        """用户主动缩范围时必须尊重（这是高级里的排误报手段）。"""
        doc = rules.load_document(self.rules_path)
        for rule in doc["rules"]:
            if rule["id"] == "R-101":
                rule["sources"] = ["url"]      # 只看 URL
        rules.save_document(doc, self.rules_path)
        self.engine.load(force=True)

        # URL 里命中 → 拦
        self.assertTrue(_scan(self.engine, url="http://x/api?q=delete").blocked)
        # body 里命中 → 不拦（因为用户限定只看 url）
        self.assertFalse(_scan(self.engine, url="http://x/api",
                               body="action=delete").blocked)

    def test_empty_and_full_list_equivalent(self):
        """留空与显式列出全部字段语义相同 —— 指纹与判定都要一致。"""
        empty = {"id": "R-X", "name": "t", "match_mode": "substring",
                 "keywords": ["w"], "sources": []}
        full = dict(empty, sources=list(ALL_SOURCES))
        self.assertEqual(fingerprint(empty), fingerprint(full))

    def test_save_then_reload_keeps_full_scope(self):
        """UI 保存（提交空 sources）后仍是全字段，且不会标记成"用户定制"。"""
        doc = rules.load_document(self.rules_path)
        rule = [r for r in doc["rules"] if r["id"] == "R-101"][0]
        round_tripped = dict(rule)
        round_tripped["sources"] = []          # UI 提交的形态
        saved = rules.upsert_rule(doc, round_tripped)
        self.assertEqual(saved["sources"], [])
        self.assertTrue(saved.get("_builtin_hash"),
                        "只是保存、没改内容 → 不该丢弃内置指纹")


class TestRuleMigration(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-migrate-")
        self.path = os.path.join(self.tmp, "rules.json")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _legacy_file(self, rev=0, strip_hash=True):
        """造一个"老用户"文件。"""
        rules.save_document(rules.default_document(), self.path)
        with open(self.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        doc["defaults_rev"] = rev
        if strip_hash:
            for rule in doc["rules"]:
                rule.pop("_builtin_hash", None)
        # 只留最初的几条，模拟旧版
        doc["rules"] = [r for r in doc["rules"]
                        if r["id"] in ("R-101", "R-102", "R-103")]
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
        return doc

    def test_new_rules_added(self):
        self._legacy_file()
        doc = rules.load_document(self.path)
        ids = {r["id"] for r in doc["rules"]}
        self.assertIn("R-105", ids, "新增的 del/rm 规则应自动补齐")
        self.assertIn("R-106", ids)
        self.assertGreaterEqual(doc.get("defaults_rev"), rules.DEFAULTS_REV)

    def test_user_edit_preserved(self):
        self._legacy_file()
        with open(self.path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for rule in doc["rules"]:
            if rule["id"] == "R-101":
                rule["keywords"].append("MY_CUSTOM_WORD")
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)

        doc = rules.load_document(self.path)
        r101 = [r for r in doc["rules"] if r["id"] == "R-101"][0]
        self.assertIn("MY_CUSTOM_WORD", r101["keywords"],
                      "用户自己加的关键词必须保留")

    def test_user_deletion_respected(self):
        doc = rules.load_document(self.path)
        rules.delete_rule(doc, "R-102")
        rules.save_document(doc, self.path)

        # 把 rev 降下来，模拟再次触发迁移
        with open(self.path, encoding="utf-8") as fh:
            raw = json.load(fh)
        raw["defaults_rev"] = 0
        with open(self.path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, ensure_ascii=False, indent=2)

        doc = rules.load_document(self.path)
        self.assertNotIn("R-102", {r["id"] for r in doc["rules"]},
                         "用户删掉的规则不应被迁移复活")
        self.assertIn("R-102", doc.get("removed_defaults") or [])

    def test_edited_builtin_not_overwritten(self):
        """改过内容的规则不该被新版模板覆盖。"""
        path = os.path.join(self.tmp, "rules2.json")
        rules.save_document(rules.default_document(), path)
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        for rule in doc["rules"]:
            if rule["id"] == "R-105":
                rule["keywords"] = ["only_my_word"]
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)

        # 触发迁移
        with open(path, encoding="utf-8") as fh:
            raw = json.load(fh)
        raw["defaults_rev"] = 0
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(raw, fh, ensure_ascii=False, indent=2)

        doc = rules.load_document(path)
        r105 = [r for r in doc["rules"] if r["id"] == "R-105"][0]
        self.assertEqual(r105["keywords"], ["only_my_word"],
                         "用户改过的内置规则不应被覆盖")


# ====================================================================
# 3. 激活态：我开了才生效
# ====================================================================

class TestActivationState(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-active-")
        self.hb = os.path.join(self.tmp, "active.json")
        # 把心跳路径指向隔离文件：否则测试会读到真实控制台的心跳，
        # 结果依赖外部进程是否在跑（不稳定，且会互相干扰）。
        self._saved = os.environ.get("WAF_STATE_FILE")
        os.environ["WAF_STATE_FILE"] = self.hb
        os.environ.pop("WAF_ALWAYS_ON", None)
        os.environ.pop("WAF_ALWAYS_OFF", None)

    def tearDown(self):
        state.stop_heartbeat()
        if self._saved is None:
            os.environ.pop("WAF_STATE_FILE", None)
        else:
            os.environ["WAF_STATE_FILE"] = self._saved
        os.environ.pop("WAF_ALWAYS_ON", None)
        os.environ.pop("WAF_ALWAYS_OFF", None)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_inactive_when_no_heartbeat(self):
        self.assertFalse(state.is_active(self.hb))
        self.assertFalse(state.should_intercept()[0])

    def test_active_after_activate(self):
        state.activate(port=1234, path=self.hb)
        try:
            self.assertTrue(state.is_active(self.hb))
            active, reason = state.should_intercept(path=self.hb)
            self.assertTrue(active, reason)
        finally:
            state.deactivate(self.hb)

    def test_inactive_after_deactivate(self):
        state.activate(port=1234, path=self.hb)
        state.deactivate(self.hb)
        self.assertFalse(state.is_active(self.hb))

    def test_stale_heartbeat_expires(self):
        """控制台被强杀（心跳没人刷新）：过期后自动失效。"""
        state.activate(port=1234, path=self.hb)
        state.stop_heartbeat()          # 停止刷新，模拟强杀
        old = time.time() - (state.STALE_AFTER + 5)
        os.utime(self.hb, (old, old))
        self.assertFalse(state.is_active(self.hb),
                         "心跳过期后应视为未运行")

    def test_always_off_wins(self):
        state.activate(port=1234, path=self.hb)
        try:
            os.environ["WAF_ALWAYS_OFF"] = "1"
            self.assertFalse(state.is_active(self.hb))
            self.assertFalse(state.should_intercept()[0])
        finally:
            state.deactivate(self.hb)

    def test_always_on_wins(self):
        os.environ["WAF_ALWAYS_ON"] = "1"
        self.assertTrue(state.is_active(self.hb))
        self.assertTrue(state.should_intercept()[0])

    def test_engine_switch_off_blocks_intercept(self):
        """控制台在跑但用户按了暂停 → 不拦截。"""
        state.activate(port=1234, path=self.hb)
        try:
            tmp = tempfile.mkdtemp()
            try:
                path = os.path.join(tmp, "rules.json")
                rules.save_document(rules.default_document(), path)
                engine = RuleEngine(path)
                self.assertTrue(state.should_intercept(engine, path=self.hb)[0],
                                "开关开着时应拦截")
                engine.set_enabled(False)
                active, reason = state.should_intercept(engine, path=self.hb)
                self.assertFalse(active, "暂停后不应拦截：%s" % reason)
                self.assertIn("暂停", reason)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        finally:
            state.deactivate(self.hb)


# ====================================================================
# 4. curl shim 遵从激活态
# ====================================================================

class TestShimActivation(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-shim-")
        self.hb = os.path.join(self.tmp, "active.json")
        # 规则文件也隔离：否则总开关的实时状态会决定测试结果
        self.rules_path = os.path.join(self.tmp, "rules.json")
        rules.save_document(rules.default_document(), self.rules_path)

    def tearDown(self):
        state.stop_heartbeat()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run_shim(self, url, extra_env=None):
        env = dict(os.environ)
        env["PYTHONPATH"] = ROOT
        env["WAF_NO_LOG"] = "1"
        # 子进程也要指向隔离心跳文件，否则会读到真实控制台的状态
        env["WAF_STATE_FILE"] = self.hb
        # 同样隔离规则文件：不读本机 data/rules.json
        env["AGENTWAF_RULES_FILE"] = self.rules_path
        env.pop("WAF_RULES_FILE", None)
        env.pop("WAF_ALWAYS_ON", None)
        env.pop("WAF_ALWAYS_OFF", None)
        env.update(extra_env or {})
        script = os.path.join(ROOT, "waf", "curlshim.py")
        return subprocess.run([sys.executable, script, "-s", url],
                              capture_output=True, env=env, timeout=30)

    def test_passthrough_when_inactive(self):
        """未开启：应透传给真实 curl（exit 7 = 连不上，不是 126）。"""
        proc = self._run_shim("http://127.0.0.1:1/1.php?delete=test.txt")
        self.assertNotEqual(proc.returncode, 126,
                            "未开启时不应拦截：%s"
                            % proc.stdout.decode("utf-8", "replace")[:200])

    def test_blocks_when_always_on(self):
        """WAF_ALWAYS_ON=1 强制开启：应拦截。"""
        proc = self._run_shim("http://127.0.0.1/1.php?delete=test.txt",
                              {"WAF_ALWAYS_ON": "1"})
        self.assertEqual(proc.returncode, 126, "强制开启时应拦截")
        data = json.loads(proc.stdout.decode("utf-8", "replace"))
        self.assertTrue(data["blocked"])

    def test_always_off_overrides(self):
        proc = self._run_shim("http://127.0.0.1/1.php?delete=test.txt",
                              {"WAF_ALWAYS_OFF": "1"})
        self.assertNotEqual(proc.returncode, 126)
        self.assertNotIn("命中敏感词", proc.stdout.decode("utf-8", "replace"))


# ====================================================================
# 5. PATH 接入模块
# ====================================================================

class TestInstallPath(unittest.TestCase):

    def test_module_imports(self):
        from waf import install_path
        self.assertTrue(callable(install_path.status))
        self.assertTrue(callable(install_path.install))
        self.assertTrue(callable(install_path.uninstall))

    def test_status_shape(self):
        from waf import install_path
        st = install_path.status()
        for key in ("bin_dir", "resolved", "shim_wins", "is_windows"):
            self.assertIn(key, st)

    def test_autorun_preserves_existing(self):
        """写 AutoRun 时不能破坏用户已有的其它命令。"""
        from waf import install_path
        existing = "doskey ls=dir"
        # _strip_our_autorun 对不含标记的内容应原样返回
        self.assertEqual(install_path._strip_our_autorun(existing), existing)


if __name__ == "__main__":
    unittest.main(verbosity=2)
