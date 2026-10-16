# -*- coding: utf-8 -*-
"""回归：一键卸载必须真的"恢复原状"。

测的是承诺本身：装完之后机器上多了 6 处接入（AutoRun / BASH_ENV /
PowerShell profile / PYTHONPATH / HUNTGUARD_HOME / PATH 条目），
卸载之后必须**一处不剩**，而且用户自己的东西（PATH 条目、profile 内容、
.bashrc 内容、自己的 PYTHONPATH）一个都不能少。

为什么用假注册表：真卸载会把开发机/用户机上的接入拆掉 —— 测试绝不能
有副作用。这里把 winreg 换成内存实现，profile / bashrc / site-packages
全部指向临时目录，等于在一台"假机器"上跑完整的装-卸流程。
"""

import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from waf import config, install_path                   # noqa: E402


class FakeKey(object):
    def __init__(self, store, path, create):
        self.store = store
        self.path = path.lower()
        if create:
            store.setdefault(self.path, {})

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeWinreg(object):
    """够用的内存注册表：只实现 install_path 用到的那几个函数。"""

    HKEY_CURRENT_USER = "HKCU"
    HKEY_LOCAL_MACHINE = "HKLM"
    KEY_READ = 0x20019
    KEY_WRITE = 0x20006
    REG_SZ = 1
    REG_EXPAND_SZ = 2

    def __init__(self):
        self.hives = {"HKCU": {}, "HKLM": {}}

    def _resolve(self, root, subkey):
        hive = self.hives.setdefault(root, {})
        return hive, subkey.lower()

    def OpenKey(self, root, subkey, reserved=0, access=0):
        hive, key = self._resolve(root, subkey)
        if key not in hive:
            raise FileNotFoundError("key not found: %s" % subkey)
        return FakeKey(hive, key, create=False)

    def CreateKeyEx(self, root, subkey, reserved=0, access=0):
        hive, key = self._resolve(root, subkey)
        return FakeKey(hive, key, create=True)

    def QueryValueEx(self, key, name):
        values = key.store.get(key.path, {})
        if name not in values:
            raise FileNotFoundError("value not found: %s" % name)
        return values[name], FakeWinreg.REG_SZ

    def SetValueEx(self, key, name, reserved, kind, value):
        key.store.setdefault(key.path, {})[name] = value

    def DeleteValue(self, key, name):
        values = key.store.get(key.path, {})
        if name not in values:
            raise FileNotFoundError("value not found: %s" % name)
        del values[name]


class FakeSystemTest(unittest.TestCase):
    """把全部外部落点换成临时的，跑完整 install → uninstall。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-uninst-")
        self.fake = FakeWinreg()
        self.profile = os.path.join(self.tmp, "profile.ps1")
        self.bashrc = os.path.join(self.tmp, "bashrc")
        self.site = os.path.join(self.tmp, "site-packages")
        os.makedirs(self.site, exist_ok=True)

        # 用户自己的东西：卸载后必须原样还在
        self.user_path_entry = r"C:\Users\someone\bin"
        self.user_pythonpath = os.path.join(self.tmp, "my-python")
        self.profile_text = "# 用户自己的 PowerShell 配置\n$env:FOO = 'bar'\n"
        with open(self.profile, "w", encoding="utf-8") as fh:
            fh.write(self.profile_text)
        with open(self.bashrc, "w", encoding="utf-8") as fh:
            fh.write("# 用户自己的 bash 配置\nalias ll='ls -l'\n")
        env = self.fake.hives["HKCU"].setdefault("environment", {})
        env["Path"] = self.user_path_entry
        env["PYTHONPATH"] = self.user_pythonpath

        self._saved = {}
        self._patch("_try_import_winreg", lambda: self.fake)
        self._patch("_broadcast_environment_change", lambda: None)
        self._patch("is_admin", lambda: False)
        self._patch("powershell_profile_paths", lambda: [self.profile])
        self._patch("user_bashrc_path", lambda: self.bashrc)
        self._patch("python_user_site", lambda: self.site)

    def _patch(self, name, value):
        self._saved[name] = getattr(install_path, name)
        setattr(install_path, name, value)

    def tearDown(self):
        for name, value in self._saved.items():
            setattr(install_path, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _env(self):
        return self.fake.hives["HKCU"].get("environment", {})

    # -- 断言辅助 ----------------------------------------------------

    def assert_installed(self):
        """装完之后：六处接入都在。"""
        self.assertTrue(install_path.has_cmd_autorun(), "AutoRun 没装上")
        self.assertTrue(install_path.has_bash_env(), "BASH_ENV 没装上")
        self.assertTrue(install_path.has_powershell_profile(), "profile 没装上")
        self.assertTrue(install_path.has_python_hook(), "PYTHONPATH 没装上")
        self.assertTrue(install_path.has_home_env(), "HUNTGUARD_HOME 没写上")

    def assert_clean(self, where=""):
        """verify_clean() 必须一条残留都没有。"""
        dirty = [(name, detail) for name, clean, detail
                 in install_path.verify_clean() if not clean]
        self.assertEqual(dirty, [], "%s 卸载后仍有残留：%s" % (where, dirty))

    def assert_user_content_kept(self):
        with open(self.profile, "r", encoding="utf-8") as fh:
            profile = fh.read()
        self.assertIn("用户自己的 PowerShell 配置", profile)
        with open(self.bashrc, "r", encoding="utf-8") as fh:
            bashrc = fh.read()
        self.assertIn("alias ll=", bashrc)
        env = self._env()
        self.assertIn(self.user_path_entry, env.get("Path", ""),
                      "用户自己的 PATH 条目被吃掉了")
        self.assertIn(self.user_pythonpath, env.get("PYTHONPATH", ""),
                      "用户自己的 PYTHONPATH 被吃掉了")

    # -- 用例 --------------------------------------------------------

    def test_install_then_uninstall_is_clean(self):
        """装 → 卸：六处接入一处不剩，用户的东西一个不少。"""
        install_path.install()
        self.assert_installed()
        self.assertNotEqual(
            [c for c in install_path.verify_clean() if not c[1]], [],
            "装完之后 verify_clean 应该能看出这些接入")

        install_path.uninstall()
        self.assert_clean("卸载之后")
        self.assert_user_content_kept()

    def test_uninstall_is_idempotent(self):
        """连卸两次不能报错、也不能把别的东西删掉。"""
        install_path.install()
        install_path.uninstall()
        install_path.uninstall()
        self.assert_clean("连着卸两次之后")
        self.assert_user_content_kept()

    def test_home_env_pointing_elsewhere_is_kept(self):
        """HUNTGUARD_HOME 指向别的安装副本时，不能动它。

        别人机器上可能同时有两份（复制目录做测试很常见），
        卸载一份把另一份的指针删了会直接搞坏那份。
        """
        other = os.path.join(self.tmp, "another-copy")
        env = self._env()
        env["HUNTGUARD_HOME"] = other
        install_path.uninstall()
        self.assertEqual(self._env().get("HUNTGUARD_HOME"), other,
                         "指向别处的 HUNTGUARD_HOME 被误删")

    def test_verify_clean_reports_shape(self):
        """verify_clean() 的返回结构是稳定的（UI/脚本会读它）。"""
        checks = install_path.verify_clean()
        names = [name for name, _clean, _detail in checks]
        for expected in install_path.CLEAN_CHECK_NAMES:
            self.assertIn(expected, names)
        for _name, clean, detail in checks:
            self.assertIsInstance(clean, bool)
            self.assertTrue(detail)


class TestPurgeData(unittest.TestCase):
    """``--purge-data`` 的删除行为与**防呆**。"""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-purge-")
        self.data = os.path.join(self.tmp, "data")
        os.makedirs(os.path.join(self.data, "run"))
        os.makedirs(os.path.join(self.data, "certs"))
        for rel in ("events.db", "rules.json", "config.json",
                    os.path.join("run", "active.json"),
                    os.path.join("certs", "ca.key")):
            with open(os.path.join(self.data, rel), "w",
                      encoding="utf-8") as fh:
                fh.write("x")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_purge_removes_everything(self):
        ok, msg, removed = install_path.purge_data_dir(
            self.data, require_inside_root=False)
        self.assertTrue(ok, msg)
        self.assertEqual(removed, 5)
        self.assertFalse(os.path.isdir(self.data), "data 目录没删掉")

    def test_missing_dir_is_not_an_error(self):
        ok, _msg, removed = install_path.purge_data_dir(
            os.path.join(self.tmp, "nope"), require_inside_root=False)
        self.assertTrue(ok)
        self.assertEqual(removed, 0)

    def test_refuses_outside_install_root(self):
        """默认只肯删安装目录内的东西 —— 防手滑/防配置被改。"""
        ok, msg, removed = install_path.purge_data_dir(self.data)
        self.assertFalse(ok, "删了安装目录外的目录：%s" % msg)
        self.assertEqual(removed, 0)
        self.assertTrue(os.path.isdir(self.data), "文件被删了")

    def test_refuses_drive_root(self):
        ok, _msg, _removed = install_path.purge_data_dir(
            os.path.abspath(os.sep), require_inside_root=False)
        self.assertFalse(ok, "居然同意删盘根")

    def test_cli_flag_parses(self):
        from waf import cli
        parser = cli.build_parser()
        args = parser.parse_args(["uninstall-path", "--purge-data"])
        self.assertTrue(args.purge_data)
        args = parser.parse_args(["uninstall-path"])
        self.assertFalse(args.purge_data)


class TestUninstallerBatch(unittest.TestCase):
    """uninstall.bat 的静态检查（逻辑部分在 TestPurgeData / FakeSystemTest）。"""

    def setUp(self):
        self.path = os.path.join(ROOT, "uninstall.bat")
        with open(self.path, "rb") as fh:
            self.raw = fh.read()
        self.text = self.raw.decode("ascii", "replace")

    def test_exists_and_is_ascii(self):
        self.assertTrue(os.path.isfile(self.path))
        try:
            self.raw.decode("ascii")
        except UnicodeDecodeError as exc:
            self.fail("uninstall.bat 含非 ASCII（cmd 按系统代码页读会乱码）：%s"
                      % exc)

    def test_calls_the_uninstall_entry_point(self):
        self.assertIn("cli.py", self.text)
        self.assertIn("uninstall-path", self.text)
        self.assertIn("_find-python.cmd", self.text)

    def test_asks_before_irreversible_steps(self):
        """删 data / 删目录都必须先问，且默认是"不删"。"""
        self.assertIn("_DELDATA", self.text)
        self.assertIn("_DELDIR", self.text)
        self.assertIn("--purge-data", self.text)

    def test_has_non_interactive_mode(self):
        """无人值守卸载（自动化/AI 用）：WAF_UNINSTALL=yes|purge|all。

        为什么不靠 `echo Y | uninstall.bat`：cmd 的 set /p 第一次调用会
        把**整个重定向缓冲**当成一个值吃掉（实测 `_ANS` 变成
        "Y<换行>N<换行>N"，后面的 if 直接语法错），所以多提问的批处理
        根本没法用管道驱动 —— 必须给一个环境变量入口。
        """
        for value in ("yes", "purge", "all"):
            self.assertIn('"%s"' % value, self.text,
                          "缺少 WAF_UNINSTALL=%s 分支" % value)
        self.assertIn("WAF_UNINSTALL", self.text)

    def test_interactive_prompts_still_there(self):
        self.assertIn("set /p", self.text, "交互式提问被删掉了")

    def test_self_delete_is_guarded(self):
        """自删前必须确认这真是安装目录，且拒绝盘根。"""
        for marker in ("waf\\cli.py", "README.md", "uninstall.bat"):
            self.assertIn(marker, self.text,
                          "自删前的安装目录校验缺少 %s" % marker)
        self.assertIn('if "%_DIR:~1%"==":" goto :unsafe', self.text,
                      "缺少盘根防护")

    def test_no_hardcoded_install_path(self):
        for bad in ("D:\\agent-waf", "C:\\Users\\", "E:\\Git"):
            self.assertNotIn(bad, self.text, "写死了开发机路径：%s" % bad)


if __name__ == "__main__":
    unittest.main()
