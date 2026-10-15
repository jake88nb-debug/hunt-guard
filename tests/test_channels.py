# -*- coding: utf-8 -*-
"""多渠道覆盖（AI 工具会话）自测。

覆盖的四个通道：
  1. Git Bash  —— BASH_ENV（ZCode / Claude Code / Codex 在 Windows 上执行
                  命令走的就是非交互 Git Bash）
  2. Python    —— .pth 钩子（AI 写的 requests 脚本）
  3. PowerShell—— profile 里删别名 + 前置 PATH
  4. cmd       —— AutoRun

重点验证两件事：
  * **装了要能拦**：WAF 开启时请求被拦下
  * **关了不干扰**：WAF 关闭时零输出污染、原样透传
（"关了不干扰"比"开了能拦"更容易出问题 —— 钩子在每个进程都会跑）
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

# 关键：本进程内 import waf.autohook 会把护栏装到**测试进程自己**身上，
# 之后所有 subprocess 调用都会被自己拦下（实测踩过：整个套件跑不完）。
# 把心跳指到不存在的路径即可让 autohook 判定"控制台没开"而保持静默。
os.environ.setdefault("WAF_STATE_FILE",
                      os.path.join(tempfile.gettempdir(),
                                   "agentwaf-test-no-heartbeat.json"))

from waf import install_path                            # noqa: E402


def _bash_available():
    """这台机器上能不能跑 bash。

    为什么需要（实测发现）：仓库里 8 个测试直接
    subprocess.run(["bash", ...])，在没装 bash 的环境（纯 Windows、
    精简 CI 容器）上全部 ERROR —— 测试套件在别人的机器上不绿，
    会让"下载即用"的承诺打折扣。缺 bash 时应当 skip 而不是 ERROR。
    """
    import shutil as _sh
    return _sh.which("bash") is not None


requires_bash = unittest.skipUnless(
    _bash_available(), "这台机器没有 bash，跳过 Git Bash 通道测试")


class TestPowerShellProfileIdempotent(unittest.TestCase):
    """profile 反复安装不能越写越长 —— 这是线上会真实发生的问题。

    新架构：profile 里只有**一行指针**指向 <root>\\bin\\waf.ps1，
    真正的处理（删 curl 别名 + 前置 PATH）在项目目录内的脚本里。
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-ps-")
        self.profile = os.path.join(self.tmp, "profile.ps1")
        self._orig = install_path.powershell_profile_paths
        install_path.powershell_profile_paths = lambda: [self.profile]

    def tearDown(self):
        install_path.powershell_profile_paths = self._orig
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _lines(self):
        with open(self.profile, "r", encoding="utf-8") as fh:
            return [l for l in fh.read().splitlines() if l.strip()]

    def test_install_is_idempotent(self):
        install_path.install_powershell_profile()
        first = len(self._lines())
        for _ in range(3):
            install_path.install_powershell_profile()
        self.assertEqual(len(self._lines()), first,
                         "重复安装导致 profile 反复追加内容")

    def test_profile_stays_minimal(self):
        """profile 必须保持极简 —— 只有指针，没有逻辑。

        这是"所有文件都在安装目录内"的核心：profile 里出现别的东西
        就意味着逻辑漏到外面了。
        """
        install_path.install_powershell_profile()
        lines = self._lines()
        self.assertLessEqual(len(lines), 5,
                             "profile 太长了，逻辑应该放在 bin/waf.ps1：%s" % lines)
        content = "\n".join(lines)
        self.assertIn("waf.ps1", content, "缺少指向 bin/waf.ps1 的指针")

    def test_pointer_has_absolute_fallback(self):
        """指针要有绝对路径兜底 —— 环境变量要新终端才可见。"""
        install_path.install_powershell_profile()
        with open(self.profile, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("AGENTWAF_HOME", content)
        # profile 里存的是安装根目录，再拼 \bin\waf.ps1
        self.assertIn(install_path.config.ROOT, content,
                      "缺少安装目录的绝对路径兜底")

    def test_ps1_script_removes_curl_alias(self):
        """删别名的逻辑在项目内的 bin/waf.ps1 里（不在外部 profile）。

        只删**内置的** Invoke-WebRequest 别名 —— 早先无条件删任何同名
        别名，会把用户自己定义的 curl/wget 别名静默抹掉。
        """
        script = os.path.join(install_path.bin_dir(), "waf.ps1")
        self.assertTrue(os.path.isfile(script), "缺少 %s" % script)
        with open(script, "r", encoding="utf-8") as fh:
            content = fh.read()
        # 仍要删内置别名，否则 curl 不经过 PATH
        self.assertIn("Remove-Item", content)
        self.assertIn("Alias:$name", content)
        # 关键：必须比对 Definition，只删内置的那个
        self.assertIn("Invoke-WebRequest", content,
                      "必须只删内置别名（比对 Definition），"
                      "否则会误删用户自定义的 curl 别名")
        self.assertIn("PATH", content)

    def test_ps1_script_is_ascii(self):
        """bin/waf.ps1 必须纯 ASCII（PowerShell 5.1 按 ANSI 读无 BOM 文件）。"""
        script = os.path.join(install_path.bin_dir(), "waf.ps1")
        with open(script, "rb") as fh:
            data = fh.read()
        try:
            data.decode("ascii")
        except UnicodeDecodeError as exc:
            self.fail("bin/waf.ps1 含非 ASCII 字符：%s" % exc)

    def test_preserves_user_content(self):
        """用户自己的 profile 内容不能被吃掉。"""
        with open(self.profile, "w", encoding="utf-8") as fh:
            fh.write("# 用户自己的配置\nSet-Alias ll Get-ChildItem\n")
        install_path.install_powershell_profile()
        with open(self.profile, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("用户自己的配置", content)
        self.assertIn("Set-Alias ll", content)
        self.assertIn("waf.ps1", content)

    def test_cleans_legacy_forms(self):
        """历史版本写的多种形态都要能清掉，且不留孤立大括号。

        旧版曾在 profile 里写 `if (...) { ... }` 块，逐行过滤会留下
        孤立的 `}`，直接让整个 profile 解析失败 —— 必须整块删。
        """
        legacy = (
            "# agent-waf\n"
            'if ($env:PATH -notlike "*D:\\agent-waf\\bin*") '
            '{ $env:PATH = "D:\\agent-waf\\bin;" + $env:PATH }\n'
            "# agent-waf: 移除 curl 别名\n"
            "if (Test-Path Alias:curl) { Remove-Item Alias:curl -Force }\n"
            "# One-line pointer: all logic lives in the project folder.\n"
            "if ($env:AGENTWAF_HOME -and (Test-Path \"$env:AGENTWAF_HOME\\bin\\waf.ps1\")) {\n"
            '    . "$env:AGENTWAF_HOME\\bin\\waf.ps1"\n'
            "}\n"
            "# end-agent-waf\n"
        )
        with open(self.profile, "w", encoding="utf-8") as fh:
            fh.write(legacy)
        install_path.install_powershell_profile()
        with open(self.profile, "r", encoding="utf-8") as fh:
            content = fh.read()

        # 只应剩一个我们写的区块
        self.assertEqual(content.count("# agent-waf"), 1)
        # 不能有孤立的右大括号（会让 PowerShell 解析失败）
        for line in content.splitlines():
            self.assertNotEqual(line.strip(), "}",
                                "残留了孤立大括号，profile 会解析失败")

    def test_uninstall_removes_ours_only(self):
        with open(self.profile, "w", encoding="utf-8") as fh:
            fh.write("# 用户配置\n")
        install_path.install_powershell_profile()
        install_path.uninstall_powershell_profile()
        with open(self.profile, "r", encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("用户配置", content)
        self.assertNotIn("waf.ps1", content)


class TestRegistryPathNormalize(unittest.TestCase):
    """注册表里"值不存在"必须判定为空，不能等于真实路径。

    历史 bug（很隐蔽）：``_normalize("")`` 走 ``os.path.abspath("")``，
    返回的是**当前工作目录**。安装脚本又恰好是在安装目录里执行的，
    于是 ``_normalize("") == _normalize(ROOT)`` 恒成立，
    ``install_home_env()`` 把"注册表里没这个值"当成"值已经对了"，
    报"已是目标值"却一个字节都没写：

        AGENTWAF_HOME 从不生效 → PowerShell profile 的条件行失效
        → PowerShell 里 curl 仍是 Invoke-WebRequest 别名 → 静默绕过拦截

    换个目录跑就正常，所以只看代码很难发现，必须有测试盯着。
    """

    def test_empty_is_not_cwd(self):
        saved = os.getcwd()
        try:
            # 安装脚本的典型 cwd —— bug 就在这个组合下触发
            os.chdir(install_path.config.ROOT)
            self.assertEqual(install_path._normalize(""), "",
                             "空路径被归一化成了当前工作目录")
            self.assertNotEqual(
                install_path._normalize(""),
                install_path._normalize(install_path.config.ROOT),
                "空值与安装目录被判为同一路径 —— install_home_env 会静默失效")
        finally:
            os.chdir(saved)

    def test_real_paths_still_compare(self):
        """修空值不能把正常比较弄坏（大小写、尾斜杠、相对路径）。"""
        root = install_path.config.ROOT
        self.assertEqual(install_path._normalize(root),
                         install_path._normalize(root + os.sep))
        if os.name == "nt":
            # normcase 只在 Windows 折叠大小写
            self.assertEqual(install_path._normalize(root),
                             install_path._normalize(root.upper()))
        self.assertNotEqual(install_path._normalize(root),
                            install_path._normalize(os.path.join(root, "bin")))


@requires_bash
class TestBashEnvScript(unittest.TestCase):
    """bin/waf-bash-env.sh 是 Git Bash 覆盖的载体，要求静默、幂等、极快。"""

    def setUp(self):
        self.script = install_path.bash_env_script()

    def test_script_exists(self):
        self.assertTrue(os.path.isfile(self.script),
                        "缺少 BASH_ENV 脚本：%s" % self.script)

    def test_script_is_silent(self):
        """source 它不能产生任何输出 —— 输出会污染调用方脚本。"""
        proc = self._run_bash('. "%s"' % self.script)
        self.assertEqual(proc.stdout.decode("utf-8", "replace").strip(), "",
                         "BASH_ENV 脚本产生了 stdout 输出")
        self.assertEqual(proc.stderr.decode("utf-8", "replace").strip(), "",
                         "BASH_ENV 脚本产生了 stderr 输出")

    def _run_bash(self, code, env_extra=None):
        """在受控环境里跑 bash。

        ``BASH_ENV`` 清空是必须的：测试进程继承了宿主 shell 的 BASH_ENV，
        不清的话 bash 启动时就会先 source 一次我们的脚本，加上测试里
        再 source，次数就对不上了（这也是之前测试偶发失败的原因）。
        """
        env = dict(os.environ)
        env["BASH_ENV"] = ""                      # 隔离：由测试自己控制 source
        env["PATH"] = "/usr/bin:/bin"             # 干净起点
        env.update(env_extra or {})
        return subprocess.run(["bash", "-c", code], capture_output=True,
                              timeout=25, env=env)

    @property
    def _bin_posix(self):
        """本安装的 bin 目录（POSIX 形式）。

        不能硬编码 "agent-waf"：别人从 GitHub 下载后目录名可能是
        ``agent-waf-main``、``waf`` 或任何自定义名字，硬编码会让
        测试在别人的机器上误报。

        也不能只靠 ``_to_posix`` 做纯字符串推算 —— 在 Git Bash 的
        /tmp 沙箱里（如本测试从 /tmp 下运行时），同一个目录在 bash
        眼里是 ``/tmp/x/bin``，而推算出来是 ``/c/Users/.../Temp/x/bin``，
        两者其实是同一个地方却比不相等。所以交给 bash 自己解析
        （``cd && pwd``），拿到的才是这个 shell 真正使用的形式。
        """
        proc = subprocess.run(
            ["bash", "-c", 'cd "%s" && pwd' % install_path.bin_dir()],
            capture_output=True, timeout=25)
        resolved = proc.stdout.decode("utf-8", "replace").strip()
        if resolved:
            return resolved.rstrip("/")
        return install_path._to_posix(install_path.bin_dir()).rstrip("/")

    def _count(self, path_text):
        expected = self._bin_posix
        return [p for p in path_text.split(":") if p.rstrip("/") == expected]

    def test_script_is_idempotent(self):
        """重复 source 不能把 PATH 越加越长。"""
        proc = self._run_bash(
            '. "%s"; . "%s"; . "%s"; echo "$PATH"' %
            (self.script, self.script, self.script))
        entries = self._count(proc.stdout.decode("utf-8", "replace").strip())
        self.assertEqual(len(entries), 1,
                         "重复 source 后 PATH 里有 %d 个 shim：%s"
                         % (len(entries), entries))

    def test_script_self_heals_duplicates(self):
        """PATH 里已有重复条目时应自动压成一个。

        历史版本可能留下多份（旧机制 + 新机制叠加）。只做"已存在就跳过"
        的话重复会永远留着 —— 实测踩过：用户 PATH 里两条同时存在。
        """
        dup = "%s:%s" % (self._bin_posix, self._bin_posix)
        proc = self._run_bash(
            'export PATH="%s:/usr/bin:/bin:%s"; . "%s"; echo "$PATH"'
            % (dup, dup, self.script))
        entries = self._count(proc.stdout.decode("utf-8", "replace").strip())
        self.assertEqual(len(entries), 1,
                         "重复条目未被自愈：%s" % entries)

    def test_script_places_bin_first(self):
        """无论原本有没有重复，最终都应是 PATH 首位。"""
        proc = self._run_bash(
            '. "%s"; echo "$PATH"' % self.script)
        first = proc.stdout.decode("utf-8", "replace").strip().split(":")[0]
        self.assertEqual(first.rstrip("/"), self._bin_posix,
                         "shim 不在 PATH 首位：%s" % first)

    def test_script_prepends_bin(self):
        proc = self._run_bash('. "%s"; which curl' % self.script)
        resolved = proc.stdout.decode("utf-8", "replace").strip()
        expected = os.path.join(self._bin_posix, "curl")
        self.assertEqual(os.path.normcase(resolved).replace("\\", "/"),
                         os.path.normcase(expected).replace("\\", "/"),
                         "source 后 curl 未解析到拦截器：%s" % resolved)


@requires_bash
class TestBashShimFastPath(unittest.TestCase):
    """bin/curl 的快速透传路径：WAF 关闭时不应启动 Python。"""

    def setUp(self):
        self.shim = os.path.join(ROOT, "bin", "curl")
        self.tmp = tempfile.mkdtemp(prefix="agentwaf-shim2-")
        # 隔离规则文件：不读本机 data/rules.json，否则测试结果会跟着
        # 用户当前的总开关状态变（暂停过拦截就挂）。
        from waf import rules as _rules
        self.rules = os.path.join(self.tmp, "rules.json")
        _rules.save_document(_rules.default_document(), self.rules)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _env(self):
        env = dict(os.environ)
        env["AGENTWAF_RULES_FILE"] = self.rules
        env["WAF_NO_LOG"] = "1"
        env.pop("WAF_RULES_FILE", None)
        env.pop("WAF_ALWAYS_ON", None)
        env.pop("WAF_ALWAYS_OFF", None)
        return env

    def test_shim_exists_and_executable(self):
        self.assertTrue(os.path.isfile(self.shim))
        if os.name != "nt":
            self.assertTrue(os.access(self.shim, os.X_OK))

    def test_passthrough_when_off(self):
        """WAF 关闭时应直接透传给真实 curl（连不上端口 = 透传成功）。"""
        env = self._env()
        # 规则文件里 enabled=true，唯一能解释"透传"的就是心跳不存在
        env["WAF_STATE_FILE"] = os.path.join(self.tmp, "nonexistent.json")
        proc = subprocess.run(["bash", self.shim, "-s",
                               "http://127.0.0.1:1/safe?id=1"],
                              capture_output=True, timeout=40, env=env)
        # curl 连不上端口返回 7；若被拦截则是 126
        self.assertNotEqual(proc.returncode, 126,
                            "WAF 关闭时不应拦截")

    def test_block_when_always_on(self):
        env = self._env()
        env["WAF_ALWAYS_ON"] = "1"
        proc = subprocess.run(["bash", self.shim, "-s",
                               "http://127.0.0.1/del/a.txt"],
                              capture_output=True, timeout=60, env=env)
        self.assertEqual(proc.returncode, 126, "WAF 开启时应拦截")
        self.assertIn("命中敏感词", proc.stdout.decode("utf-8", "replace"))


class TestPythonHookModule(unittest.TestCase):
    """autohook 模块：安装、幂等、失败不炸宿主。"""

    def test_module_importable(self):
        import waf.autohook as hook
        self.assertTrue(hasattr(hook, "bootstrap"))
        self.assertTrue(hasattr(hook, "_install"))

    def test_debug_is_silent_by_default(self):
        """默认不能往 stdout/stderr 写字。"""
        proc = subprocess.run(
            [sys.executable, "-c", "import waf.autohook"],
            capture_output=True, timeout=40,
            env=dict(os.environ, PYTHONPATH=ROOT,
                     AGENTWAF_HOOK_DEBUG=""))
        self.assertEqual(proc.stdout.decode("utf-8", "replace").strip(), "")
        self.assertEqual(proc.stderr.decode("utf-8", "replace").strip(), "")

    def test_disabled_by_env(self):
        """AGENTWAF_NO_HOOK=1 应完全跳过。"""
        proc = subprocess.run(
            [sys.executable, "-c",
             "import waf.autohook as h; print(h._state['patched'])"],
            capture_output=True, timeout=40,
            env=dict(os.environ, PYTHONPATH=ROOT, AGENTWAF_NO_HOOK="1"))
        self.assertIn("False", proc.stdout.decode("utf-8", "replace"))

    def test_install_state_shape(self):
        import waf.autohook as hook
        for key in ("patched", "installing", "wrapped", "attempts"):
            self.assertIn(key, hook._state)

    def test_setting_enabled_honors_public_env_var(self):
        """autohook 必须认 AGENTWAF_RULES_FILE —— 和 config.py 同名。

        历史 bug：这里读的是 WAF_RULES_FILE（谁都不认的名字）。用户按文档
        设了 AGENTWAF_RULES_FILE 指向共享规则集时，引擎读新文件、钩子还在
        读 data/rules.json，两边开关状态可以打架（该拦不拦 / 不该拦却拦）。
        """
        import json
        import tempfile
        import shutil
        import waf.autohook as hook

        tmp = tempfile.mkdtemp(prefix="agentwaf-hookrules-")
        saved = os.environ.get("AGENTWAF_RULES_FILE")
        saved_legacy = os.environ.get("WAF_RULES_FILE")
        try:
            target = os.path.join(tmp, "shared-rules.json")
            with open(target, "w", encoding="utf-8") as fh:
                json.dump({"settings": {"enabled": False}, "rules": []}, fh)

            os.environ["AGENTWAF_RULES_FILE"] = target
            os.environ.pop("WAF_RULES_FILE", None)
            self.assertFalse(
                hook._read_setting_enabled(tmp),
                "设了 AGENTWAF_RULES_FILE=enabled:false，钩子仍认为开启")

            with open(target, "w", encoding="utf-8") as fh:
                json.dump({"settings": {"enabled": True}, "rules": []}, fh)
            self.assertTrue(hook._read_setting_enabled(tmp))

            # 旧名字仍兼容（有人脚本里写过），但不能盖过新名字
            os.environ["WAF_RULES_FILE"] = os.path.join(tmp, "nope.json")
            self.assertTrue(hook._read_setting_enabled(tmp),
                            "旧变量名不应覆盖 AGENTWAF_RULES_FILE")
        finally:
            for key, val in (("AGENTWAF_RULES_FILE", saved),
                             ("WAF_RULES_FILE", saved_legacy)):
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val
            shutil.rmtree(tmp, ignore_errors=True)


class TestHookFileContent(unittest.TestCase):
    """Python 钩子必须是**完全自包含**的：文件全在安装目录内。

    历史演变：
      1. `.pth` 直接 `import waf.autohook` —— 会把 `waf` 包名绑死到
         当前安装目录，导致同机另一份拷贝被静默劫持
      2. `.pth` + 引导器（site-packages 里两个文件）—— 修好了包名问题，
         但文件落在系统目录里，删掉项目会留残留
      3. 现在：`<root>/hooks/sitecustomize.py` + 一个 PYTHONPATH 环境变量
         —— 零文件落在安装目录之外
    """

    def test_hook_script_lives_inside_install_dir(self):
        """钩子脚本必须在安装目录内。"""
        script = install_path.hooks_script()
        self.assertTrue(os.path.isfile(script), "缺少 %s" % script)
        inside = os.path.normcase(os.path.abspath(script)).startswith(
            os.path.normcase(os.path.abspath(install_path.config.ROOT)))
        self.assertTrue(inside,
                        "钩子脚本必须在安装目录内：%s" % script)

    def test_hook_script_is_valid_python(self):
        script = install_path.hooks_script()
        with open(script, "r", encoding="utf-8") as fh:
            source = fh.read()
        compile(source, script, "exec")          # 语法错误会直接抛出

    def test_hook_does_not_import_waf_by_name(self):
        """钩子不能直接 `import waf` —— 会绑死安装目录（历史 bug）。

        用 AST 检查真实 import 语句，而不是匹配文本：文档里说明
        "不 import waf 包名"这种注释会误报。
        """
        import ast as _ast
        script = install_path.hooks_script()
        with open(script, "r", encoding="utf-8") as fh:
            tree = _ast.parse(fh.read(), script)
        offenders = []
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for alias in node.names:
                    if alias.name == "waf" or alias.name.startswith("waf."):
                        offenders.append("import %s" % alias.name)
            elif isinstance(node, _ast.ImportFrom):
                module = node.module or ""
                if module == "waf" or module.startswith("waf."):
                    offenders.append("from %s import ..." % module)
        self.assertEqual(offenders, [],
                         "钩子不能直接 import waf 包名：%s" % offenders)

    def test_hook_chains_other_sitecustomize(self):
        """必须链式执行别人的 sitecustomize，不能吃掉它。"""
        script = install_path.hooks_script()
        with open(script, "r", encoding="utf-8") as fh:
            source = fh.read()
        self.assertIn("sitecustomize", source)
        self.assertTrue("_chain" in source or "other_sitecustomize" in source,
                        "缺少与其它 sitecustomize 共存的逻辑")

    def test_no_files_left_in_system_site_packages(self):
        """系统 site-packages 里不能有我们的文件（自包含要求）。"""
        site_dir = install_path.python_user_site()
        if not site_dir:
            self.skipTest("找不到用户级 site-packages")
        leftovers = []
        for name in install_path.LEGACY_HOOK_FILES:
            path = os.path.join(site_dir, name)
            if os.path.isfile(path):
                leftovers.append(name)
        self.assertEqual(leftovers, [],
                         "系统目录残留旧版文件：%s" % leftovers)

    def test_cleanup_removes_legacy_files(self):
        """遗留文件应被自动清理。"""
        site_dir = install_path.python_user_site()
        if not site_dir:
            self.skipTest("找不到用户级 site-packages")
        os.makedirs(site_dir, exist_ok=True)
        name = install_path.LEGACY_HOOK_FILES[0]
        fake = os.path.join(site_dir, name)
        with open(fake, "w", encoding="utf-8") as fh:
            fh.write("# leftover\n")
        try:
            removed = install_path._cleanup_legacy_hook_files()
            self.assertIn(name, removed)
            self.assertFalse(os.path.isfile(fake))
        finally:
            if os.path.isfile(fake):
                os.remove(fake)

    def test_hook_effective_probe(self):
        """真实起进程验证钩子加载（装了才测）。"""
        if not install_path.has_python_hook():
            self.skipTest("未安装 Python 钩子")
        self.assertTrue(install_path.python_hook_effective(),
                        "钩子装了但新进程里没被加载")


class TestSourceScopeRegression(unittest.TestCase):
    """回归：字段范围默认全开（防止老 users 的规则被限定死）。"""

    def test_status_reports_all_channels(self):
        st = install_path.status()
        for key in ("cmd_autorun", "bash_env", "python_hook",
                    "powershell_profile", "resolved", "shim_wins"):
            self.assertIn(key, st, "status 缺少字段 %s" % key)


class TestLaunchersExist(unittest.TestCase):
    """文档里教用户敲的每个命令，磁盘上都必须真的有。

    历史 bug：README / DESIGN / install.bat 十处教用户用
    ``waf-run python exp.py``，但 ``bin/waf-run`` 根本不存在 —— 用户照着
    文档敲只会得到 "command not found"。这类"文档承诺但文件缺失"的问题
    在开发机上永远发现不了（开发机 PATH 里可能有别处的同名脚本），
    必须有测试盯着。
    """

    def test_documented_entry_points_exist(self):
        root = os.path.dirname(HERE)
        expected = [
            "wafctl", "wafctl.cmd",             # 命令行入口
            "start.bat", "stop.bat", "install.bat",
            "start-proxy.bat",
            "bin/curl", "bin/curl.cmd",         # curl 拦截器
            "bin/waf-run", "bin/waf-run.cmd",   # 带护栏跑任意命令
            "bin/waf-bash-env.sh", "bin/waf.ps1",
            "scripts/install_shim.sh",
        ]
        missing = [p for p in expected
                   if not os.path.isfile(os.path.join(root, p))]
        self.assertEqual(missing, [],
                         "文档里提到但文件不存在：%s" % missing)

    def test_shell_entry_points_are_executable(self):
        """非 Windows 上必须能直接执行（Git 要记住 100755）。"""
        if os.name == "nt":
            self.skipTest("Windows 不看 exec 位")
        root = os.path.dirname(HERE)
        for rel in ("bin/curl", "bin/waf-run", "bin/waf-bash-env.sh",
                    "wafctl", "scripts/install_shim.sh"):
            path = os.path.join(root, rel)
            self.assertTrue(os.access(path, os.X_OK),
                            "%s 没有可执行位（Linux/Mac 上跑不了）" % rel)

    def test_waf_run_injects_guard(self):
        """waf-run 必须真的给子 Python 进程装上护栏。"""
        import tempfile
        import shutil as _shutil
        from waf import rules as _rules

        tmp = tempfile.mkdtemp(prefix="agentwaf-run-")
        try:
            script = os.path.join(tmp, "exp.py")
            with open(script, "w", encoding="utf-8") as fh:
                fh.write(
                    "import urllib.request\n"
                    "try:\n"
                    "    urllib.request.urlopen("
                    "'http://127.0.0.1/delete.php', timeout=2)\n"
                    "    print('NOT_BLOCKED')\n"
                    "except Exception as exc:\n"
                    "    print('BLOCKED' if 'WafBlocked' in type(exc).__name__\n"
                    "          else 'OTHER:' + type(exc).__name__)\n"
                )
            rp = os.path.join(tmp, "rules.json")
            _rules.save_document(_rules.default_document(), rp)

            env = dict(os.environ)
            env["AGENTWAF_RULES_FILE"] = rp
            env["WAF_ALWAYS_ON"] = "1"
            env["WAF_NO_LOG"] = "1"
            env.pop("WAF_RULES_FILE", None)

            runner = os.path.join(os.path.dirname(HERE), "waf", "runner.py")
            proc = subprocess.run([sys.executable, runner, sys.executable, script],
                                  capture_output=True, env=env, timeout=60)
            out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
            self.assertIn("BLOCKED", out,
                          "waf-run 没拦住子进程的请求：%s" % out[-400:])
        finally:
            _shutil.rmtree(tmp, ignore_errors=True)

    @requires_bash
    def test_waf_run_launcher_script_paths(self):
        """启动脚本本身必须能跑通 —— 它算错目录就等于功能不存在。

        历史 bug：bin/waf-run 用 ``dirname(__file__)`` 当安装根目录，
        但脚本在 <root>/bin/ 下，于是去找 <root>/bin/waf/runner.py ——
        路径不存在，启动器直接失效，而 runner.py 本身是好的。
        上面那个测试直接调 runner.py，绕过了启动器，所以抓不到这类 bug
        （实测漏过一次）。这里必须经启动器调。
        """
        import shutil as _shutil
        import tempfile
        from waf import rules as _rules

        root = os.path.dirname(HERE)
        tmp = tempfile.mkdtemp(prefix="agentwaf-launch-")
        try:
            rp = os.path.join(tmp, "rules.json")
            _rules.save_document(_rules.default_document(), rp)

            env = dict(os.environ)
            env["AGENTWAF_RULES_FILE"] = rp
            env["WAF_ALWAYS_ON"] = "1"
            env["WAF_NO_LOG"] = "1"
            env.pop("WAF_RULES_FILE", None)
            env.pop("BASH_ENV", None)

            launcher = os.path.join(root, "bin", "waf-run")
            if not os.path.isfile(launcher):
                self.skipTest("bin/waf-run 不存在")

            # 用 python 打印自己的路径，验证启动器把参数正确转给了 runner
            proc = subprocess.run(
                ["bash", launcher, sys.executable, "-c",
                 "print('LAUNCHER_OK')"],
                capture_output=True, env=env, timeout=90, cwd=tmp)
            out = (proc.stdout + proc.stderr).decode("utf-8", "replace")
            self.assertIn("LAUNCHER_OK", out,
                          "启动器没能跑起来：%s" % out[-400:])
            self.assertNotIn("can't open file", out,
                             "启动器算错了脚本路径：%s" % out[-400:])
        finally:
            _shutil.rmtree(tmp, ignore_errors=True)


@requires_bash
class TestLinuxBashEnvChannel(unittest.TestCase):
    """Linux/WSL/macOS：必须靠 BASH_ENV 覆盖非交互 bash。

    非交互 bash（``bash -c "..."``，AI 工具执行命令的方式）**不读**
    ~/.bashrc。只写 .bashrc 的话，Linux 用户的 AI 会话完全不拦截 ——
    而 Windows 侧早就用 BASH_ENV 修好了，两边不能一个有一个没有。
    """

    def test_install_shim_exports_bash_env(self):
        root = os.path.dirname(HERE)
        script = os.path.join(root, "scripts", "install_shim.sh")
        with open(script, encoding="utf-8") as fh:
            content = fh.read()
        self.assertIn("BASH_ENV", content,
                      "install_shim.sh 没有设置 BASH_ENV —— "
                      "非交互 bash 通道在 Linux 上是断的")

    def test_noninteractive_bash_resolves_shim(self):
        """起一个非交互 bash，确认 curl 解析到 bin/curl。"""
        if os.name == "nt":
            self.skipTest("Git Bash 的 BASH_ENV 由注册表负责，另有测试")
        root = os.path.dirname(HERE)
        hook = os.path.join(root, "bin", "waf-bash-env.sh")
        env = dict(os.environ)
        env["BASH_ENV"] = hook
        proc = subprocess.run(["bash", "-c", "command -v curl"],
                              capture_output=True, env=env, timeout=30)
        resolved = proc.stdout.decode("utf-8", "replace").strip()
        self.assertTrue(resolved.endswith("bin/curl"),
                        "非交互 bash 没解析到拦截器：%r" % resolved)



class TestMultiCopyCleanup(unittest.TestCase):
    """同一套件被解压两份（或挪了文件夹）时，旧副本的残留必须清理干净。

    这是"下载者解压两次"会踩的真实坑：
      * AutoRun 里两条 PATH 前置语句叠加 —— 旧副本排在前面，先命中，
        新装的那份完全不生效；卸载时也清不掉
      * PYTHONPATH 里两个 hooks —— 旧副本的钩子先被加载，你在新副本里
        改规则/开关，实际生效的是旧副本
      * ~/.bashrc 里两行 export PATH —— 同上

    清理必须同时满足：旧副本（可能已被删除）要清掉，用户自己的
    PATH / hooks 目录一个都不能动。
    """

    def test_autorun_paired_chunks_removed(self):
        """成对写入的 AGENT_WAF_HOME + PATH 片段要一起删掉。

        标记只在第一个片段上，只按标记过滤会留下 PATH 那句 ——
        实测踩过，所以成对识别。
        """
        from waf import install_path as ip

        old_home = 'set "AGENT_WAF_HOME=D:\old-copy"'
        old_path = 'set "PATH=D:\old-copy\bin;%PATH%"'
        new_home = 'set "AGENT_WAF_HOME=%s"' % ip.config.ROOT
        new_path = 'set "PATH=%s;%%PATH%%"' % ip.bin_dir()
        value = " & ".join([old_home, old_path, new_home, new_path])

        out = ip._strip_our_autorun(value)
        self.assertEqual(out, "",
                         "旧副本残留没被清干净：%r" % out)

    def test_autorun_keeps_user_chunks(self):
        """用户自己的 PATH 设置不能被误删。"""
        from waf import install_path as ip

        user = 'set "PATH=D:\mytool;%PATH%"'
        ours = ('set "AGENT_WAF_HOME=D:\old" & '
                'set "PATH=D:\old\bin;%PATH%"')
        out = ip._strip_our_autorun(user + " & " + ours)
        self.assertIn("mytool", out, "误删了用户的 PATH：%r" % out)
        self.assertNotIn("AGENT_WAF_HOME", out, "残留未清：%r" % out)

    def test_pythonpath_removes_stale_copies(self):
        """旧副本的 hooks 要清掉，用户自己的 hooks 要保留。"""
        import tempfile
        import shutil
        from waf import install_path as ip

        tmp = tempfile.mkdtemp(prefix="agentwaf-multi-")
        try:
            # 一个"旧副本"（模拟：目录还在）
            oldroot = os.path.join(tmp, "old-copy")
            os.makedirs(os.path.join(oldroot, "hooks"))
            os.makedirs(os.path.join(oldroot, "waf"))
            with open(os.path.join(oldroot, "hooks", "sitecustomize.py"),
                      "w", encoding="utf-8") as fh:
                fh.write("# agent-waf hook\n")

            # 用户自己的、恰好也叫 hooks 的项目目录
            userhooks = os.path.join(tmp, "myproj", "hooks")
            os.makedirs(userhooks)

            value = os.pathsep.join([
                os.path.join(oldroot, "hooks"),
                ip.hooks_dir(),
                userhooks,
            ])
            out = ip._strip_our_pythonpath(value)
            self.assertNotIn("old-copy", out,
                             "旧副本 hooks 没清掉：%r" % out)
            self.assertIn(userhooks, out,
                          "误删了用户自己的 hooks：%r" % out)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_bashrc_line_is_replaced_not_appended(self):
        """~/.bashrc 里的那行要替换，不能每次安装都追加一行。

        追加的话旧副本那行还在，而 Git Bash 取第一个命中的 —— 于是走的是
        旧副本。这里调用真实的 write_bashrc_pointer（只碰文件），
        **不**调用 install_bash_env —— 后者会写注册表 BASH_ENV，
        把开发机真实的指针指到临时目录（实测污染过一次）。
        """
        import shutil
        import tempfile
        from waf import install_path as ip

        tmp = tempfile.mkdtemp(prefix="agentwaf-bashrc-")
        saved_home = os.environ.get("HOME")
        saved_userprofile = os.environ.get("USERPROFILE")
        try:
            # user_bashrc_path() 基于 ~，两套变量都指向临时目录
            os.environ["HOME"] = tmp
            os.environ["USERPROFILE"] = tmp
            bashrc = ip.user_bashrc_path()
            folder = os.path.dirname(bashrc)
            if folder and not os.path.isdir(folder):
                os.makedirs(folder)

            # 预置：用户自己的内容 + 一个"旧副本"留下的行
            old_line = ('export PATH="/d/old-copy/bin:$PATH"  %s'
                        % ip.BASHRC_MARK)
            with open(bashrc, "w", encoding="utf-8") as fh:
                fh.write("# my own stuff\n")
                fh.write(old_line + "\n")

            ok, _msg = ip.write_bashrc_pointer()
            self.assertTrue(ok)

            final = open(bashrc, encoding="utf-8", errors="replace").read()
            marked = [ln for ln in final.splitlines()
                      if ip.BASHRC_MARK in ln]
            self.assertEqual(len(marked), 1,
                             "~/.bashrc 里有多行拦截器配置：%s" % marked)
            self.assertNotIn("old-copy", final,
                             "旧副本那行没被替换掉：%s" % final)
            self.assertIn("my own stuff", final,
                          "误删了用户自己的内容：%s" % final)
        finally:
            for key, val in (("HOME", saved_home),
                             ("USERPROFILE", saved_userprofile)):
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val
            shutil.rmtree(tmp, ignore_errors=True)



if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestReleaseScript(unittest.TestCase):
    """回归：发布打包脚本必须真的排除 data/。

    data/ 里有 ca.key（明文私钥）、含私钥的 agent-waf-ca.pem、
    events.db + -wal（完整拦截记录）。README 主推 "Download ZIP"，
    一旦打包带上这些就等于把私钥和日志发给所有人。

    踩过的坑（实测读代码发现，本机无 zip 命令所以从未跑到）：
    Info-ZIP 的 `zip -r out.zip .` 存出的条目名**不带 "./" 前缀**
    （是 `data/run/x`），而排除模式写的是 `./data` —— 匹配不上任何
    条目，data/ 会整包进 zip。自检能兜住（fail-closed），
    但结果是"有 zip 的环境发布必然失败"。
    现在 python 是主路径，zip 只作兜底且模式改成 `data/*`。
    """

    def _script(self):
        path = os.path.join(os.path.dirname(HERE), "scripts",
                            "make-release.sh")
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def test_excludes_data(self):
        content = self._script()
        self.assertIn("data", content, "脚本没有排除 data/")

    def test_zip_patterns_have_no_dot_slash(self):
        """发给 zip -x 的模式不能带 "./" 前缀（否则匹配不上条目名）。"""
        content = self._script()
        # 抓 EXCLUDES_ZIP 数组块
        start = content.find("EXCLUDES_ZIP=(")
        self.assertGreater(start, -1, "找不到 EXCLUDES_ZIP 定义")
        end = content.find(")", start)
        block = content[start:end]
        bad = [ln.strip() for ln in block.split("\n")
               if ln.strip().startswith('"./')]
        self.assertEqual(bad, [],
                         "zip 排除模式带了 ./ 前缀，匹配不上条目名：%s" % bad)

    def test_python_zipfile_is_primary(self):
        """主路径应是 python 的 zipfile（无模式歧义），zip 只作兜底。"""
        content = self._script()
        py_pos = content.find("pack_with_python")
        zip_pos = content.find("pack_with_zip")
        self.assertGreater(py_pos, -1, "没有 python 打包路径")
        self.assertGreater(zip_pos, -1, "没有 zip 兜底路径")
        # 调用顺序：python 先于 zip
        call_py = content.find('pack_with_python "$PY_BIN"')
        call_zip = content.find("pack_with_zip\n")
        if call_zip < 0:
            call_zip = content.find("pack_with_zip$")
        self.assertLess(call_py, call_zip if call_zip > 0 else len(content),
                        "python 应当是主路径")

    def test_selfcheck_covers_private_key_and_db(self):
        """自检必须覆盖私钥与事件库（最后一道闸）。"""
        content = self._script()
        for needle in ("ca.key", ".pem", "events.db"):
            self.assertIn(needle, content,
                          "自检没覆盖 %s" % needle)

    def test_selfcheck_aborts_on_sensitive(self):
        """自检发现敏感文件必须 exit 1（不能只打印警告）。"""
        content = self._script()
        for marker in ("zip 里混进了敏感文件", "tar.gz 里混进了敏感文件"):
            idx = content.find(marker)
            self.assertGreater(idx, -1, "找不到自检失败分支：%s" % marker)
            tail = content[idx:idx + 300]
            self.assertIn("exit 1", tail,
                          "自检发现敏感文件后没有中止打包：%s" % marker)
