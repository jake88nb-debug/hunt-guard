# -*- coding: utf-8 -*-
r"""正则安全检查：拦住会导致灾难性回溯（ReDoS）的规则。

为什么需要
----------
规则可以由用户/AI 添加（UI 里能填正则），而 Python 的 re **没有超时机制**。
一条病态正则配上几十个字符就能让匹配耗时指数级增长 —— 每个请求都会
卡死在 engine.scan 里，整个拦截器形同瘫痪。
本机实测：`(a+)+$` 对 27 个字符的输入耗时 4.9 秒；`(a{1,10})+$` 同样
能挂住进程，更极端的直接不返回。

为什么用子进程探测
------------------
"跑一次并计时"必须在**子进程**里做：正则一旦进入灾难性回溯，
就再也不会回到 Python 字节码层 —— signal.alarm / 线程超时 / 事件循环
对纯 C 实现的 re 全都没用。本机实测：主线程直接卡死，连 Ctrl+C 都进不去。
所以探测起子进程，超时直接 kill。

为什么不做静态分析（粗筛）
--------------------------
一开始我在子进程前加了一层"粗筛"，用字符串特征判断"这条正则可能危险吗"，
只把可疑的送进子进程，为的是省掉 149 条规则起 149 个解释器的开销。
结果**反复漏检**——粗筛要枚举"危险形状"，而危险形状是无穷的：

  (a+)+$          组内量词 + 组量词        → 粗筛认
  (a{1,10})+$     组内 {n,m} + 组量词      → 粗筛漏（我只认了 *+?）
  a{10,20}a{10,20}$  相邻有界量词          → 粗筛漏
  ([a-z]+@)+$     组内含 @ 才能触发        → 粗筛认，但采样输入没 @ → 漏
  (,|;)+$         同上                     → 漏
  (\d+[-.])+$     同上                     → 漏

每补一个形状就漏下一个。这种"黑名单式"防护和规则引擎本身一样
是穷举对抗，注定漏。

现在的做法（批量探测，无粗筛）
------------------------------
  * 把所有候选正则**一次性**丢给一个子进程，逐条探测并汇报
  * 全部安全 → 一次解释器启动就够（常见情况：149 条约 0.3s）
  * 某个正则卡住 → 整个子进程超时，再**逐条**重跑定位到具体哪条，
    只对卡住的那条判危险

这样既没有漏检（每条都真跑），又不用为安全的正则各起一个进程。

采样输入
--------
必须是"接近匹配但最终失败"的形态 —— CPython 的 re 只在整体匹配
必然失败时才走满回溯（实测：`(a*)*` 对纯 "aaaa" 是 0.0000s，
加个终止符才暴露）。同时要覆盖各类触发字符（字母/数字/空格/
`@ , ; - .` 等标点），否则像 `([a-z]+@)+$` 这种"需要 @ 才爆炸"
的正则永远测不出来（踩过）。
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import threading

# 单条正则的探测预算（秒）。
#
# 取值依据（实测）：安全的规则在 30 字符采样上是**微秒级**；
# 真正的灾难性回溯是秒级起步。所以 0.05s 是很宽的阈值 —— 既不会误伤
# 正常规则（差三个数量级），又能抓住"每请求耗几秒"的病态正则。
#
# 踩过的坑：一开始设 3.0s，结果 (x+x+)+y 实测 2.34s 被当成"安全"放过了 ——
# 而 2.34s/请求 在真实扫描（256KB 字段）上就是彻底不可用。
PROBE_BUDGET_SEC = 0.05

# 正则长度上限：超过直接判危险（不探测）。
# 理由见 probe_patterns 里的说明 —— 4000+ 字符的正常规则不存在，
# 而超长正则无法在有限探测里确认安全。
MAX_PATTERN_LEN = 4000

# 整体子进程超时（含解释器启动）。超过说明有正则真的挂住了。
SUBPROCESS_TIMEOUT_SEC = 3.0

# 采样输入：都是"接近匹配但最终失败"的形态。
# 覆盖：纯重复 / 交替 / 数字 / 空格 / 各类标点 / 带终止符。
_SAMPLES = (
    "a" * 30 + "!",
    "a" * 26 + "!",
    "a" * 30,
    "1" * 30 + "!",
    ("ab" * 16) + "!",
    " " * 30 + "!",
    "x" * 26,
    "a" * 24 + ".",
    ("a" * 14 + "!") * 2,
    "abcabcabcabcabcabcabcabcabcabcz",
    # 标点类触发字符 —— 缺了它们会漏掉 ([a-z]+@)+$ / (,|;)+$ / (\d+[-.])+$
    "a" * 20 + "@",
    ("a@" * 15) + "!",
    "," * 30 + "!",
    (";," * 15) + "!",
    "1" * 20 + ".",
    ("1." * 15) + "!",
    ("1-" * 15) + "!",
    "." * 30 + "!",
    "-" * 30 + "!",
    "_" * 30 + "!",
    ":" * 30 + "!",
    "/" * 30 + "!",
    "a" * 10 + "=" + "a" * 10 + "!",
    "a&a&a&a&a&a&a&a&a&a&a&a&a&a&a!",
    "a" * 12 + "%" + "a" * 12 + "!",
    # ---- 固定次数嵌套：`(.*a){20}` / `([a-z]*a){15}` 这类 ----
    #
    # 这类正则只在"目标字符数**刚好不足**要求次数"时才走满回溯 ——
    # 数量够了就匹配成功、直接返回。所以采样要覆盖"正好差一点"的
    # 多种长度；光给长的（如 'a'*30）反而测不出来。
    # 实测发现这个形态此前完全没覆盖，实测能挂住进程。
    "a" * 19 + "!",
    "a" * 17 + "!",
    "a" * 25 + "!",
    "ab" * 9 + "!",
    "a" * 14 + "b",
    # 较长的纯重复串（无终止符）。覆盖"需要较多重复才失败"的形态。
    #
    # 实测结论（写下来免得后人重复踩）：`(.*a){20}` / `([a-z]*a){15}`
    # 这类**固定次数**嵌套在 CPython 上并不随输入增长
    # （'a'×50 到 ×800 都是 0.015–0.03s 的常数开销）—— 它们不是
    # ReDoS，不判危险是正确的。真正危险的是外层**无上限**的形态
    # （(a+)+$、(.*a){20}$ 这类带锚点的），那些已由前面的采样覆盖。
    # 保留长串是因为对无上限嵌套有实际触发作用。
    "a" * 55,
    "a" * 40,
    "ab" * 22,
)

# 子进程侧执行的探测脚本。
# 入参：patterns（JSON 数组）、samples（JSON 数组）、budget（秒）
# 出参：每行一个 JSON {"i": 序号, "safe": bool, "worst": 秒, "err": str}
_PROBE_SRC = r'''
import json, re, sys, time
patterns = json.loads(sys.argv[1])
samples = json.loads(sys.argv[2])
budget = float(sys.argv[3])
for index, pattern in enumerate(patterns):
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except Exception:
        # 语法错误不算危险（交给 compile 报错）
        print(json.dumps({"i": index, "safe": True, "worst": 0.0}))
        sys.stdout.flush()
        continue
    worst = 0.0
    crashed = ""
    for sample in samples:
        t0 = time.monotonic()
        try:
            for _ in regex.finditer(sample):
                pass
        except (RecursionError, OverflowError, MemoryError) as exc:
            crashed = type(exc).__name__
            break
        elapsed = time.monotonic() - t0
        if elapsed > worst:
            worst = elapsed
        if elapsed > budget:
            break          # 单个样本已超预算，够判定了（后续样本只会更慢）
    print(json.dumps({"i": index, "safe": not crashed and worst <= budget,
                      "worst": worst, "err": crashed}))
    sys.stdout.flush()
'''

_cache = {}
_cache_lock = threading.Lock()
_disk_loaded = False

# 磁盘缓存的版本号：改了采样集或判定逻辑必须 +1，
# 否则旧结论会被一直复用（比如以前漏检的正则仍被当成安全）。
_CACHE_VERSION = 4


def _cache_path():
    """磁盘缓存文件路径。

    为什么要磁盘缓存：探测要起子进程（单条约 0.3s，156 条约 0.27s
    批量）。而 curl shim / 代理 / guard 每次启动都是一个**新进程** ——
    没有磁盘缓存的话每次调用都要重探一遍（实测把单次 curl 从 2s 拖到
    54s，加回缓存后回到 2.9s）。内置规则内容是稳定的，结论可以长期复用。
    """
    # 缓存必须落在安装目录内（"完全自包含"的承诺）。
    # 早先在 config 导入失败时 fallback 到 ~/.huntguard，
    # 那会在用户主目录建目录 —— 违反自包含。现在失败就返回 None，
    # 调用方跳过磁盘缓存（只是慢一点，不会留文件在外面）。
    try:
        from . import config
        base = config.DATA_DIR
    except Exception:
        return None
    arm = hashlib.sha256(
        ("|".join(_SAMPLES) + "|v%d" % _CACHE_VERSION).encode("utf-8")
    ).hexdigest()[:12]
    return os.path.join(base, "regex_safety_%s.json" % arm)


def _load_disk_cache():
    global _disk_loaded
    if _disk_loaded:
        return
    _disk_loaded = True
    import json as _json
    import os as _os
    path = _cache_path()
    if not path:
        return
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = _json.load(fh)
        if isinstance(data, dict):
            with _cache_lock:
                for key, reason in data.items():
                    # 键是 pattern（budget 固定用默认值）
                    _cache.setdefault((key, PROBE_BUDGET_SEC),
                                      reason if reason else "")
    except (OSError, ValueError):
        pass


def _save_disk_cache():
    import json as _json
    import os as _os
    path = _cache_path()
    if not path:
        return
    try:
        folder = _os.path.dirname(path)
        if folder:
            _os.makedirs(folder, exist_ok=True)
        with _cache_lock:
            data = {key[0]: value for key, value in _cache.items()
                    if isinstance(key, tuple) and len(key) == 2}
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            _json.dump(data, fh, ensure_ascii=False)
        _os.replace(tmp, path)
    except OSError:
        pass


def _run_probe(patterns, timeout, budget):
    """跑一次子进程探测。返回 (结果列表, 是否整体超时)。

    结果列表按输入顺序给出 {safe, worst, err}；整体超时返回 (None, True)。
    """
    cmd = [sys.executable, "-c", _PROBE_SRC,
           json.dumps(list(patterns)), json.dumps(list(_SAMPLES)),
           json.dumps(budget)]
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    # 告诉子进程"你是我自己人，别装护栏"。
    #
    # argv 里带着正在被探测的正则文本（含 `drop table` / `truncate`
    # 这类样本词），guard 的 _needs_cmd_scan 会认定它是破坏性命令，
    # 于是子进程里的钩子反过来去扫自己 → 又要起探测子进程 →
    # 无限递归（冷缓存时 stderr 刷满 engine_error，已实测复现）。
    env = dict(os.environ)
    env["WAF_INTERNAL_PROC"] = "1"
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout,
                              creationflags=creationflags, env=env)
    except subprocess.TimeoutExpired:
        return None, True
    except (OSError, subprocess.SubprocessError):
        return None, False            # 探测不可用 → 调用方保守放行

    results = {}
    out = (proc.stdout or b"").decode("utf-8", "replace")
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except ValueError:
            continue
        results[data.get("i")] = data
    return results, False


def probe_patterns(patterns, timeout=SUBPROCESS_TIMEOUT_SEC,
                   budget=PROBE_BUDGET_SEC):
    """批量探测。返回 {pattern: 危险原因}（安全的 pattern 不在结果里）。

    注意两个时间参数是**不同**的东西（踩过）：
      ``budget``  —— 单条正则的匹配预算（0.05s）
      ``timeout`` —— 子进程整体超时（3.0s，含解释器启动约 0.3s）
    一开始把两者设成同一个值，于是每个子进程都在 0.05s"超时"，
    于是**所有**正则（包括明显安全的）都被判危险。

    策略：
      1. 全部丢给一个子进程跑。全部安全就到此为止（一次解释器启动）。
      2. 整体超时 → 逐条重跑，定位到卡住的那条，只把它判危险。
         逐条也超时的那条就是病态正则；其余照常。
    """
    bad = {}
    todo = []
    seen = set()
    for pattern in patterns:
        if not pattern or not isinstance(pattern, str) or pattern in seen:
            continue
        if len(pattern) > MAX_PATTERN_LEN:
            # 超长正则**直接判危险**（fail-closed）。
            #
            # 踩过：这里早先是 `continue`（跳过探测），于是
            # unsafe.get() 返回 None → 调用方视为"安全"并编译使用 ——
            # 一条 4001 字符的病态正则可以绕过整个 ReDoS 防护
            # （实测发现：从 fail-closed 退化成 fail-open）。
            #
            # 为什么长正则本身就危险：探测要在有限时间内跑完，超长
            # 正则看不清内部结构；而且正常规则不需要 4000+ 字符
            # （内置最长的是 R-314 的密码重置正则，约 120 字符）。
            bad[pattern] = ("正则过长（%d 字符 > %d），无法确认安全性，"
                            "请拆成多条规则" % (len(pattern), MAX_PATTERN_LEN))
            continue
        try:
            re.compile(pattern)
        except (re.error, RecursionError, ValueError, OverflowError):
            continue                  # 语法错误由调用方处理
        seen.add(pattern)
        todo.append(pattern)

    if not todo:
        return bad

    results, timed_out = _run_probe(todo, timeout, budget)

    if timed_out:
        # 有正则卡住了。逐条定位（只在这一步付多次启动的代价）
        for pattern in todo:
            single, one_timeout = _run_probe([pattern], timeout, budget)
            if one_timeout:
                bad[pattern] = ("匹配超时（超过 %.1fs 仍未返回）—— "
                                "疑似灾难性回溯，会让每个请求卡死" % timeout)
                continue
            if not single:
                continue              # 探测不可用 → 保守放行
            info = single.get(0) or {}
            if not info.get("safe", True):
                bad[pattern] = _reason(info)
        return bad

    if not results:
        return {}                     # 探测不可用 → 保守放行
    for index, pattern in enumerate(todo):
        info = results.get(index) or {}
        if not info.get("safe", True):
            bad[pattern] = _reason(info)
    return bad


def _reason(info):
    err = info.get("err") or ""
    worst = info.get("worst") or 0.0
    if err:
        # 子进程只在"匹配时崩溃"（RecursionError / OverflowError /
        # MemoryError）时才产出 err —— 那本身就是危险信号。
        # （早先还比过一个 err != "匹配耗时超预算" 的分支，
        #  但子进程从不产出那个字符串，是死代码；已删。）
        return "匹配时异常（%s）—— 疑似灾难性回溯" % err
    return ("匹配耗时 %.2fs，超过安全预算 —— 疑似灾难性回溯，"
            "会让每个请求卡死" % worst)


def check_pattern(pattern, budget=PROBE_BUDGET_SEC):
    """单条检查（兼容旧调用）。安全返回 ""，危险返回原因。"""
    if not pattern or not isinstance(pattern, str):
        return ""
    _load_disk_cache()
    key = (pattern, budget)
    with _cache_lock:
        if key in _cache:
            return _cache[key]
    bad = probe_patterns([pattern], budget=budget)
    result = bad.get(pattern, "")
    with _cache_lock:
        _cache[key] = result
    _save_disk_cache()
    return result


def check_patterns(patterns, budget=PROBE_BUDGET_SEC):
    """批量检查。返回 {pattern: 原因}（安全的 pattern 不在结果里）。"""
    if not patterns:
        return {}
    _load_disk_cache()
    missing = []
    with _cache_lock:
        for pattern in patterns:
            if (pattern, budget) not in _cache:
                missing.append(pattern)
    if missing:
        bad = probe_patterns(missing, budget=budget)
        with _cache_lock:
            for pattern in missing:
                _cache[(pattern, budget)] = bad.get(pattern, "")
        _save_disk_cache()
    out = {}
    with _cache_lock:
        for pattern in patterns:
            reason = _cache.get((pattern, budget), "")
            if reason:
                out[pattern] = reason
    return out


def check_rule_regexes(rule, budget=PROBE_BUDGET_SEC):
    """检查一条规则里的所有正则（含 exclude），返回 [(pattern, reason)]。

    exclude 也必须查：它在**每个命中点**上跑，病态 exclude 一样卡死。
    """
    patterns = list(rule.get("regex") or []) + list(rule.get("exclude") or [])
    bad = check_patterns(patterns, budget=budget)
    return [(p, bad[p]) for p in patterns if p in bad]


def clear_cache(include_disk=False):
    """清内存缓存。``include_disk=True`` 时连磁盘缓存一起清掉。

    测试用：默认只清内存，这样跑测试不用每次重探（0.27s×N）。
    真正需要重探（改了采样集/判定逻辑）时把 _CACHE_VERSION +1 即可。
    """
    global _disk_loaded
    with _cache_lock:
        _cache.clear()
    if include_disk:
        _disk_loaded = False
        import os as _os
        try:
            _os.remove(_cache_path())
        except OSError:
            pass
