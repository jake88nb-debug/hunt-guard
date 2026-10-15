# -*- coding: utf-8 -*-
"""归一化管线：把各种混淆写法还原成可比对的标准形式。

目标：`DELETE` / `%64elete` / `de%6ce te` / `de/**/lete` / `d_e-l.e t e`
       / `delete\u0000` / `ｄｅｌｅｔｅ`(全角) 都能命中关键词 `delete`。
"""

import html
import re
import unicodedata
from urllib.parse import unquote_plus, unquote

# 会干扰关键词连续性的分隔/噪声字符
SEPARATORS = r"[\s_\-\.\,;:/\|\\\*\+\~\^`'\"\(\)\[\]\{\}<>@!\?#=&%$]"
SEP_RE = re.compile(SEPARATORS)
SQL_COMMENT_RE = re.compile(r"/\*.*?\*/", re.S)
SQL_INLINE_COMMENT_RE = re.compile(r"(?:--|#)[^\n]*")
ZERO_WIDTH = "".join([
    "\u200b", "\u200c", "\u200d", "\u2060", "\ufeff", "\u00ad",
    "\u180e", "\u2028", "\u2029",
])
INVISIBLE_RE = re.compile(u"[%s]" % ZERO_WIDTH)
WS_RE = re.compile(r"\s+")
URL_TOKEN_RE = re.compile(r"%[0-9a-fA-F]{2}")
HTML_ENTITY_RE = re.compile(r"&(#\d{2,7}|#x[0-9a-fA-F]{2,6}|[a-zA-Z]{2,10});")
UNICODE_ESC_RE = re.compile(r"\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\U([0-9a-fA-F]{8})")
FULLWIDTH_RE = re.compile(u"[\uff01-\uff5e]")
CJK_CONFUSABLE = {
    u"　": " ",   # 全角空格
    u"／": "/",
    u"．": ".",
    u"＿": "_",
    u"－": "-",
}


def url_decode_deep(text, rounds=3):
    """反复 URL 解码，直到不再变化（防双重编码）。"""
    current = text
    for _ in range(rounds):
        try:
            nxt = unquote_plus(current)
        except Exception:
            break
        if nxt == current:
            try:
                nxt2 = unquote(current)
            except Exception:
                break
            if nxt2 == current:
                break
            nxt = nxt2
        current = nxt
    return current


def html_unescape_deep(text, rounds=2):
    current = text
    for _ in range(rounds):
        try:
            nxt = html.unescape(current)
        except Exception:
            break
        if nxt == current:
            break
        current = nxt
    # 处理 &#x64; 这类
    def _num(match):
        raw = match.group(1)
        try:
            if raw.startswith("#x") or raw.startswith("#X"):
                return chr(int(raw[2:], 16))
            if raw.startswith("#"):
                return chr(int(raw[1:]))
        except (ValueError, OverflowError):
            return match.group(0)
        return match.group(0)

    try:
        current = HTML_ENTITY_RE.sub(_num, current)
    except Exception:
        pass
    return current


def unicode_unescape(text):
    """还原 \\uXXXX / \\xXX / \\UXXXXXXXX 转义。"""
    def _rep(match):
        raw = match.group(1) or match.group(2) or match.group(3)
        base = 16
        try:
            code = int(raw, base)
            if code > 0x10FFFF:
                return match.group(0)
            return chr(code)
        except (ValueError, OverflowError):
            return match.group(0)

    try:
        return UNICODE_ESC_RE.sub(_rep, text)
    except Exception:
        return text


def strip_invisible(text):
    text = INVISIBLE_RE.sub("", text)
    # 去掉其他控制字符（保留 \t \n \r）
    return "".join(ch for ch in text
                   if ch in "\t\n\r" or unicodedata.category(ch)[0] != "C")


def fold_fullwidth(text):
    """全角/兼容字符折叠 + NFKC 归一化。

    两层：
      1. 手工处理 CJK 形近字与全角 ASCII（原有表驱动行为）
      2. **Unicode NFKC** —— 把"兼容等价"的字符折成基本字符

    第 2 层是补的（实测发现的绕过）：
        𝐝𝐞𝐥𝐞𝐭𝐞   U+1D41D… 数学粗体字母
        Ⓓⓔⓛⓔⓣⓔ   带圈字母
        ｄｅｌｅｔｅ  全角（这一类旧逻辑已覆盖）
    前两类都是"兼容等价于 delete"，但不在 U+FF01–FF5E 区间里，
    旧逻辑完全放过 —— 实测 𝐝𝐞𝐥𝐞𝐭𝐞 归一化后原样保留，规则匹配不到。

    NFKC 一次覆盖全部兼容等价形式（含全角，与手工处理重复但幂等无害）。
    CJK 形近字表仍要保留：NFKC 不做"字形相似但编码不同"的映射。
    """
    out = []
    for ch in text:
        if ch in CJK_CONFUSABLE:
            out.append(CJK_CONFUSABLE[ch])
            continue
        code = ord(ch)
        if 0xFF01 <= code <= 0xFF5E:          # 全角 ASCII
            out.append(chr(code - 0xFEE0))
        elif code == 0x3000:                   # 表意空格
            out.append(" ")
        else:
            out.append(ch)
    folded = "".join(out)
    try:
        return unicodedata.normalize("NFKC", folded)
    except (TypeError, ValueError):
        return folded


def strip_sql_noise(text):
    text = SQL_COMMENT_RE.sub("", text)
    return text


def collapse_ws(text):
    return WS_RE.sub(" ", text)


def compact(text):
    """去掉所有分隔/噪声字符：d_e-l ete → delete。"""
    return SEP_RE.sub("", text)


def normalize(text, ops):
    """按 ops 顺序执行归一化。ops 见 rules.json 的 settings.normalize。"""
    if not isinstance(text, str):
        text = str(text)
    out = text
    for op in ops:
        try:
            if op == "url_decode":
                out = url_decode_deep(out)
            elif op == "html_unescape":
                out = html_unescape_deep(out)
            elif op == "unicode_unescape":
                out = unicode_unescape(out)
            elif op == "fold_fullwidth":
                out = fold_fullwidth(out)
            elif op == "strip_invisible":
                out = strip_invisible(out)
            elif op == "strip_sql_comment":
                out = strip_sql_noise(out)
            elif op == "collapse_ws":
                out = collapse_ws(out)
            elif op == "compact":
                out = compact(out)
            elif op == "lower":
                out = out.lower()
        except Exception:
            continue
    return out


def build_variants_with_map(text, ops):
    """返回 [(label, normalized_text, index_map)]。

    ``index_map`` 把归一化文本的每个字符位置映射回**原文**位置。
    没有它就没法把"在归一化文本里发现的命中"翻译回原文 ——
    归一化会改变长度（url_decode 变短、compact 删字符），
    拿归一化 offset 去切原文是错的：

      * matched_text 显示错位置（报告里能看到命中点上下文不对）
      * exclude / 白名单按错误位置判断 → 误拦、漏拦双向出问题
      * 实测：`?deleted_at=2024-01-01` 在 compact 变体上 offset=13，
        原文里那个位置根本不是 delete，导致本该放行的软删除字段被拦

    实现：给每个字符带一个"来自原文哪个下标"的标记，逐 op 传播。
    折叠/替换类操作（url_decode、fullwidth）把新字符归属到它替换掉的
    那一整段的首字符；删除类操作（compact、strip）自然消失。
    """
    if not isinstance(text, str):
        text = str(text)
    core_ops = [op for op in ops if op != "compact"]

    # "轻量归一化"变体（不含 compact）
    mid_text, mid_map = _apply_ops_with_map(text, core_ops)
    variants = []
    seen = set()

    def _add(label, value, index_map):
        if not value or value in seen:
            return
        seen.add(value)
        variants.append((label, value, index_map))

    _add("normalized", mid_text, mid_map)
    # 原文变体：映射就是恒等（位置即原文位置）
    _add("original", text, list(range(len(text))))
    # 激进压缩变体：在中间结果上继续 compact
    comp_text, comp_map = _compact_with_map(list(mid_text), list(mid_map))
    _add("compact", "".join(comp_text), comp_map)
    return variants


_URL_CANDIDATE_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")
_HTML_CANDIDATE_RE = re.compile(r"(?:&#?[0-9a-zA-Z]{2,10};)+")
_UNI_CANDIDATE_RE = re.compile(r"(?:\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2})+")

# `+` 在 URL 表单编码里代表空格。单字符直接映射，不必进 func
# （这是热路径：查询串里 `+` 很常见，实测走 func 会明显变慢）。
_URL_FAST = {"+": " "}


def _apply_ops_with_map(text, ops):
    """按 ops 依次应用，全程维护 index_map。返回 (文本, 映射)。

    对解码类 op（url_decode / html_unescape / unicode_unescape）跑
    **多轮**，直到不再变化或达到轮次上限。为什么需要：`%2541` 是
    两层编码（`%25`→`%`，再 `%41`→`A`），`&amp;lt;` 同理。
    单轮只能解开外层，结果会和 normalize() 不一致 —— 那意味着
    按映射变体匹配的关键词跟实际解码结果不同，形成绕过。
    """
    chars = list(text)
    idx = list(range(len(text)))
    for op in ops:
        try:
            if op == "url_decode":
                chars, idx = _repeat_transform(
                    chars, idx, url_decode_deep, _URL_CANDIDATE_RE,
                    fast=_URL_FAST)
            elif op == "html_unescape":
                chars, idx = _repeat_transform(
                    chars, idx, html_unescape_deep, _HTML_CANDIDATE_RE)
            elif op == "unicode_unescape":
                chars, idx = _repeat_transform(
                    chars, idx, unicode_unescape, _UNI_CANDIDATE_RE)
            elif op == "fold_fullwidth":
                chars, idx = _fold_with_map(chars, idx)
            elif op == "strip_invisible":
                chars, idx = _strip_with_map(chars, idx)
            elif op == "strip_sql_comment":
                chars, idx = _strip_with_map(chars, idx, SQL_COMMENT_RE)
            elif op == "collapse_ws":
                chars, idx = _collapse_with_map(chars, idx)
            elif op == "lower":
                chars = [c.lower() for c in chars]
        except Exception:
            continue
    return "".join(chars), idx


def _repeat_transform(chars, idx, func, candidate_re, fast=None, rounds=4):
    """反复跑 _map_transform 直到不再变化（覆盖多层编码）。

    轮次上限 4：正常站点最多两层编码；再多基本是刻意构造，
    这种输入我们只要保证"不卡"就够了 —— 解不开的层会原样保留，
    后续规则仍按字面匹配，不会因为解码失败而漏拦（只有更严）。
    """
    for _ in range(rounds):
        new_chars, new_idx = _map_transform(chars, idx, func,
                                            candidate_re, fast)
        if new_chars == chars:
            break
        chars, idx = new_chars, new_idx
    return chars, idx


def _map_transform(chars, idx, func, candidate_re=None, fast=None,
                   max_span=16):
    """逐字符替换类 op 的通用处理（url_decode / html_unescape / unicode）。

    这些操作可能把 `%20` 变成 ` `（3→1）、`&amp;` 变成 `&`（5→1）、
    `+` 变成空格（1→1，表单编码语义）。

    性能（踩过的坑）：最早对每个 `%`/`&`/`\\`/`+` 都无条件尝试展开成
    1..12 字符片段并逐一调用 func —— 输入塞满 `%` 时（URL 里合法）
    就是 30000×12 次 join + 正则，实测 30000 个 `%` 要 2.7 秒
    （对照纯字母 0.05 秒，54 倍）。配合 max_scan_bytes=256KB，
    单请求能拖到几十秒，几个并发就打满 CPU。

    现在两步：
      1. 用**候选正则**一次性找出"看起来是转义序列"的位置
         （`%[0-9a-f]{2}`、`&#\\d+;`、`\\u[0-9a-f]{4}`…）。
         没有转义序列的输入只付一次正则扫描的代价。
      2. 只在候选区间上调用 func，整段连续转义序列一次解完。

    多轮解码（`%2541` → `%41` → `A`、`&amp;lt;` → `&lt;` → `<`）
    由 _apply_ops_with_map 外层**重复跑几轮**来覆盖，而不是在单轮里
    从长到短试探 —— 后者会把普通文本也吞进去，导致 index_map 塌缩
    （实测踩过，匹配位置全挤到区间开头）。

    ``fast`` 是无需展开的单字符快速通道（`+` → 空格），走它不调 func。
    """
    out_chars, out_idx = [], []
    text = "".join(chars)
    n = len(chars)

    # 候选区间：起始下标 -> 连续转义串的长度。
    # 正则本身是贪心的（(?:%xx)+ / (?:&#\w+;)+），一次匹配就拿到
    # 整段连续转义序列，不用逐个字符试探。
    spans = {}
    if candidate_re is not None:
        for m in candidate_re.finditer(text):
            spans[m.start()] = m.end() - m.start()

    i = 0
    while i < n:
        if i in spans:
            length = spans[i]
            seg = text[i:i + length]
            try:
                new = func(seg)
            except Exception:
                new = seg
            if new != seg:
                out_chars.extend(list(new))
                out_idx.extend([idx[i]] * len(new))
                i += length
                continue
        ch = chars[i]
        if fast is not None and ch in fast:
            out_chars.append(fast[ch])
            out_idx.append(idx[i])
            i += 1
            continue
        out_chars.append(ch)
        out_idx.append(idx[i])
        i += 1
    return out_chars, out_idx


def _fold_with_map(chars, idx):
    """折叠 + NFKC，并维护 index_map。

    注意 NFKC 可能把一个字符展开成多个（㍿ → 株式会社、ﬁ → fi、
    ½ → 1⁄2），所以映射要用 [origin] * len(new) —— 展开出来的每个字符
    都归属到原字符的位置。早先如果按 1:1 处理，长度就对不上了
    （映射比文本短，offset 全错位）。
    """
    out_chars, out_idx = [], []
    for ch, origin in zip(chars, idx):
        if ch in CJK_CONFUSABLE:
            new = CJK_CONFUSABLE[ch]
        else:
            code = ord(ch)
            if 0xFF01 <= code <= 0xFF5E:
                new = chr(code - 0xFEE0)
            elif code == 0x3000:
                new = " "
            else:
                new = ch
        try:
            new = unicodedata.normalize("NFKC", new)
        except (TypeError, ValueError):
            pass
        out_chars.extend(list(new))
        out_idx.extend([origin] * len(new))
    return out_chars, out_idx


def _strip_with_map(chars, idx, pattern=None):
    out_chars, out_idx = [], []
    for ch, origin in zip(chars, idx):
        if pattern is not None:
            if pattern.search(ch):
                continue
        else:
            if INVISIBLE_RE.search(ch):
                continue
            if ch not in "\t\n\r" and unicodedata.category(ch)[0] == "C":
                continue
        out_chars.append(ch)
        out_idx.append(origin)
    return out_chars, out_idx


def _collapse_with_map(chars, idx):
    """连续空白折成一个空格，归属到该段首个字符。"""
    out_chars, out_idx = [], []
    prev_ws = False
    for ch, origin in zip(chars, idx):
        is_ws = ch in " \t\n\r"
        if is_ws:
            if prev_ws:
                continue
            out_chars.append(" ")
            out_idx.append(origin)
            prev_ws = True
        else:
            out_chars.append(ch)
            out_idx.append(origin)
            prev_ws = False
    return out_chars, out_idx


def _compact_with_map(chars, idx):
    """去掉分隔/噪声字符，归属关系不变。"""
    out_chars, out_idx = [], []
    for ch, origin in zip(chars, idx):
        if SEP_RE.search(ch):
            continue
        out_chars.append(ch)
        out_idx.append(origin)
    return out_chars, out_idx


