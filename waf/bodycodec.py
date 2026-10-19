# -*- coding: utf-8 -*-
"""请求体解码：按 Content-Encoding 解压后再交给引擎扫描。

为什么需要（实测绕过）：客户端发 ``Content-Encoding: gzip`` 时，body 是
压缩过的字节流 —— 目标会解压执行，而直接扫原始字节看不到
``action=delete``。压缩本身不是攻击，只是正常用法，所以必须解开扫。

做不到的情况（br / zstd 需要第三方库）**明确拒绝**，而不是假装扫过：
``unsupported`` 让调用方按 fail-closed 处理。
"""

import zlib

# 解压后的上限：防 zip bomb（256KB 的 gzip 可以膨胀到几百 MB）。
MAX_DECODED = 8 * 1024 * 1024

_STATUS_OK = "ok"
_STATUS_NONE = "none"
_STATUS_TOO_BIG = "too_big"
_STATUS_BAD = "bad"
_STATUS_UNSUPPORTED = "unsupported"

_IDENTITY = ("", "identity")


def _inflate(data, wbits):
    """有上限的解压；超出上限抛 ValueError。"""
    engine = zlib.decompressobj(wbits)
    try:
        out = engine.decompress(data, MAX_DECODED)
    except zlib.error as exc:
        raise ValueError("解压失败：%s" % exc)
    if engine.unconsumed_tail:
        raise ValueError("解压后超过 %d 字节" % MAX_DECODED)
    try:
        out += engine.flush()
    except zlib.error as exc:
        raise ValueError("解压失败：%s" % exc)
    if len(out) > MAX_DECODED:
        raise ValueError("解压后超过 %d 字节" % MAX_DECODED)
    return out


def decode_request_body(body, content_encoding):
    """按 Content-Encoding 解压请求体。

    返回 ``(data, status)``，status 取值：
      ``none``         没有编码（原样返回）
      ``ok``           解压成功
      ``too_big``      解压后超过上限
      ``bad``          数据损坏 / 不是它声称的编码
      ``unsupported``  编码本工具解不了（br / zstd ...）

    多重编码（"gzip, br"）按 RFC 逆序解；遇到解不了的就返回
    unsupported —— 不要跳过其中一层，那等于扫了个假 body。
    """
    if isinstance(body, str):
        body = body.encode("utf-8", "replace")
    if not body:
        return body, _STATUS_NONE
    header = (content_encoding or "").strip().lower()
    if header in _IDENTITY:
        return body, _STATUS_NONE

    layers = [part.strip() for part in header.split(",") if part.strip()]
    data = body
    for layer in reversed(layers):
        try:
            if layer in ("gzip", "x-gzip"):
                data = _inflate(data, 16 + zlib.MAX_WBITS)
            elif layer == "deflate":
                # 有的客户端发的是裸 deflate（无 zlib 头），两种都试
                try:
                    data = _inflate(data, zlib.MAX_WBITS)
                except ValueError:
                    data = _inflate(data, -zlib.MAX_WBITS)
            elif layer in _IDENTITY:
                continue
            else:
                return body, _STATUS_UNSUPPORTED
        except ValueError as exc:
            text = str(exc)
            if "超过" in text:
                return body, _STATUS_TOO_BIG
            return body, _STATUS_BAD
    return data, _STATUS_OK


def is_unsupported(status):
    return status in (_STATUS_UNSUPPORTED, _STATUS_TOO_BIG, _STATUS_BAD)
