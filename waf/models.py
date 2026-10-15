# -*- coding: utf-8 -*-
"""数据模型：待检目标 / 命中 / 结论。"""

import json
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# source 取值（扫描维度）
SOURCE_URL = "url"
SOURCE_PATH = "path"
SOURCE_QUERY = "query"
SOURCE_BODY = "body"
SOURCE_HEADERS = "headers"
SOURCE_METHOD = "method"
SOURCE_HOST = "host"
SOURCE_RAW_CMD = "raw_cmd"

ALL_SOURCES = [SOURCE_URL, SOURCE_PATH, SOURCE_QUERY, SOURCE_BODY,
               SOURCE_HEADERS, SOURCE_METHOD, SOURCE_HOST, SOURCE_RAW_CMD]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class ScanTarget:
    """一个待检测对象。可以是 HTTP 请求，也可以是一条命令。"""

    kind: str = "request"           # request | curl | text
    method: str = "GET"
    url: str = ""
    host: str = ""
    path: str = ""
    query: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw_cmd: str = ""
    tool: str = ""                   # curl / burp / proxy / python / manual
    meta: Dict[str, Any] = field(default_factory=dict)

    def fields(self) -> List[tuple]:
        """返回 (source, text) 列表，只含非空项。"""
        out = []
        if self.method:
            out.append((SOURCE_METHOD, self.method))
        if self.host:
            out.append((SOURCE_HOST, self.host))
        if self.url:
            out.append((SOURCE_URL, self.url))
        if self.path:
            out.append((SOURCE_PATH, self.path))
        if self.query:
            out.append((SOURCE_QUERY, self.query))
        if self.body:
            out.append((SOURCE_BODY, self.body))
        if self.headers:
            blob = "\n".join("%s: %s" % (k, v) for k, v in self.headers.items())
            out.append((SOURCE_HEADERS, blob))
        if self.raw_cmd:
            out.append((SOURCE_RAW_CMD, self.raw_cmd))
        return out

    def summary(self) -> str:
        if self.kind == "curl" and self.raw_cmd:
            return self.raw_cmd
        target = self.url or (self.host + self.path)
        return "%s %s" % (self.method, target)


@dataclass
class Hit:
    """一条命中记录。

    两个字段容易混（写调用方代码时踩过两次）：

      ``source``      —— **源字段名**：url / host / path / query / body /
                         headers / raw_cmd。``offset`` 就是相对**这个字段
                         的原始文本**的位置，不是相对整条命令或整份报文。
      ``field_name``  —— **归一化变体标签**：normalized / original / compact。
                         表示这条命中是在哪个变体上发现的（用于排查
                         "为什么压缩写法也被命中"这类问题）。

    要按 offset 取原文，必须用 hit.source 对应的字段文本：
        text = dict(target.fields())[hit.source]
        text[hit.offset:hit.offset + len(hit.keyword)]
    """
    source: str
    keyword: str
    matched_text: str
    rule_id: str = ""
    rule_name: str = ""
    severity: str = "medium"
    action: str = "block"
    field_name: str = ""
    offset: int = -1

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "source": self.source,
            "keyword": self.keyword,
            "matched_text": self.matched_text,
        }
        # 截图同款三个字段在最前，其余为增强信息
        if self.rule_id:
            data["rule_id"] = self.rule_id
            data["rule_name"] = self.rule_name
            data["severity"] = self.severity
            data["action"] = self.action
        if self.offset >= 0:
            data["offset"] = self.offset
        return data


@dataclass
class Verdict:
    blocked: bool = False
    reason: str = ""
    stage: str = "content_scan"
    hits: List[Hit] = field(default_factory=list)
    suppressed: List[Dict[str, Any]] = field(default_factory=list)
    mode: str = "block"
    unlocked: bool = False
    duration_ms: float = 0.0
    target: str = ""
    tool: str = ""
    method: str = ""

    def to_dict(self, include_meta: bool = True) -> Dict[str, Any]:
        """默认输出与截图一致的 JSON 结构。"""
        data = {
            "success": not self.blocked,
            "blocked": self.blocked,
            "reason": self.reason,
            "stage": self.stage,
            "hits": [h.to_dict() for h in self.hits],
        }
        if include_meta:
            data["mode"] = self.mode
            data["unlocked"] = self.unlocked
            data["duration_ms"] = round(self.duration_ms, 2)
            if self.suppressed:
                data["suppressed"] = self.suppressed
            if self.target:
                data["target"] = self.target
            if self.tool:
                data["tool"] = self.tool
        return data

    def to_json(self, indent: int = 2, include_meta: bool = True) -> str:
        return json.dumps(self.to_dict(include_meta), ensure_ascii=False, indent=indent)


class WafBlocked(Exception):
    """guard 模式：请求被拦截时抛出。"""

    def __init__(self, verdict: Verdict):
        self.verdict = verdict
        super().__init__("%s (hits=%d)" % (verdict.reason, len(verdict.hits)))
