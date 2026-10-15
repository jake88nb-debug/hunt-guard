# -*- coding: utf-8 -*-
"""事件日志（SQLite）：拦截记录、放行记录、统计。"""

import json
import os
import sqlite3
import threading
import time

from . import config

_lock = threading.RLock()
_local = threading.local()


def _connect():
    config.ensure_dirs()
    conn = sqlite3.connect(config.DB_FILE, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    # 自动 checkpoint：WAL 攒到约 1MB 就合并回主库并截断。
    #
    # 为什么必须设（实测发现）：WAL 默认只在连接关闭时合并，
    # 而控制台是长驻进程、可能几天不关 —— 于是 data/events.db-wal 会
    # 一直涨（实测本机 4.1MB）。它是**明文**的拦截记录（完整 URL、
    # payload、命中的关键词），而且多数清理动作只盯着 .db 本身，
    # 不会想到旁边那个 -wal 里才是最新最全的内容。设上限后残留有界。
    conn.execute("PRAGMA wal_autocheckpoint=1000")   # 单位：页（约 1MB）
    return conn


def get_conn():
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = _connect()
        _local.conn = conn
    return conn


def init_db():
    conn = get_conn()
    with _lock:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          REAL    NOT NULL,
            ts_text     TEXT    NOT NULL,
            blocked     INTEGER NOT NULL,
            reason      TEXT    NOT NULL DEFAULT '',
            stage       TEXT    NOT NULL DEFAULT '',
            tool        TEXT    NOT NULL DEFAULT '',
            method      TEXT    NOT NULL DEFAULT '',
            target      TEXT    NOT NULL DEFAULT '',
            rule_ids    TEXT    NOT NULL DEFAULT '',
            hit_count   INTEGER NOT NULL DEFAULT 0,
            severity    TEXT    NOT NULL DEFAULT '',
            unlocked    INTEGER NOT NULL DEFAULT 0,
            duration_ms REAL    NOT NULL DEFAULT 0,
            detail      TEXT    NOT NULL DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts DESC);
        CREATE INDEX IF NOT EXISTS idx_events_blocked ON events(blocked, ts DESC);
        CREATE INDEX IF NOT EXISTS idx_events_tool    ON events(tool, ts DESC);
        """)
        conn.commit()


def _severity_of(hits):
    from .models import SEVERITY_ORDER
    best = ""
    best_rank = 99
    for hit in hits or []:
        sev = (hit.get("severity") or "medium") if isinstance(hit, dict) else getattr(hit, "severity", "medium")
        rank = SEVERITY_ORDER.get(sev, 99)
        if rank < best_rank:
            best_rank = rank
            best = sev
    return best


def add_event(verdict, tool="", rule_ids=None):
    """写入一条事件。verdict 可以是 Verdict 对象或 dict。"""
    if hasattr(verdict, "to_dict"):
        data = verdict.to_dict(include_meta=False)
        target = getattr(verdict, "target", "")
        duration = getattr(verdict, "duration_ms", 0.0)
        unlocked = getattr(verdict, "unlocked", False)
        method = getattr(verdict, "method", "")
    else:
        data = dict(verdict)
        target = data.get("target", "")
        duration = data.get("duration_ms", 0.0)
        unlocked = data.get("unlocked", False)
        method = data.get("method", "")

    hits = data.get("hits") or []
    if rule_ids is None:
        ids = []
        for hit in hits:
            rid = hit.get("rule_id") if isinstance(hit, dict) else None
            if rid and rid not in ids:
                ids.append(rid)
        rule_ids = ids
    elif isinstance(rule_ids, str):
        rule_ids = [rule_ids]

    conn = get_conn()
    with _lock:
        cur = conn.execute(
            """INSERT INTO events
               (ts, ts_text, blocked, reason, stage, tool, method, target,
                rule_ids, hit_count, severity, unlocked, duration_ms, detail)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                time.time(),
                time.strftime("%Y-%m-%d %H:%M:%S"),
                1 if data.get("blocked") else 0,
                str(data.get("reason") or ""),
                str(data.get("stage") or ""),
                str(tool or data.get("tool") or ""),
                str(method or data.get("method") or ""),
                str(target or "")[:4000],
                ",".join(rule_ids or []),
                len(hits),
                _severity_of(hits),
                1 if unlocked else 0,
                float(duration or 0.0),
                json.dumps(data, ensure_ascii=False)[:60000],
            ),
        )
        conn.commit()
        return cur.lastrowid


def query_events(limit=100, offset=0, blocked_only=False, tool="", search=""):
    conn = get_conn()
    sql = "SELECT * FROM events WHERE 1=1"
    params = []
    if blocked_only:
        sql += " AND blocked=1"
    if tool:
        sql += " AND tool=?"
        params.append(tool)
    if search:
        sql += " AND (target LIKE ? OR reason LIKE ? OR rule_ids LIKE ? OR detail LIKE ?)"
        like = "%" + search + "%"
        params.extend([like, like, like, like])
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([int(limit), int(offset)])
    rows = conn.execute(sql, params).fetchall()
    items = []
    for row in rows:
        item = dict(row)
        try:
            item["detail_json"] = json.loads(item.get("detail") or "{}")
        except ValueError:
            item["detail_json"] = {}
        item.pop("detail", None)
        item["rule_ids"] = [r for r in (item.get("rule_ids") or "").split(",") if r]
        items.append(item)
    total = conn.execute("SELECT COUNT(*) FROM events WHERE 1=1" +
                         (" AND blocked=1" if blocked_only else "") +
                         (" AND tool=?" if tool else "") +
                         (" AND (target LIKE ? OR reason LIKE ? OR rule_ids LIKE ? OR detail LIKE ?)" if search else ""),
                         params[:-2] if (blocked_only or tool or search) else []).fetchone()[0]
    return {"items": items, "total": total, "limit": limit, "offset": offset}


def stats():
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    blocked = conn.execute("SELECT COUNT(*) FROM events WHERE blocked=1").fetchone()[0]
    today_prefix = time.strftime("%Y-%m-%d") + "%"
    today = conn.execute("SELECT COUNT(*) FROM events WHERE ts_text LIKE ?",
                         (today_prefix,)).fetchone()[0]
    today_blocked = conn.execute("SELECT COUNT(*) FROM events WHERE blocked=1 AND ts_text LIKE ?",
                                 (today_prefix,)).fetchone()[0]
    by_tool = [dict(r) for r in conn.execute(
        "SELECT tool, COUNT(*) AS n, SUM(blocked) AS blocked FROM events GROUP BY tool ORDER BY n DESC").fetchall()]
    by_rule = [dict(r) for r in conn.execute(
        """SELECT rule_id, COUNT(*) AS n FROM (
             SELECT value AS rule_id FROM events, json_each(
               CASE WHEN rule_ids='' THEN '[]' ELSE '["' || replace(rule_ids, ',', '","') || '"]' END)
           ) GROUP BY rule_id ORDER BY n DESC LIMIT 20""").fetchall()] if _has_json1(conn) else []
    top_targets = [dict(r) for r in conn.execute(
        "SELECT target, COUNT(*) AS n, SUM(blocked) AS blocked FROM events GROUP BY target ORDER BY n DESC LIMIT 10").fetchall()]
    return {
        "total": total,
        "blocked": blocked,
        "allowed": total - blocked,
        "today": today,
        "today_blocked": today_blocked,
        "by_tool": by_tool,
        "by_rule": by_rule,
        "top_targets": top_targets,
    }


def _has_json1(conn):
    try:
        conn.execute("SELECT json_each('[]')")
        return True
    except sqlite3.OperationalError:
        return False


def clear_events(keep_days=None):
    conn = get_conn()
    with _lock:
        if keep_days is None:
            conn.execute("DELETE FROM events")
        else:
            cutoff = time.time() - keep_days * 86400
            conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
        conn.commit()
        # TRUNCATE checkpoint：把 WAL 内容合并回主库并**清空 WAL 文件**。
        # 只 commit 的话，被删的数据仍留在 -wal 里（它是明文），
        # 用户以为清干净了、实际还能从 -wal 捞出来。
        try:
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        except sqlite3.Error:
            pass
        conn.execute("VACUUM")
    return True


def db_size():
    """返回 (主库字节, WAL 字节)，方便自检里提示清理。"""
    sizes = []
    for suffix in ("", "-wal", "-shm"):
        try:
            sizes.append(os.path.getsize(config.DB_FILE + suffix))
        except OSError:
            sizes.append(0)
    return sizes[0], sizes[1]
