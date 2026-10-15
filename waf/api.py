# -*- coding: utf-8 -*-
"""本地 REST API + Web UI 服务（stdlib，无第三方依赖）。

路由
----
GET  /                      仪表盘
GET  /api/status            引擎与进程状态
GET  /api/rules             规则 + 设置 + 放行名单
POST /api/rules             新增/更新规则
POST /api/rules/toggle      启用/停用规则
POST /api/rules/delete      删除规则
POST /api/allow             新增/更新放行名单
POST /api/allow/delete      删除放行条目
POST /api/settings          修改全局设置（mode / fail_mode 等）
POST /api/scan              测试台：扫描任意文本或请求
POST /api/unlock            开启解锁窗口
POST /api/lock              立即上锁
GET  /api/events            事件列表（分页/过滤）
GET  /api/stats             统计
POST /api/events/clear      清空或按天数清理日志
GET  /api/proxy             代理状态
POST /api/proxy             启停代理（mitm / upstream）
GET  /api/ca                导出 CA 文件路径与下载
GET  /api/ca/download       下载 CA 证书
POST /api/shutdown          关闭控制台
"""

import json
import os
import socketserver
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from . import certs, config, logstore, rules as rules_mod, state
from .engine import get_engine
from .models import ScanTarget

_UI_CACHE = {}
_proxy_holder = {"server": None, "thread": None}
_started_at = time.time()
_verbose = os.environ.get("WAF_LOG_REQUESTS") == "1"

# 本地 API 的请求体上限。控制台只收规则/设置这类小 JSON，
# 限长可以避免畸形请求把内存吃满（实测发现的 _read_body 无上限）。
MAX_BODY_BYTES = 4 * 1024 * 1024


def _read_ui(name):
    path = os.path.join(config.UI_DIR, name)
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _inject_token(body):
    """把 auth_token 注入页面，让 UI 能带着它请求 API。

    为什么需要（实测发现的坑）：config.auth_token 一填，所有 API
    都要 X-Auth-Token，而 UI 从来不发送这个头 —— 于是**按文档开启
    安全选项 = 整个控制台报废**，且没有界面能改回来（只能手改
    config.json）。这是"照着文档配置反而把工具弄坏"的典型。

    注入方式：在 </head> 前插一段 <script>window.__WAF_TOKEN=...</script>。
    页面是本地同源的，token 本来就要给这个页面用；跨站请求已被
    _guard_origin 拒掉，所以不存在"被别的网页读走"的路径。
    """
    try:
        cfg = config.load_config()
        token = str(cfg.get("auth_token") or "")
        if not token or not body:
            return body
        marker = b"</head>"
        if marker not in body:
            return body
        snippet = ('<script>window.__WAF_TOKEN=%s;</script>'
                   % json.dumps(token)).encode("utf-8")
        return body.replace(marker, snippet + marker, 1)
    except Exception:
        return body


class Handler(BaseHTTPRequestHandler):
    server_version = "HuntGuard/" + config.VERSION
    protocol_version = "HTTP/1.1"

    # ------------------------------------------------------------ 工具

    def log_message(self, fmt, *args):
        if _verbose:
            sys.stderr.write("[agent-waf api] %s - %s\n" %
                             (self.address_string(), fmt % args))

    def _send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, body, content_type, status=200, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        # 本地 API 不需要大 body；限长可以防止一个畸形请求把内存吃满
        if length > MAX_BODY_BYTES:
            raise ValueError("请求体过大（%d > %d）" % (length, MAX_BODY_BYTES))
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _guard_token(self):
        """可选鉴权：config.auth_token 非空时校验 X-Auth-Token。"""
        cfg = config.load_config()
        token = cfg.get("auth_token") or ""
        if not token:
            return True
        return self.headers.get("X-Auth-Token") == token

    def _guard_origin(self):
        """拒绝来自网页的跨站请求（CSRF 防护）。

        为什么必须有：控制台监听 127.0.0.1 且默认无 token，
        任何网页都能对着它发请求。`mode:'no-cors'` 的 fetch 虽然读不到
        响应，但**请求已经发出去了** —— 足以触发
        `POST /api/intercept {"action":"off"}` 静默关掉护栏。
        攻击者只要在目标网站上挂一段 JS，或在用户浏览的页面里塞一个
        form，就能在用户毫不知情时解除防护。

        判据：浏览器发起的跨站请求一定带 Origin（或 Referer）头，
        且值不是本机地址。curl / 脚本不带这些头 —— 所以正常用法不受影响。
        """
        origin = self.headers.get("Origin") or ""
        referer = self.headers.get("Referer") or ""
        for value in (origin, referer):
            if not value:
                continue
            try:
                host = urlparse(value).hostname or ""
            except ValueError:
                return False                     # 解析不了的 Origin 直接拒
            if host not in ("127.0.0.1", "localhost", "::1"):
                return False
        return True

    # ------------------------------------------------------------ 路由

    def do_GET(self):
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        if route in ("/", "/index.html"):
            body = _read_ui("index.html")
            if body is None:
                self._send_json({"error": "ui/index.html 缺失"}, 500)
                return
            # 注入了 auth_token（若配置了），UI 才能带着它调 API ——
            # 否则一填 token 整个控制台就报废（见 _inject_token）
            self._send_bytes(_inject_token(body), "text/html; charset=utf-8")
            return

        if route.startswith("/static/"):
            name = os.path.basename(route)
            body = _read_ui(name)
            if body is None:
                self._send_json({"error": "not found"}, 404)
                return
            ctype = "text/css" if name.endswith(".css") else (
                "application/javascript" if name.endswith(".js") else "application/octet-stream")
            self._send_bytes(body, ctype)
            return

        if not route.startswith("/api/"):
            self._send_json({"error": "not found", "path": route}, 404)
            return

        # GET 也挡跨站请求。虽然浏览器 CORS 会让跨站读不到响应，
        # 但"请求确实发出去了"这一点就足以泄露信息（比如某些接口的
        # 副作用、或者配合 DNS rebinding）。POST 已有这道闸，GET 也补上。
        if not self._guard_origin():
            self._send_json({"error": "cross-origin request rejected"}, 403)
            return

        if not self._guard_token():
            self._send_json({"error": "unauthorized"}, 401)
            return

        if route == "/api/status":
            self._send_json(self._status())
        elif route == "/api/rules":
            self._send_json(self._rules_payload())
        elif route == "/api/events":
            self._send_json(self._events(query))
        elif route == "/api/stats":
            self._send_json(logstore.stats())
        elif route == "/api/proxy":
            self._send_json(self._proxy_status())
        elif route == "/api/ca":
            self._send_json(self._ca_status())
        elif route == "/api/ca/download":
            self._download_ca()
        elif route == "/api/health":
            self._send_json({"ok": True, "version": config.VERSION})
        else:
            self._send_json({"error": "not found", "path": route}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/")

        # 先挡跨站请求，再查 token：网页只要能让浏览器发一个 POST
        # 就能关掉护栏（mode:'no-cors' 读不到响应但请求已经生效）。
        if not self._guard_origin():
            self._send_json(
                {"error": "cross-origin request rejected",
                 "hint": "控制台只接受本机请求；浏览器扩展/网页无法操作它"}, 403)
            return

        if not self._guard_token():
            self._send_json({"error": "unauthorized"}, 401)
            return

        handlers = {
            "/api/rules": self._upsert_rule,
            "/api/rules/toggle": self._toggle_rule,
            "/api/rules/delete": self._delete_rule,
            "/api/allow": self._upsert_allow,
            "/api/allow/delete": self._delete_allow,
            "/api/settings": self._update_settings,
            "/api/scan": self._scan,
            "/api/report": self._report_event,
            "/api/unlock": self._unlock,
            "/api/lock": self._lock_now,
            "/api/events/clear": self._clear_events,
            "/api/proxy": self._proxy_control,
            "/api/intercept": self._intercept_control,
            "/api/shutdown": self._shutdown,
        }
        handler = handlers.get(route)
        if handler is None:
            self._send_json({"error": "not found", "path": route}, 404)
            return
        try:
            handler(self._read_body())
        except ValueError as exc:
            self._send_json({"error": str(exc)}, 400)
        except Exception as exc:
            self._send_json({"error": "%s: %s" % (type(exc).__name__, exc)}, 500)

    # ------------------------------------------------------------ 业务

    def _status(self):
        engine = get_engine()
        proxy_state = self._proxy_status()
        st = state.status()
        return {
            "version": config.VERSION,
            "uptime_sec": round(time.time() - _started_at, 1),
            "pid": os.getpid(),
            "root": config.ROOT,
            "rules_file": config.rules_path(),
            "db_file": config.DB_FILE,
            "intercept_enabled": engine.enabled(),
            "active": st.get("active"),
            "active_detail": st,
            "mode": engine.mode(),
            "fail_mode": engine.settings.get("fail_mode", "closed"),
            "unlock_remaining": round(engine.unlock_remaining(), 1),
            "unlock_reason": engine.settings.get("unlock_reason", ""),
            "rules_total": len(engine.rules),
            "rules_enabled": len([r for r in engine.rules if r.get("enabled", True)]),
            "allowlist_total": len((engine.doc or {}).get("allowlist") or []),
            "proxy": proxy_state,
            "stats": logstore.stats(),
        }

    def _rules_payload(self):
        engine = get_engine()
        doc = engine.doc or {}
        return {
            "settings": doc.get("settings") or {},
            "rules": doc.get("rules") or [],
            "allowlist": doc.get("allowlist") or [],
            "updated_at": doc.get("updated_at", ""),
            "unlock_remaining": round(engine.unlock_remaining(), 1),
        }

    def _events(self, query):
        def _int(name, default):
            try:
                return int((query.get(name) or [default])[0])
            except (ValueError, TypeError):
                return default

        blocked_only = (query.get("blocked") or ["0"])[0] in ("1", "true", "yes")
        return logstore.query_events(
            limit=min(max(_int("limit", 100), 1), 1000),
            offset=max(_int("offset", 0), 0),
            blocked_only=blocked_only,
            tool=(query.get("tool") or [""])[0],
            search=(query.get("q") or [""])[0],
        )

    def _reload_rules_file(self, mutate):
        """读改写 rules.json，保证 UI 操作原子且可回滚。

        走 rules_mod.update_document：读-改-写整段在同一把**跨进程**
        锁里。原来是自己 load + save，控制台与独立 wafctl 并发时
        后写者会整体覆盖前者的改动（实测丢失更新，见
        rules.update_document 的说明）。
        """
        box = {}

        def _wrapped(doc):
            box["result"] = mutate(doc)
            return doc

        saved = rules_mod.update_document(_wrapped, config.rules_path())
        get_engine().load(force=True)
        return saved, box.get("result")

    def _upsert_rule(self, payload):
        rule = payload.get("rule") or payload
        if not isinstance(rule, dict):
            raise ValueError("缺少 rule 对象")
        if not rule.get("id"):
            rule = dict(rule)
            rule["id"] = "R-" + os.urandom(3).hex().upper()
        _, saved_rule = self._reload_rules_file(
            lambda doc: rules_mod.upsert_rule(doc, rule))
        self._send_json({"ok": True, "rule": saved_rule})

    def _toggle_rule(self, payload):
        rule_id = str(payload.get("id") or "")
        enabled = bool(payload.get("enabled", True))
        if not rule_id:
            raise ValueError("缺少 id")
        _, ok = self._reload_rules_file(
            lambda doc: rules_mod.toggle_rule(doc, rule_id, enabled))
        self._send_json({"ok": bool(ok), "id": rule_id, "enabled": enabled})

    def _delete_rule(self, payload):
        rule_id = str(payload.get("id") or "")
        if not rule_id:
            raise ValueError("缺少 id")
        _, ok = self._reload_rules_file(
            lambda doc: rules_mod.delete_rule(doc, rule_id))
        self._send_json({"ok": bool(ok), "id": rule_id})

    def _upsert_allow(self, payload):
        entry = payload.get("allow") or payload
        if not isinstance(entry, dict):
            raise ValueError("缺少 allow 对象")
        if not entry.get("id"):
            entry = dict(entry)
            entry["id"] = "A-" + os.urandom(3).hex().upper()
        _, saved = self._reload_rules_file(
            lambda doc: rules_mod.upsert_allow(doc, entry))
        self._send_json({"ok": True, "allow": saved})

    def _delete_allow(self, payload):
        allow_id = str(payload.get("id") or "")
        if not allow_id:
            raise ValueError("缺少 id")
        _, ok = self._reload_rules_file(
            lambda doc: rules_mod.delete_allow(doc, allow_id))
        self._send_json({"ok": bool(ok), "id": allow_id})

    def _update_settings(self, payload):
        patch = payload.get("settings") if isinstance(payload.get("settings"), dict) else payload
        allowed = set(rules_mod.DEFAULT_SETTINGS.keys())

        def _mutate(doc):
            settings = doc.setdefault("settings", {})
            for key, value in (patch or {}).items():
                if key in allowed:
                    settings[key] = value
            return dict(settings)

        _, settings = self._reload_rules_file(_mutate)
        self._send_json({"ok": True, "settings": settings})

    def _scan(self, payload):
        mode = str(payload.get("kind") or "text")
        engine = get_engine()
        if mode == "request":
            target = ScanTarget(
                kind="request",
                method=str(payload.get("method") or "GET").upper(),
                url=str(payload.get("url") or ""),
                host=str(payload.get("host") or ""),
                path=str(payload.get("path") or ""),
                query=str(payload.get("query") or ""),
                headers=payload.get("headers") or {},
                body=str(payload.get("body") or ""),
                tool="console",
            )
        elif mode == "curl":
            from .curlshim import parse_curl_args
            argv = payload.get("argv")
            if isinstance(argv, str):
                argv = argv.split()
            target, _ = parse_curl_args(list(argv or []))
            target.tool = "console"
        else:
            text = str(payload.get("text") or "")
            target = ScanTarget(kind="text", method="", url="", path="",
                                body=text, tool="console")
        verdict = engine.scan(target, log=bool(payload.get("log", True)))
        self._send_json(verdict.to_dict(include_meta=True))

    def _report_event(self, payload):
        """外部工具（Burp 扩展等）已经自行判定过，这里只落库，避免重复扫描。

        请求体：
            { "tool": "burp-repeater", "method": "GET", "url": "...",
              "blocked": true, "reason": "...", "hits": [...] }
        """
        tool = str(payload.get("tool") or "external")
        hits = payload.get("hits") or []
        event = {
            "blocked": bool(payload.get("blocked")),
            "reason": str(payload.get("reason") or ""),
            "stage": str(payload.get("stage") or "burp_extension"),
            "hits": hits,
            "unlocked": bool(payload.get("unlocked")),
            "method": str(payload.get("method") or ""),
            "target": str(payload.get("url") or "")[:4000],
        }
        event_id = logstore.add_event(event, tool=tool)
        self._send_json({"ok": True, "id": event_id})

    def _unlock(self, payload):
        minutes = float(payload.get("minutes") or 10)
        reason = str(payload.get("reason") or "")
        until = get_engine().set_unlock(minutes, reason)
        logstore.add_event({
            "blocked": False,
            "reason": "解锁窗口开启：%s 分钟（%s）" % (minutes, reason or "未填理由"),
            "stage": "unlock",
            "hits": [],
            "unlocked": True,
            "method": "-",
            "target": "-",
        }, tool="console")
        self._send_json({"ok": True, "unlock_until": until,
                         "remaining": round(get_engine().unlock_remaining(), 1)})

    def _lock_now(self, payload):
        get_engine().clear_unlock()
        logstore.add_event({
            "blocked": False, "reason": "解锁窗口已手动关闭", "stage": "lock",
            "hits": [], "unlocked": False, "method": "-", "target": "-",
        }, tool="console")
        self._send_json({"ok": True, "remaining": 0})

    def _clear_events(self, payload):
        keep_days = payload.get("keep_days")
        if keep_days in ("", None):
            keep_days = None
        else:
            keep_days = float(keep_days)
        logstore.clear_events(keep_days)
        self._send_json({"ok": True, "keep_days": keep_days})

    # ------------------------------------------------------------ 代理

    def _proxy_status(self):
        server = _proxy_holder.get("server")
        running = bool(server and _proxy_holder.get("thread")
                       and _proxy_holder["thread"].is_alive())
        if running:
            return dict(server.status(), running=True)
        cfg = config.load_config()
        return {
            "running": False,
            "host": cfg.get("proxy_host", config.PROXY_HOST),
            "port": cfg.get("proxy_port", config.PROXY_PORT),
            "mitm": False,
            "upstream": None,
        }

    def _proxy_control(self, payload):
        action = str(payload.get("action") or "status").lower()
        if action == "start":
            self._proxy_start(payload)
        elif action == "stop":
            self._proxy_stop()
        elif action == "status":
            self._send_json(self._proxy_status())
        else:
            raise ValueError("action 只能是 start/stop/status")

    def _proxy_start(self, payload):
        if self._proxy_status().get("running"):
            self._send_json({"ok": True, "already": True,
                             "status": self._proxy_status()})
            return
        from .proxy import ProxyServer

        mitm = bool(payload.get("mitm"))
        upstream = payload.get("upstream") or None
        upstream_port = payload.get("upstream_port")
        if upstream:
            if not upstream_port:
                upstream_port = 8080
            upstream_port = int(upstream_port)

        cfg = config.load_config()
        server = ProxyServer(
            host=cfg.get("proxy_host", config.PROXY_HOST),
            port=int(cfg.get("proxy_port", config.PROXY_PORT)),
            mitm=mitm, upstream=upstream, upstream_port=upstream_port)

        if mitm:
            certs.ensure_ca()
            _proxy_holder["ca"] = certs.ca_paths()

        thread = threading.Thread(target=server.serve_forever)
        thread.daemon = True
        thread.start()
        _proxy_holder["server"] = server
        _proxy_holder["thread"] = thread
        time.sleep(0.4)
        status = server.status()
        status["running"] = True
        self._send_json({"ok": True, "status": status})

    def _proxy_stop(self):
        server = _proxy_holder.get("server")
        if server:
            server.shutdown()
        _proxy_holder["server"] = None
        _proxy_holder["thread"] = None
        self._send_json({"ok": True, "running": False})

    # ------------------------------------------------------------ CA

    def _ca_status(self):
        if not certs.available():
            return {"available": False,
                    "hint": "pip install cryptography 后才能生成 CA"}
        try:
            paths = certs.ca_paths()
        except Exception as exc:
            return {"available": False, "error": str(exc)}
        return {
            "available": True,
            "cert": paths["cert"],
            "key": paths["key"],
            "download_url": "/api/ca/download",
            "hint": "把 CA 导入系统/浏览器信任库；curl 用 --cacert <cert>",
        }

    def _download_ca(self):
        try:
            paths = certs.ca_paths()
            with open(paths["cert"], "rb") as fh:
                body = fh.read()
        except Exception as exc:
            self._send_json({"error": str(exc)}, 500)
            return
        self._send_bytes(body, "application/x-x509-ca-cert", extra={
            "Content-Disposition": 'attachment; filename="agent-waf-ca.crt"'})

    # ------------------------------------------------------------ 拦截开关

    def _intercept_control(self, payload):
        """总开关：开启/暂停拦截。不改规则，只改 settings.enabled。"""
        action = str(payload.get("action") or "status").lower()
        engine = get_engine()

        if action == "status":
            st = state.status()
            self._send_json({"ok": True, "enabled": engine.enabled(),
                             "active": st.get("active"), "detail": st})
            return

        if action == "on":
            engine.set_enabled(True)
            state.activate(pid=os.getpid())
            logstore.add_event({
                "blocked": False, "reason": "拦截已开启", "stage": "intercept_on",
                "hits": [], "unlocked": False, "method": "-", "target": "-",
            }, tool="console")
            st = state.status()
            self._send_json({"ok": True, "enabled": True, "active": st.get("active")})
            return

        if action == "off":
            engine.set_enabled(False)
            logstore.add_event({
                "blocked": False, "reason": "拦截已暂停（透传所有请求）",
                "stage": "intercept_off", "hits": [], "unlocked": False,
                "method": "-", "target": "-",
            }, tool="console")
            st = state.status()
            self._send_json({"ok": True, "enabled": False, "active": st.get("active")})
            return

        raise ValueError("action 只能是 on/off/status")

    # ------------------------------------------------------------ 关闭

    def _shutdown(self, payload):
        self._send_json({"ok": True, "message": "HuntGuard 正在关闭"})

        def _stop():
            time.sleep(0.3)
            server = _proxy_holder.get("server")
            if server:
                try:
                    server.shutdown()
                except Exception:
                    pass
            try:
                self.server.shutdown()
            except Exception:
                pass

        threading.Thread(target=_stop, daemon=True).start()


class _ThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(host=None, port=None, open_browser=False):
    cfg = config.load_config()
    host = host or cfg.get("api_host", config.API_HOST)
    port = int(port or cfg.get("api_port", config.API_PORT))

    config.ensure_dirs()
    logstore.init_db()
    rules_mod.write_defaults_if_missing()
    get_engine().load(force=True)

    # 激活拦截器：写心跳文件，后台线程持续刷新。
    # 这就是"打开了才生效"的开关 —— 关闭控制台（或强杀后心跳过期）
    # 都会让 curl shim / 代理 / Burp 扩展回到纯透传状态。
    state.activate(port=port, pid=os.getpid())

    httpd = _ThreadingHTTPServer((host, port), Handler)
    url = "http://%s:%d/" % (host, port)
    sys.stderr.write("[agent-waf] 控制台已启动：%s\n" % url)
    sys.stderr.write("[agent-waf] 规则文件：%s\n" % config.rules_path())
    if open_browser:
        threading.Thread(target=lambda: (time.sleep(0.8), webbrowser.open(url)),
                         daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server = _proxy_holder.get("server")
        if server:
            server.shutdown()
        # 关闭时撤销激活态：之后 curl 直接透传
        state.deactivate()
        httpd.server_close()
        sys.stderr.write("[agent-waf] 已停止，拦截器回到未启用状态\n")
    return httpd


if __name__ == "__main__":
    serve()
