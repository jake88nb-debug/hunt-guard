# -*- coding: utf-8 -*-
"""本地 HTTP/HTTPS 代理：所有经过它的请求先过 WAF。

三种用法
--------
1. 作为浏览器 / 工具的代理（HTTP 全量检测，HTTPS 在 --mitm 下全量检测）：
       wafctl start --proxy --mitm
       浏览器代理设为 127.0.0.1:8899，并导入 data/certs/agent-waf-ca.pem

2. 作为 Burp 的上游代理（Burp → Upstream Proxy → 127.0.0.1:8899）：
       只对 HTTP 明文有效；HTTPS 因为 Burp 自己完成 TLS，WAF 只能看到 CONNECT 主机名。
       HTTPS 要用 burp/burp_waf.py 扩展（推荐）。

3. 链式：浏览器 → WAF(8899, --mitm) → Burp(8080) → 目标
       wafctl start --proxy --mitm --upstream 127.0.0.1:8080
       WAF 先解密检查，再把明文交给 Burp，Burp 里能看到完整请求。

未开 --mitm 时，HTTPS 走 CONNECT 隧道：仅能按主机名/端口判定，隧道内内容不检查。
"""

import json
import os
import select
import socket
import ssl
import sys
import threading
import time

from . import certs, config, logstore, state
from .engine import get_engine
from .guard import no_socket_scan
from .models import ScanTarget, Verdict

MAX_HEADER_BYTES = 256 * 1024
MAX_BODY_BYTES = 32 * 1024 * 1024
SOCKET_TIMEOUT = 60
BLOCK_STATUS = "403 Forbidden"


def _log(msg):
    sys.stderr.write("[agent-waf proxy] %s\n" % msg)
    sys.stderr.flush()


class _Reader(object):
    """带缓冲的 socket 读取器，支持按行和按字节读。"""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            return False
        self.buf += chunk
        return True

    def read_line(self, limit=MAX_HEADER_BYTES):
        while b"\r\n" not in self.buf and b"\n" not in self.buf:
            if len(self.buf) > limit:
                raise ValueError("header too large")
            if not self._fill():
                if not self.buf:
                    return None
                break
        if b"\r\n" in self.buf:
            line, self.buf = self.buf.split(b"\r\n", 1)
        elif b"\n" in self.buf:
            line, self.buf = self.buf.split(b"\n", 1)
        else:
            line, self.buf = self.buf, b""
        return line

    def read_exact(self, count):
        while len(self.buf) < count:
            if not self._fill():
                break
        data, self.buf = self.buf[:count], self.buf[count:]
        return data

    def read_chunked(self, limit=MAX_BODY_BYTES):
        body = b""
        while True:
            line = self.read_line()
            if line is None:
                break
            size_text = line.split(b";", 1)[0].strip()
            try:
                size = int(size_text, 16)
            except ValueError:
                break
            if size == 0:
                while True:
                    trailer = self.read_line()
                    if trailer in (None, b""):
                        break
                break
            body += self.read_exact(size)
            self.read_exact(2)                     # CRLF
            if len(body) > limit:
                break
        return body

    def read_remaining(self, limit=MAX_BODY_BYTES):
        data = self.buf
        self.buf = b""
        while len(data) < limit:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return data


def _shred_files(*paths):
    """覆写后删除：私钥文件尽量不留可恢复内容。

    普通 unlink 只是解除目录项，数据块还在盘上；对私钥来说这是不必要的
    暴露面。覆写一遍再删，成本可以忽略（文件都是几 KB）。
    任何失败都吞掉 —— 清理不能影响主流程。
    """
    for path in paths:
        if not path:
            continue
        try:
            if os.path.exists(path):
                size = os.path.getsize(path)
                with open(path, "r+b") as fh:
                    fh.write(b"\x00" * size)
                    fh.flush()
                    os.fsync(fh.fileno())
        except OSError:
            pass
        try:
            os.remove(path)
        except OSError:
            pass


def _write_key_file(path, data):
    """写私钥文件，尽量只给自己可读（0600）。"""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


class ProxyServer(object):
    def __init__(self, host=None, port=None, mitm=False, upstream=None,
                 upstream_port=None, logger=None):
        cfg = config.load_config()
        self.host = host or cfg.get("proxy_host", config.PROXY_HOST)
        self.port = int(port or cfg.get("proxy_port", config.PROXY_PORT))
        self.mitm = bool(mitm)
        self.upstream = upstream
        self.upstream_port = upstream_port
        self._logger = logger or _log
        self._sock = None
        self._threads = []
        self._stop = threading.Event()
        self._conn_count = 0
        self._blocked_count = 0
        self._lock = threading.Lock()

    # ------------------------------------------------------------ 生命周期

    def serve_forever(self):
        # 清掉上次异常退出遗留的叶证书私钥（只增不删 = 私钥在盘上堆积）
        stale = self._cleanup_stale_leaves()
        if stale:
            self._logger("已清理上次遗留的 %d 个叶证书/私钥文件" % stale)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(128)
        self._sock.settimeout(1.0)
        self._logger("listening on %s:%d (mitm=%s, upstream=%s)" %
                     (self.host, self.port, self.mitm,
                      "%s:%s" % (self.upstream, self.upstream_port) if self.upstream else "-"))
        while not self._stop.is_set():
            try:
                client, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            thread = threading.Thread(target=self._handle_safe, args=(client, addr))
            thread.daemon = True
            thread.start()
            with self._lock:
                self._threads.append(thread)
                self._threads = [t for t in self._threads if t.is_alive()]

    def shutdown(self):
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass

    def handle_once(self, client, addr):
        """供测试直接调用。"""
        self._handle_safe(client, addr)

    # ------------------------------------------------------------ 连接处理

    def _handle_safe(self, client, addr):
        with self._lock:
            self._conn_count += 1
        try:
            client.settimeout(SOCKET_TIMEOUT)
            reader = _Reader(client)
            self._handle_stream(client, reader, None, None, addr, tls=False)
        except (socket.timeout, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as exc:
            self._logger("连接异常 %s: %r" % (addr, exc))
        finally:
            try:
                client.close()
            except Exception:
                pass

    def _handle_stream(self, client, reader, host_hint, port_hint, addr, tls):
        """处理一条（可能复用多次）连接上的请求。"""
        while True:
            try:
                request = self._read_request(reader, host_hint, port_hint, tls)
            except (ValueError, socket.timeout):
                return
            if request is None:
                return

            method, target, version, headers, body = request

            if method.upper() == "CONNECT" and not tls:
                if self._handle_connect(client, reader, target, addr):
                    continue                 # CONNECT 已升级为 TLS/隧道并处理完
                return

            if not self._handle_plain(client, method, target, version, headers, body,
                                      host_hint, port_hint, tls):
                return

    def _read_request(self, reader, host_hint, port_hint, tls):
        line = reader.read_line()
        if line is None:
            return None
        if not line.strip():
            return self._read_request(reader, host_hint, port_hint, tls)
        try:
            text = line.decode("latin-1")
        except Exception:
            return None
        parts = text.split()
        if len(parts) < 2:
            return None
        method, target = parts[0], parts[1]
        version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        headers = {}
        raw_pairs = []
        while True:
            header_line = reader.read_line()
            if header_line is None:
                return None
            if header_line in (b"", b"\r"):
                break
            try:
                htext = header_line.decode("latin-1")
            except Exception:
                continue
            if ":" not in htext:
                continue
            key, value = htext.split(":", 1)
            key, value = key.strip(), value.strip()
            headers[key] = value
            raw_pairs.append((key, value))

        lower = {k.lower(): v for k, v in headers.items()}
        body = b""
        if lower.get("transfer-encoding", "").lower().startswith("chunked"):
            body = reader.read_chunked()
        elif "content-length" in lower:
            try:
                length = int(lower["content-length"])
            except ValueError:
                length = 0
            body = reader.read_exact(min(max(length, 0), MAX_BODY_BYTES))

        return method, target, version, raw_pairs, body

    # ------------------------------------------------------------ CONNECT

    def _handle_connect(self, client, reader, target, addr):
        """CONNECT host:port —— 决策：拦截 / 裸隧道 / MITM。"""
        host, port = self._split_hostport(target)

        if self.mitm:
            if self._is_blocked_connect(host, port):
                self._send_block(client, self._last_verdict)
                return False
            try:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            except OSError:
                return False
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                cert_pem, key_pem = certs.leaf_for(host)
                # 叶证书私钥只在写盘→加载→删除这个瞬时窗口内存在。
                # 为什么不能留在盘上（攻击面）：proxy 之前把每个
                # CONNECT 过的主机的叶私钥都写进 data/run/ 且只增不删，
                # MITM 跑一天就攒出几十上百个私钥文件。配合"CA 已导入信任库"
                # 的前提，任何能读到这些文件的同用户进程都能伪造任意站点证书。
                # Python 3.8 的 load_cert_chain 只接受路径（实测不接受文件对象），
                # 所以必须落盘一次——那就用完立刻删，且删在 finally 里，
                # 保证握手失败也不会残留。
                cert_file, key_file = self._write_temp_leaf(host, cert_pem, key_pem)
                try:
                    ctx.load_cert_chain(cert_file, key_file)
                finally:
                    _shred_files(cert_file, key_file)
                tls_sock = ctx.wrap_socket(client, server_side=True)
            except Exception as exc:
                self._logger("MITM 握手失败 %s:%s (%r)" % (host, port, exc))
                return False
            tls_reader = _Reader(tls_sock)
            self._handle_stream(tls_sock, tls_reader, host, port, addr, tls=True)
            return False

        # 非 MITM：判定主机名，然后裸隧道直连（不检查内容）
        verdict = self._scan_connect(host, port)
        if verdict and verdict.blocked:
            with self._lock:
                self._blocked_count += 1
            self._send_block(client, verdict)
            return False

        try:
            upstream = self._open_tunnel(host, port)
        except OSError as exc:
            self._logger("CONNECT 失败 %s:%s (%r)" % (host, port, exc))
            try:
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n"
                               b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            except OSError:
                pass
            return False
        try:
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        except OSError:
            upstream.close()
            return False
        self._pipe(client, reader, upstream)
        return False

    def _open_tunnel(self, host, port):
        if self.upstream:
            sock = socket.create_connection((self.upstream, int(self.upstream_port)), 20)
            sock.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                          % (host, port, host, port)).encode("latin-1"))
            resp = b""
            sock.settimeout(15)
            while b"\r\n\r\n" not in resp and len(resp) < 8192:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                resp += chunk
            if b" 200 " not in resp.split(b"\r\n", 1)[0]:
                sock.close()
                raise OSError("上游代理拒绝 CONNECT：%s" % resp[:200])
            return sock
        return socket.create_connection((host, port), 20)

    def _pipe(self, client, reader, upstream):
        """双向转发直到任一端关闭。reader 里可能已有缓冲数据。"""
        if reader.buf:
            try:
                upstream.sendall(reader.buf)
            except OSError:
                pass
            reader.buf = b""
        try:
            while not self._stop.is_set():
                readable, _, _ = select.select([client, upstream], [], [], 1.0)
                if not readable:
                    continue
                for sock in readable:
                    try:
                        data = sock.recv(65536)
                    except OSError:
                        return
                    if not data:
                        return
                    other = upstream if sock is client else client
                    try:
                        other.sendall(data)
                    except OSError:
                        return
        finally:
            try:
                upstream.close()
            except Exception:
                pass

    def _split_hostport(self, target):
        if target.startswith("["):                   # IPv6
            host, _, rest = target[1:].partition("]")
            port = rest.lstrip(":")
            return host, int(port or 443)
        if ":" in target:
            host, port = target.rsplit(":", 1)
            try:
                return host, int(port)
            except ValueError:
                return target, 443
        return target, 443

    _leaf_counter = [0]

    def _upstream_tls_context(self, host):
        """连上游服务器时用的 TLS 上下文。

        默认**校验证书**（这是实测发现的问题：之前无条件
        CERT_NONE + check_hostname=False，等于静默信任任何证书 ——
        中间人替换、目标证书过期、域名不匹配全都察觉不到）。

        但这是渗透测试工具，打自签证书的靶场是日常操作，硬校验会让
        代理直接不可用。所以：

          * 默认校验（安全）
          * 目标证书有问题时**不静默降级**，而是明确告知并给出开关
          * 需要用 WAF_PROXY_INSECURE=1 显式关闭校验，
            且每次连接都会在日志里写一行提示（不会悄悄发生）
        """
        ctx = ssl.create_default_context()
        insecure = os.environ.get("WAF_PROXY_INSECURE") == "1"
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            # 只提示一次，避免刷屏；但确实留痕了
            if not getattr(self, "_insecure_warned", False):
                self._logger(
                    "警告：WAF_PROXY_INSECURE=1 —— 已关闭上游证书校验，"
                    "无法察觉中间人替换/证书异常。仅用于自签靶场。")
                self._insecure_warned = True
        return ctx

    def _write_temp_leaf(self, host, cert_pem, key_pem):
        """写一份临时叶证书 + 私钥，供 ssl 加载。

        调用方必须在 load_cert_chain 之后立刻 _shred_files() 删掉 ——
        私钥不该在盘上停留超过必要的时间。文件名带进程号 + 计数器，
        避免多实例互相覆盖。
        """
        config.ensure_dirs()
        self._leaf_counter[0] += 1
        tag = "%s-%d-%d" % (host.replace(":", "_").replace("*", "star"),
                            os.getpid(), self._leaf_counter[0])
        cert_file = os.path.join(config.RUN_DIR, "leaf-%s.crt" % tag)
        key_file = os.path.join(config.RUN_DIR, "leaf-%s.key" % tag)
        with open(cert_file, "wb") as fh:
            fh.write(cert_pem)
        _write_key_file(key_file, key_pem)
        return cert_file, key_file

    def _cleanup_stale_leaves(self):
        """清掉上次运行遗留的叶证书私钥（异常退出会留下）。

        只增不删是个攻击面：跑一天攒几十个私钥文件，
        配合已导入信任库的 CA，等于把伪造任意站点证书的原料留在盘上。
        """
        try:
            names = os.listdir(config.RUN_DIR)
        except OSError:
            return 0
        removed = 0
        for name in names:
            if not name.startswith("leaf-"):
                continue
            if not (name.endswith(".crt") or name.endswith(".key")):
                continue
            _shred_files(os.path.join(config.RUN_DIR, name))
            removed += 1
        return removed

    def _is_blocked_connect(self, host, port):
        verdict = self._scan_connect(host, port)
        self._last_verdict = verdict
        if verdict and verdict.blocked:
            with self._lock:
                self._blocked_count += 1
            return True
        return False

    def _scan_connect(self, host, port):
        """CONNECT 阶段只能看到主机名，用它做一次机会性检查。

        必须同样过激活态 gate（实测发现的架构不一致）：
        其它三个扫描入口（普通请求、guard、curl shim）都先问
        ``state.should_intercept()`` —— 控制台关了 / 用户暂停了就放行。
        CONNECT 检查早先漏了这一步，于是会出现"已暂停但它还在拦"
        这类不一致。当前代理寄生于控制台进程、影响面小，
        但一致性要保证 —— 否则代理哪天独立运行就成了真的绕过点。
        """
        if os.environ.get("WAF_CONNECT_SCAN", "1") != "1":
            return None
        try:
            engine = get_engine()
            active, _reason = state.should_intercept(engine)
            if not active:
                return None
        except Exception:
            return None
        target = ScanTarget(kind="request", method="CONNECT",
                            url="%s:%d" % (host, port), host=host,
                            tool="proxy-connect")
        try:
            return engine.scan(target)
        except Exception:
            return None

    # ------------------------------------------------------------ 普通请求

    def _handle_plain(self, client, method, target, version, headers, body,
                      host_hint, port_hint, tls):
        parsed = self._resolve_target(method, target, headers, host_hint,
                                     port_hint, tls)
        if parsed is None:
            self._send_error(client, 400, "Bad Request", "无法解析请求目标")
            return False
        scheme, host, port, path_query = parsed
        path, _, query = path_query.partition("?")

        # 拦截器未开启（或已被暂停）→ 纯转发，不检查不记录。
        engine = get_engine()
        active, _reason = state.should_intercept(engine)
        if not active:
            return self._forward(client, method, scheme, host, port, path_query,
                                 headers, body, version)

        header_dict = {}
        for key, value in headers:
            header_dict[key] = value

        body_text = ""
        if body:
            try:
                body_text = body.decode("utf-8", "replace")
            except Exception:
                body_text = body.decode("latin-1", "replace")

        full_url = "%s://%s%s%s" % (scheme, host,
                                     "" if port in (80, 443) else ":%d" % port,
                                     path_query or "/")
        scan_target = ScanTarget(
            kind="request",
            method=method,
            url=full_url,
            host=host,
            path=path,
            query=query,
            headers=header_dict,
            body=body_text,
            tool="proxy",
            meta={"tls": tls},
        )
        try:
            verdict = get_engine().scan(scan_target)
        except Exception as exc:
            self._logger("扫描异常：%r" % exc)
            verdict = Verdict(blocked=False, reason="引擎异常", stage="engine_error")

        if verdict.blocked:
            with self._lock:
                self._blocked_count += 1
            self._send_block(client, verdict)
            return False               # 拦截后关闭连接，让客户端拿到完整响应

        return self._forward(client, method, scheme, host, port, path_query,
                             headers, body, version)

    def _resolve_target(self, method, target, headers, host_hint, port_hint, tls):
        lower_headers = {k.lower(): v for k, v in headers}
        if target.lower().startswith(("http://", "https://")):
            scheme, rest = target.split("://", 1)
            hostport, _, path_query = rest.partition("/")
            path_query = "/" + path_query if path_query else "/"
            host, _, port_text = hostport.partition(":")
            try:
                port = int(port_text) if port_text else (443 if scheme == "https" else 80)
            except ValueError:
                port = 443 if scheme == "https" else 80
            return scheme, host, port, path_query

        # origin-form：靠 Host 头或 CONNECT 提示
        host_header = lower_headers.get("host", "")
        if host_header:
            host, _, port_text = host_header.partition(":")
            try:
                port = int(port_text) if port_text else (443 if tls else 80)
            except ValueError:
                port = 443 if tls else 80
        elif host_hint:
            host, port = host_hint, (port_hint or (443 if tls else 80))
        else:
            return None
        scheme = "https" if (tls or port == 443) else "http"
        return scheme, host, port, target or "/"

    def _forward(self, client, method, scheme, host, port, path_query,
                 headers, body, version):
        """把请求转发给目标（或上游代理），并把响应回给客户端。"""
        try:
            if self.upstream:
                sock = self._open_tunnel(self.upstream, self.upstream_port)
                # 通过上游代理时使用绝对 URI
                request_line = "%s %s://%s%s HTTP/1.1\r\n" % (
                    method, scheme, host,
                    "" if port in (80, 443) else ":%d" % port, path_query)
                out_headers = _rebuild_headers(headers, host, port, scheme,
                                              absolute=True,
                                              body_len=len(body))
                # 已扫过：这份报文在 _handle 里已经过引擎检查（见上面的
                # engine.scan），转发这一跳不该再被 socket 层扫一遍 ——
                # 重复扫只会多记一条重复事件，还可能因为传输层看到的
                # 字段更少（没有完整 URL，白名单匹配不上）而与这里的
                # 判定不一致。
                with no_socket_scan():
                    sock.sendall((request_line + out_headers).encode("latin-1") + b"\r\n" + body)
                self._relay_response(sock, client, method)
                sock.close()
                return True

            sock = socket.create_connection((host, port), 20)
            if scheme == "https":
                try:
                    ctx = self._upstream_tls_context(host)
                except ssl.SSLError as exc:
                    self._logger("上游 TLS 失败 %s:%s (%r)" % (host, port, exc))
                    sock.close()
                    self._send_error(client, 502, "Bad Gateway",
                                     "TLS 连接失败：%s" % exc)
                    return False
                try:
                    sock = ctx.wrap_socket(sock, server_hostname=host)
                except ssl.SSLError as exc:
                    self._logger("TLS 失败 %s:%s (%r)" % (host, port, exc))
                    sock.close()
                    self._send_error(client, 502, "Bad Gateway",
                                     "TLS 连接失败：%s" % exc)
                    return False

            request_line = "%s %s HTTP/1.1\r\n" % (method, path_query or "/")
            out_headers = _rebuild_headers(headers, host, port, scheme,
                                              absolute=False,
                                              body_len=len(body))
            with no_socket_scan():          # 同上：已在 _handle 里扫过
                sock.sendall((request_line + out_headers).encode("latin-1") + b"\r\n" + body)
            self._relay_response(sock, client, method)
            sock.close()
            return True
        except OSError as exc:
            self._logger("转发失败 %s:%s (%r)" % (host, port, exc))
            self._send_error(client, 502, "Bad Gateway", "上游连接失败：%s" % exc)
            return False

    def _relay_response(self, upstream, client, method):
        """流式回传响应（含 chunked / 无长度的情况）。"""
        reader = _Reader(upstream)
        status_line = reader.read_line()
        if status_line is None:
            self._send_error(client, 502, "Bad Gateway", "上游无响应")
            return
        client.sendall(status_line + b"\r\n")

        content_length = None
        chunked = False
        while True:
            line = reader.read_line()
            if line is None:
                break
            if line == b"" or line == b"\r":
                client.sendall(b"\r\n")
                break
            client.sendall(line + b"\r\n")
            lowered = line.decode("latin-1").lower()
            if lowered.startswith("content-length:"):
                try:
                    content_length = int(lowered.split(":", 1)[1].strip())
                except ValueError:
                    content_length = None
            elif lowered.startswith("transfer-encoding:") and "chunked" in lowered:
                chunked = True

        if method.upper() == "HEAD":
            return
        if chunked:
            reader.read_chunked_to(client)
        elif content_length is not None:
            remaining = content_length
            while remaining > 0:
                chunk = reader.read_exact(min(remaining, 65536))
                if not chunk:
                    break
                client.sendall(chunk)
                remaining -= len(chunk)
        else:
            # 没有长度信息：读到 EOF（Connection: close 场景）
            while True:
                chunk = reader.read_exact(65536)
                if not chunk:
                    break
                client.sendall(chunk)

    # ------------------------------------------------------------ 响应工具

    def _send_block(self, client, verdict):
        payload = verdict.to_json(indent=2, include_meta=True).encode("utf-8")
        head = (
            "HTTP/1.1 %s\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            "Content-Length: %d\r\n"
            "X-HuntGuard: blocked\r\n"
            "Connection: close\r\n\r\n" % (BLOCK_STATUS, len(payload))
        ).encode("latin-1")
        try:
            client.sendall(head + payload)
        except OSError:
            pass

    def _send_error(self, client, code, reason, message):
        payload = json.dumps({"success": False, "blocked": False,
                              "reason": message, "stage": "proxy_error"},
                             ensure_ascii=False, indent=2).encode("utf-8")
        head = (
            "HTTP/1.1 %d %s\r\n"
            "Content-Type: application/json; charset=utf-8\r\n"
            "Content-Length: %d\r\n"
            "X-HuntGuard: error\r\n"
            "Connection: close\r\n\r\n" % (code, reason, len(payload))
        ).encode("latin-1")
        try:
            client.sendall(head + payload)
        except OSError:
            pass

    # ------------------------------------------------------------ 状态

    def status(self):
        with self._lock:
            return {
                "host": self.host,
                "port": self.port,
                "mitm": self.mitm,
                "upstream": ("%s:%s" % (self.upstream, self.upstream_port)
                             if self.upstream else None),
                "connections": self._conn_count,
                "blocked": self._blocked_count,
            }


def _rebuild_headers(headers, host, port, scheme, absolute=False,
                     body_len=None):
    """重建请求头：去掉代理专用头，补 Host，保持顺序。

    ``transfer-encoding`` 必须丢掉（实测发现）：
    调用方在读取请求时**已经把 chunked body 解成裸字节**
    （见 reader.read_chunked()），如果再把这个头原样转发出去，
    上游收到的是"声明 chunked + 实际裸 body" —— 长度解释不一致，
    正是请求走私（HTTP Request Smuggling）的经典形态。

    丢掉之后必须**补上真实的 Content-Length**（``body_len``），
    否则上游根本不知道 body 到哪结束（连接是 close 语义，
    但没有长度声明时很多服务端会直接拒绝或读成空体）。
    传入 body_len 时它优先于原来的 content-length ——
    以我们实际发送的字节数为准，两边必须一致。
    """
    skip = {"proxy-connection", "connection", "keep-alive", "accept-encoding",
            "transfer-encoding", "content-length"}
    out = []
    has_host = False
    for key, value in headers:
        lowered = key.lower()
        if lowered in skip:
            continue
        if lowered == "host":
            has_host = True
        out.append("%s: %s" % (key, value))
    if not has_host:
        default_port = 443 if scheme == "https" else 80
        host_value = host if port == default_port else "%s:%d" % (host, port)
        out.insert(0, "Host: %s" % host_value)
    if body_len is not None:
        out.append("Content-Length: %d" % body_len)
    out.append("Accept-Encoding: identity")          # 便于内容检查/回传
    out.append("Connection: close")
    return "\r\n".join(out) + "\r\n"


# _Reader 的 chunked 直传扩展
def _read_chunked_to(self, out_sock):
    while True:
        line = self.read_line()
        if line is None:
            return
        out_sock.sendall(line + b"\r\n")
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError:
            return
        if size == 0:
            while True:
                trailer = self.read_line()
                if trailer is None:
                    return
                out_sock.sendall(trailer + b"\r\n")
                if trailer == b"":
                    return
        data = self.read_exact(size)
        if len(data) < size:
            return
        out_sock.sendall(data + b"\r\n")


_Reader.read_chunked_to = _read_chunked_to
