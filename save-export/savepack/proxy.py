"""临时 hosts + 反向代理，截获官方登录表单。

原理：游戏网关走的是**明文 HTTP**。把网关域名临时指到 127.0.0.1，
本地 80 端口起一个透明代理，把请求原样转发给真网关，同时记下
`Index/getUidPC` 的请求体（openid / sid / ticket）。

安全边界：
  * 只代理白名单里的那一个域名；
  * 转发目标在**改 hosts 之前**解析并校验，必须是公网地址；
  * 退出时（含异常）恢复 hosts 原文。
"""
from __future__ import annotations

import http.client
import ipaddress
import os
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .contract import PackError
from .live import HOST, assert_public_host

MARK = "# GFSAVEPACK-TEMP"
CAPTURE_PATH_KEY = "getUidPC"


# ---------------------------------------------------------------- hosts
def hosts_file() -> Path:
    root = os.environ.get("SystemRoot") or r"C:\Windows"
    return Path(root) / "System32" / "drivers" / "etc" / "hosts"


def is_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def resolve_gateway() -> str:
    """解析网关 IP。必须在改 hosts 之前调用，否则会解析到 127.0.0.1。"""
    assert_public_host(HOST)
    infos = socket.getaddrinfo(HOST, 80, type=socket.SOCK_STREAM)
    for _fam, _typ, _proto, _canon, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            continue
        return str(ip)
    raise PackError("网关没有解析到公网地址")


_CTRL_HOOK = None    # 必须保住回调引用，否则会被 GC 掉


def install_close_handler(restore) -> None:
    """点 X 关窗口 / 注销 / 关机时也把 hosts 还原。

    Windows 收到 CTRL_CLOSE_EVENT 后会给进程几秒钟善后，够把文件写回去。
    这是「用户直接把窗口关掉」这一最坏情况下的兜底。
    """
    global _CTRL_HOOK
    if os.name != "nt" or _CTRL_HOOK is not None:
        return
    try:
        import ctypes
        from ctypes import wintypes

        @ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.DWORD)
        def handler(event):
            if event in (2, 5, 6):      # CLOSE / LOGOFF / SHUTDOWN
                try:
                    restore()
                except Exception:       # noqa: BLE001
                    pass
            return True

        _CTRL_HOOK = handler
        ctypes.windll.kernel32.SetConsoleCtrlHandler(handler, True)
    except Exception:  # noqa: BLE001
        pass


class HostsGuard:
    """临时写入一条 hosts 记录，退出时整文件恢复。"""

    def __init__(self):
        self.path = hosts_file()
        self.original = None
        self.written = None

    def __enter__(self):
        try:
            self.original = self.path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise PackError("读不到 hosts 文件（需要管理员权限）：%s" % exc) from exc
        base = "\n".join(
            line for line in self.original.splitlines()
            if MARK not in line and HOST not in line)
        self.written = (base.rstrip() + "\n"
                        + "127.0.0.1\t%s\t%s\n" % (HOST, MARK))
        self._apply(self.written)
        install_close_handler(lambda: self._apply(self.original))
        return self

    def _apply(self, text: str) -> None:
        try:
            self.path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise PackError("写不了 hosts 文件（需要管理员权限）：%s" % exc) from exc

    def __exit__(self, *_exc):
        if self.original is not None:
            try:
                self._apply(self.original)
            except PackError:
                pass
        return False


# ---------------------------------------------------------------- 代理
class _QuietServer(ThreadingHTTPServer):
    """客户端登录过程中断开连接是常态，不要每次都打一屏堆栈。

    `allow_reuse_address = False` 很关键：Windows 的 SO_REUSEADDR 允许
    两个 socket 绑同一地址，绑上了却把连接分给另一个（已关闭的）socket，
    表现就是「绑定成功但连上立刻被 RST」。
    """

    allow_reuse_address = False
    owner = None

    def handle_error(self, request, client_address):
        import traceback
        tb = traceback.format_exc().strip().splitlines()
        if self.owner is not None:
            self.owner.note("server error: %s" % (tb[-1] if tb else "?"))


def _make_handler(state: "CaptureServer"):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):   # 静默，别刷屏
            pass

        def do_GET(self):
            self._relay("GET")

        def do_POST(self):
            self._relay("POST")

        def _read_body(self) -> bytes:
            te = (self.headers.get("Transfer-Encoding") or "").lower()
            if "chunked" in te:
                chunks = []
                while True:
                    line = self.rfile.readline(65536).strip()
                    if not line:
                        break
                    try:
                        size = int(line.split(b";")[0], 16)
                    except ValueError:
                        break
                    if size == 0:
                        self.rfile.readline(65536)
                        break
                    chunks.append(self.rfile.read(size))
                    self.rfile.read(2)     # 每个 chunk 尾部的 CRLF
                return b"".join(chunks)
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            return self.rfile.read(length) if length > 0 else b""

        def _relay(self, method: str) -> None:
            try:
                self._relay_inner(method)
            except Exception as exc:  # noqa: BLE001
                import traceback
                tb = traceback.format_exc().strip().splitlines()
                state.note("转发异常 %s: %s | %s"
                           % (type(exc).__name__, exc, tb[-1] if tb else ""))
                try:
                    self.send_error(502, "proxy error")
                except Exception:  # noqa: BLE001
                    pass

        def _relay_inner(self, method: str) -> None:
            body = self._read_body()

            hit = CAPTURE_PATH_KEY in self.path
            if hit and body:
                state.record_request(body)

            headers = {k: v for k, v in self.headers.items()
                       if k.lower() not in ("host", "connection",
                                            "content-length",
                                            "transfer-encoding",
                                            "proxy-connection", "expect")}
            headers["Host"] = HOST

            status, hdrs, data = 502, [], b""
            try:
                conn = http.client.HTTPConnection(state.gateway_ip, 80, timeout=30)
                try:
                    conn.request(method, self.path, body, headers)
                    resp = conn.getresponse()
                    status = resp.status
                    hdrs = resp.getheaders()
                    data = resp.read()
                finally:
                    conn.close()
            except Exception:  # noqa: BLE001  上游失败就回 502，客户端会重试
                pass

            if hit and data:
                state.record_response(data)
            state.note("%s %s -> %s %dB"
                       % (method, self.path[:70], status, len(data)))

            try:
                self.send_response(status)
                for key, value in hdrs:
                    if key.lower() in ("transfer-encoding", "content-length",
                                       "connection", "keep-alive"):
                        continue
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if data:
                    self.wfile.write(data)
            except OSError:
                pass

    return Handler


class CaptureServer:
    """本地 80 端口反向代理；把 getUidPC 的请求体和响应都收集起来。

    只截响应、不重放请求：ticket 可能一次性、req_id 会被服务端去重，
    原样再发一次很可能被拒。客户端自己登录成功的那次响应才是有效凭据。
    """

    def __init__(self, gateway_ip: str, port: int = 80):
        self.gateway_ip = gateway_ip
        self.port = port
        self.requests = []
        self.responses = []
        self.events = []
        self._lock = threading.Lock()
        self._httpd = None
        self._thread = None

    def note(self, text: str) -> None:
        with self._lock:
            self.events.append(text)
            if len(self.events) > 200:
                del self.events[:-200]

    def events_snapshot(self):
        with self._lock:
            return list(self.events)

    def probe(self) -> None:
        """起代理后自检：用公开的 version 接口确认整条转发链可用。

        失败就抛错 —— 这样 hosts 根本不会被改写，不会把游戏卡住。
        """
        body = "=&req_id=%d001" % int(time.time())
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=25)
        try:
            conn.request("POST", "/index.php/1000/Index/version", body, {
                "Host": HOST,
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Unity-Version": "2018.4.36f1",
            })
            resp = conn.getresponse()
            data = resp.read()
            code = resp.status
        finally:
            conn.close()
        if code != 200 or not data:
            raise PackError("本地代理自检失败（HTTP %s，%d 字节）。\n"
                            "  没有改 hosts，游戏不受影响。"
                            % (code, len(data)))

    def record_request(self, body: bytes) -> None:
        with self._lock:
            self.requests.append(body)

    def record_response(self, data: bytes) -> None:
        with self._lock:
            self.responses.append(data)

    def responses_snapshot(self):
        with self._lock:
            return list(self.responses)

    def request_count(self) -> int:
        with self._lock:
            return len(self.requests)

    def start(self) -> None:
        try:
            self._httpd = _QuietServer(
                ("127.0.0.1", self.port), _make_handler(self))
            self._httpd.owner = self
        except OSError as exc:
            raise PackError(
                "本地 %d 端口起不来（%s）。\n"
                "  常见原因：IIS / 其他 web 服务占着 80，先停掉再试。"
                % (self.port, exc)) from exc
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(
            target=self._httpd.serve_forever, kwargs={"poll_interval": 0.2},
            daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd is not None:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:  # noqa: BLE001
                pass
            self._httpd = None

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_exc):
        self.stop()
        return False
