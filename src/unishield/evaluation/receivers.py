"""
UniShield — Loopback receivers for verifying outbound delivery

Minimal syslog (UDP, TCP with octet counting), SMTP and HTTP receivers that
listen on 127.0.0.1 only. The passive-mode runtime check and the tests point
the export/notification outputs at them to exercise the real transport code
under the socket tripwire without touching any other host. They accept
connections; they never open one.

``wrap`` (TCP and SMTP) takes a function applied to each accepted socket,
so tests can add TLS without this module importing ssl.
"""

from __future__ import annotations

import base64
import http.server
import socketserver
import threading
from typing import Any, Callable, Optional

LOOPBACK = "127.0.0.1"


class _Server:
    server: socketserver.BaseServer

    def _start(self) -> None:
        self._thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                                        daemon=True)
        self._thread.start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(5)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.stop()
        return False


class UdpSyslogReceiver(_Server):
    """Collects one message per datagram."""

    def __init__(self):
        self.messages: list[bytes] = []
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                outer.messages.append(self.request[0])

        self.server = socketserver.ThreadingUDPServer((LOOPBACK, 0), Handler)
        self._start()


def parse_octet_frames(data: bytes) -> list[bytes]:
    """Split an RFC 6587 octet-counted stream into messages."""
    messages = []
    while data:
        length, _, rest = data.partition(b" ")
        n = int(length)
        messages.append(rest[:n])
        data = rest[n:]
    return messages


class _WrappingTCPServer(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, handler, wrap: Optional[Callable] = None):
        self.wrap = wrap
        super().__init__((LOOPBACK, 0), handler)

    def get_request(self):
        sock, address = super().get_request()
        return (self.wrap(sock) if self.wrap else sock), address


class TcpSyslogReceiver(_Server):
    """Collects octet-counted messages from each connection."""

    def __init__(self, wrap: Optional[Callable] = None):
        self.messages: list[bytes] = []
        self.connections = 0
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                outer.connections += 1
                data = b""
                try:
                    while chunk := self.rfile.read1(65536):
                        data += chunk
                except OSError:                     # e.g. a TLS peer closing without close_notify
                    pass
                outer.messages.extend(parse_octet_frames(data))

        self.server = _WrappingTCPServer(Handler, wrap)
        self._start()


class SmtpReceiver(_Server):
    """Accepts mail like a relay (EHLO, optional AUTH PLAIN, MAIL, RCPT, DATA, QUIT) and keeps it."""

    def __init__(self, wrap: Optional[Callable] = None):
        self.messages: list[dict[str, Any]] = []
        self.logins: list[tuple[str, str]] = []
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def reply(self, line: str) -> None:
                self.wfile.write(line.encode("ascii") + b"\r\n")

            def handle(self):
                envelope: dict[str, Any] = {"rcpt": []}
                self.reply("220 localhost UniShield test receiver")
                while True:
                    line = self.rfile.readline()
                    if not line:
                        return
                    command = line.decode("utf-8", "replace").strip()
                    verb = command.split(" ", 1)[0].upper()
                    if verb in ("EHLO", "HELO"):
                        self.reply("250-localhost")
                        self.reply("250 AUTH PLAIN")
                    elif verb == "AUTH":
                        parts = base64.b64decode(command.split()[-1]).split(b"\0")
                        _authzid, user, password = (parts + [b"", b"", b""])[:3]
                        outer.logins.append((user.decode(), password.decode()))
                        self.reply("235 2.7.0 Authentication successful")
                    elif verb == "MAIL":
                        envelope["from"] = command[10:].strip("<> ")
                        self.reply("250 OK")
                    elif verb == "RCPT":
                        envelope["rcpt"].append(command[8:].strip("<> "))
                        self.reply("250 OK")
                    elif verb == "DATA":
                        self.reply("354 End data with <CR><LF>.<CR><LF>")
                        body = []
                        while (chunk := self.rfile.readline()) not in (b".\r\n", b""):
                            body.append(chunk)
                        envelope["data"] = b"".join(body)
                        outer.messages.append(envelope)
                        envelope = {"rcpt": []}
                        self.reply("250 OK queued")
                    elif verb == "QUIT":
                        self.reply("221 Bye")
                        return
                    else:
                        self.reply("502 Command not implemented")

        self.server = _WrappingTCPServer(Handler, wrap)
        self._start()


class HttpReceiver(_Server):
    """Records POST requests and answers with ``status``."""

    def __init__(self, status: int = 200):
        self.requests: list[dict[str, Any]] = []
        self.status = status
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", 0))
                outer.requests.append({"path": self.path, "headers": dict(self.headers),
                                       "body": self.rfile.read(length)})
                self.send_response(outer.status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, *args):
                pass

        self.server = http.server.ThreadingHTTPServer((LOOPBACK, 0), Handler)
        self._start()
