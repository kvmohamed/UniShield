"""
UniShield — Outbound transport (analyst side only)

This is the only UniShield module that opens network connections, and it
only connects to destinations ``DestinationPolicy`` allows: allow-listed
analyst-side systems outside ``network.home_networks``. Every delivery:

    1. checks the configured host against the policy before any lookup
       (names must be listed, addresses allow-listed and not monitored);
    2. resolves a listed name and checks every address it returns;
    3. connects to that checked address (pinned), so the connection cannot
       be redirected by a later DNS answer, and never follows redirects or
       proxies (environment proxy variables are not consulted).

Transports: syslog datagrams (UDP), syslog streams (TCP, optionally TLS
with certificate verification, minimum TLS 1.2, optional client
certificate), SMTP (STARTTLS, implicit TLS or plain) and HTTP(S) POST.
Nothing here listens, and nothing is ever sent towards the monitored
network. ``evaluation/passive.py`` allows network calls in this file only
and checks every connection it makes against the same policy at runtime.
"""

from __future__ import annotations

import http.client
import platform
import smtplib
import socket
import ssl
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Iterable, Optional
from urllib.parse import urlsplit

from unishield.export.policy import DestinationPolicy, DestinationRefused, parse_address, webhook_host

__all__ = ["DeliveryError", "DestinationRefused", "TLSSettings", "deliver_datagrams", "deliver_email",
           "deliver_http_post", "deliver_stream", "resolve"]


class DeliveryError(Exception):
    """A delivery to an allowed destination failed (connection, TLS, protocol or HTTP status)."""


@dataclass(frozen=True)
class TLSSettings:
    ca_file: Optional[str] = None       # trust only this CA bundle (default: the system store)
    cert_file: Optional[str] = None     # client certificate for mutual TLS
    key_file: Optional[str] = None
    verify: bool = True                 # verify the server certificate and host name


def tls_context(settings: TLSSettings) -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=settings.ca_file)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    if not settings.verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if settings.cert_file:
        context.load_cert_chain(settings.cert_file, settings.key_file)
    return context


def resolve(policy: DestinationPolicy, host: str, port: int, *, datagram: bool = False,
            label: str = "destination") -> list[str]:
    """Checked addresses for a destination (the policy is applied before and after the lookup)."""
    policy.check_host(host, label)
    literal = parse_address(host)
    if literal is not None:
        addresses = [str(host).strip("[]")]
    else:
        kind = socket.SOCK_DGRAM if datagram else socket.SOCK_STREAM
        try:
            infos = socket.getaddrinfo(host, port, type=kind)
        except OSError as exc:
            raise DeliveryError(f"{label}: cannot resolve {host!r}: {exc}") from exc
        addresses = list(dict.fromkeys(info[4][0] for info in infos))
    for address in addresses:                          # refuse all if any answer is not allowed
        policy.check_address(host, address, label)
    return addresses


def _connect(addresses: Iterable[str], port: int, timeout: float) -> socket.socket:
    last: Optional[OSError] = None
    for address in addresses:
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as exc:
            last = exc
    raise DeliveryError(f"cannot connect to port {port}: {last}") from last


def deliver_datagrams(policy: DestinationPolicy, host: str, port: int, payloads: list[bytes],
                      timeout: float = 5.0, label: str = "destination") -> int:
    """Send each payload as one UDP datagram (RFC 5426 syslog). Returns the number sent."""
    address = resolve(policy, host, port, datagram=True, label=label)[0]
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        for payload in payloads:
            sock.sendto(payload, (address, port))
    return len(payloads)


def deliver_stream(policy: DestinationPolicy, host: str, port: int, payloads: list[bytes], timeout: float = 5.0,
                   tls: Optional[TLSSettings] = None, label: str = "destination") -> int:
    """Write payloads to one TCP (optionally TLS) connection, then close it. Returns the number sent."""
    sock = _connect(resolve(policy, host, port, label=label), port, timeout)
    try:
        if tls is not None:
            try:
                sock = tls_context(tls).wrap_socket(sock, server_hostname=host)
            except (ssl.SSLError, ssl.CertificateError) as exc:
                raise DeliveryError(f"{label}: TLS handshake with {host} failed: {exc}") from exc
        sock.sendall(b"".join(payloads))
        if tls is not None:
            try:
                sock = sock.unwrap()                    # TLS close_notify (RFC 5425 closure)
            except OSError:
                pass                                    # data is written; the peer may close first
    except OSError as exc:
        raise DeliveryError(f"{label}: sending to {host}:{port} failed: {exc}") from exc
    finally:
        sock.close()
    return len(payloads)


class _PinnedSMTP(smtplib.SMTP):
    """SMTP to a checked address; the configured name is kept for STARTTLS certificate checks."""

    def __init__(self, hostname: str, address: str, **kwargs):
        super().__init__(**kwargs)                      # no host: nothing connects yet
        self._host = hostname
        self._address = address

    def _get_socket(self, host, port, timeout):
        return socket.create_connection((self._address, port), timeout, self.source_address)


class _PinnedSMTPSSL(smtplib.SMTP_SSL):
    """Implicit-TLS SMTP to a checked address."""

    def __init__(self, hostname: str, address: str, **kwargs):
        super().__init__(**kwargs)
        self._host = hostname
        self._address = address

    def _get_socket(self, host, port, timeout):
        sock = socket.create_connection((self._address, port), timeout, self.source_address)
        return self.context.wrap_socket(sock, server_hostname=self._host)


def deliver_email(policy: DestinationPolicy, message: EmailMessage, *, host: str, port: int,
                  security: str = "starttls", tls: TLSSettings = TLSSettings(), username: Optional[str] = None,
                  password: Optional[str] = None, timeout: float = 10.0, helo_name: Optional[str] = None,
                  label: str = "SMTP relay") -> None:
    """Submit one message to the configured relay (``security``: starttls, ssl or none)."""
    address = resolve(policy, host, port, label=label)[0]
    helo = helo_name or platform.node() or "unishield"   # explicit: avoids a reverse DNS lookup
    context = tls_context(tls)
    try:
        if security == "ssl":
            smtp: smtplib.SMTP = _PinnedSMTPSSL(host, address, local_hostname=helo, timeout=timeout, context=context)
        else:
            smtp = _PinnedSMTP(host, address, local_hostname=helo, timeout=timeout)
        with smtp:
            code, reply = smtp.connect(host, port)
            if code != 220:
                raise DeliveryError(f"{label}: relay greeting {code} {reply!r}")
            smtp.ehlo()
            if security == "starttls":
                smtp.starttls(context=context)
                smtp.ehlo()
            if username:
                smtp.login(username, password or "")
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise DeliveryError(f"{label}: {type(exc).__name__}: {exc}") from exc


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float):
        super().__init__(host, port, timeout=timeout)
        self._address = address

    def connect(self):
        self.sock = socket.create_connection((self._address, self.port), self.timeout, self.source_address)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, address: str, timeout: float, context: ssl.SSLContext):
        super().__init__(host, port, timeout=timeout, context=context)
        self._address = address
        self._tls = context

    def connect(self):
        sock = socket.create_connection((self._address, self.port), self.timeout, self.source_address)
        self.sock = self._tls.wrap_socket(sock, server_hostname=self.host)


def deliver_http_post(policy: DestinationPolicy, url: str, body: bytes, headers: dict[str, str],
                      timeout: float = 10.0, tls: TLSSettings = TLSSettings(), label: str = "webhook") -> int:
    """POST ``body`` to ``url``; returns the HTTP status (2xx), raises DeliveryError otherwise. No redirects."""
    scheme, host, port = webhook_host(url)
    parts = urlsplit(url)
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    address = resolve(policy, host, port, label=label)[0]
    if scheme == "https":
        conn: http.client.HTTPConnection = _PinnedHTTPSConnection(host, port, address, timeout, tls_context(tls))
    else:
        conn = _PinnedHTTPConnection(host, port, address, timeout)
    try:
        conn.request("POST", target, body=body, headers=headers)
        response = conn.getresponse()
        response.read(65536)
        status = response.status
    except (OSError, http.client.HTTPException) as exc:
        raise DeliveryError(f"{label}: {type(exc).__name__}: {exc}") from exc
    finally:
        conn.close()
    if not 200 <= status < 300:
        raise DeliveryError(f"{label}: HTTP {status} from {host}")
    return status
