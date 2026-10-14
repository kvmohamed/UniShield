"""
UniShield — TLS handshake metadata parser

Extracts the TLS version and cipher suite from plaintext ClientHello /
ServerHello messages. These handshake messages are sent unencrypted by
design; nothing here decrypts or inspects application data.

Why not the record header: TLS 1.2 and 1.3 clients normally put the legacy
value 0x0301 ("TLS 1.0") in the record header and 0x0303 in the hello's
legacy_version field. The real version is in the supported_versions
extension (RFC 8446 §4.2.1): the client lists what it offers, the server
states what it selected.

Limitation: a hello split across several TCP segments is not reassembled;
such packets yield None.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

_VERSION_NAMES = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}

# Common cipher suites (IANA names); anything else is reported as hex.
_CIPHER_NAMES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
}

_CONTENT_HANDSHAKE = 0x16
_CLIENT_HELLO = 1
_SERVER_HELLO = 2
_EXT_SUPPORTED_VERSIONS = 0x002B


@dataclass(frozen=True)
class TLSHello:
    """Metadata from one hello message."""
    kind: str                     # "client" or "server"
    version: Optional[str]        # client: highest offered; server: selected
    cipher: Optional[str] = None  # server only: selected cipher suite


def _is_grease(value: int) -> bool:
    """GREASE placeholders (RFC 8701) look like 0x0A0A, 0x1A1A, ... 0xFAFA."""
    return (value & 0x0F0F) == 0x0A0A


def version_name(code: int) -> str:
    return _VERSION_NAMES.get(code, f"0x{code:04x}")


def cipher_name(code: int) -> str:
    return _CIPHER_NAMES.get(code, f"0x{code:04x}")


def parse_tls_hello(payload: bytes) -> Optional[TLSHello]:
    """
    Parse a TCP payload that starts with a TLS handshake record.

    Returns None if the payload is not a complete ClientHello/ServerHello.
    """
    try:
        if len(payload) < 9 or payload[0] != _CONTENT_HANDSHAKE or payload[1] != 0x03:
            return None
        record_len = int.from_bytes(payload[3:5], "big")
        body = payload[5:5 + record_len]
        hs_type = body[0]
        if hs_type not in (_CLIENT_HELLO, _SERVER_HELLO):
            return None
        hs_len = int.from_bytes(body[1:4], "big")
        if 4 + hs_len > len(body):
            return None  # hello continues in a later segment
        p = 4
        legacy_version = int.from_bytes(body[p:p + 2], "big")
        p += 2 + 32                                  # version + random
        p += 1 + body[p]                             # session id
        selected_cipher = None
        if hs_type == _CLIENT_HELLO:
            p += 2 + int.from_bytes(body[p:p + 2], "big")   # cipher suites
            p += 1 + body[p]                                  # compression methods
        else:
            selected_cipher = int.from_bytes(body[p:p + 2], "big")
            p += 2 + 1                                        # cipher + compression

        version = legacy_version
        end = 4 + hs_len
        if p + 2 <= end:
            ext_end = min(p + 2 + int.from_bytes(body[p:p + 2], "big"), end)
            p += 2
            while p + 4 <= ext_end:
                ext_type = int.from_bytes(body[p:p + 2], "big")
                ext_len = int.from_bytes(body[p + 2:p + 4], "big")
                data = body[p + 4:p + 4 + ext_len]
                p += 4 + ext_len
                if ext_type != _EXT_SUPPORTED_VERSIONS:
                    continue
                if hs_type == _CLIENT_HELLO:
                    offered = [
                        int.from_bytes(data[i:i + 2], "big")
                        for i in range(1, 1 + data[0], 2)
                    ]
                    offered = [v for v in offered if not _is_grease(v)]
                    if offered:
                        version = max(offered)
                elif len(data) >= 2:
                    version = int.from_bytes(data[:2], "big")

        if hs_type == _CLIENT_HELLO:
            return TLSHello(kind="client", version=version_name(version))
        return TLSHello(
            kind="server",
            version=version_name(version),
            cipher=cipher_name(selected_cipher) if selected_cipher is not None else None,
        )
    except (IndexError, ValueError):
        return None


def build_client_hello(versions: list[int], ciphers: list[int] | None = None) -> bytes:
    """Build a minimal ClientHello record (for tests and sample files)."""
    ciphers = ciphers or [0x1301, 0xC02F]
    sv = bytes([2 * len(versions)]) + b"".join(v.to_bytes(2, "big") for v in versions)
    ext = _EXT_SUPPORTED_VERSIONS.to_bytes(2, "big") + len(sv).to_bytes(2, "big") + sv
    cs = b"".join(c.to_bytes(2, "big") for c in ciphers)
    hello = (
        (0x0303).to_bytes(2, "big") + bytes(32) + b"\x00"
        + len(cs).to_bytes(2, "big") + cs + b"\x01\x00"
        + len(ext).to_bytes(2, "big") + ext
    )
    hs = bytes([_CLIENT_HELLO]) + len(hello).to_bytes(3, "big") + hello
    return bytes([_CONTENT_HANDSHAKE, 0x03, 0x01]) + len(hs).to_bytes(2, "big") + hs


def build_server_hello(version: int, cipher: int) -> bytes:
    """Build a minimal ServerHello record (for tests and sample files)."""
    sv = version.to_bytes(2, "big")
    ext = _EXT_SUPPORTED_VERSIONS.to_bytes(2, "big") + len(sv).to_bytes(2, "big") + sv
    hello = (
        (0x0303).to_bytes(2, "big") + bytes(32) + b"\x00"
        + cipher.to_bytes(2, "big") + b"\x00"
        + len(ext).to_bytes(2, "big") + ext
    )
    hs = bytes([_SERVER_HELLO]) + len(hello).to_bytes(3, "big") + hello
    return bytes([_CONTENT_HANDSHAKE, 0x03, 0x03]) + len(hs).to_bytes(2, "big") + hs
