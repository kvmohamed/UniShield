"""Unit tests for the TLS hello parser (audit defect D15)."""

from __future__ import annotations

from unishield.ingest.tls import (
    build_client_hello,
    build_server_hello,
    cipher_name,
    parse_tls_hello,
)


def test_client_hello_reports_highest_offered_version():
    hello = parse_tls_hello(build_client_hello([0x0303, 0x0304]))
    assert hello.kind == "client"
    assert hello.version == "TLSv1.3"
    assert hello.cipher is None


def test_grease_values_ignored():
    hello = parse_tls_hello(build_client_hello([0x1A1A, 0x0303, 0xFAFA]))
    assert hello.version == "TLSv1.2"


def test_record_header_version_not_used():
    """Modern clients write 0x0301 in the record header; that is not TLS 1.0."""
    record = build_client_hello([0x0304])
    assert record[1:3] == b"\x03\x01"
    assert parse_tls_hello(record).version == "TLSv1.3"


def test_server_hello_selected_version_and_cipher():
    hello = parse_tls_hello(build_server_hello(0x0304, 0x1302))
    assert hello.kind == "server"
    assert hello.version == "TLSv1.3"
    assert hello.cipher == "TLS_AES_256_GCM_SHA384"


def test_unknown_cipher_reported_as_hex():
    assert cipher_name(0xABCD) == "0xabcd"
    assert parse_tls_hello(build_server_hello(0x0303, 0xABCD)).cipher == "0xabcd"


def test_legacy_hello_without_extensions():
    body = (0x0301).to_bytes(2, "big") + bytes(32) + b"\x00" + b"\x00\x02\x00\x2f" + b"\x01\x00"
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    assert parse_tls_hello(record).version == "TLSv1.0"


def test_truncated_and_non_tls_payloads_return_none():
    full = build_client_hello([0x0304])
    assert parse_tls_hello(full[:30]) is None
    assert parse_tls_hello(b"GET / HTTP/1.1\r\n") is None
    assert parse_tls_hello(b"\x17\x03\x03\x00\x10" + bytes(16)) is None   # application data
    assert parse_tls_hello(b"") is None
