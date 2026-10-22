"""HTTPS configuration: uvicorn TLS options, proxy trust, HSTS only on HTTPS responses."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_PASSWORD
from unishield.config import UnishieldConfig, get_config, reset_config
from unishield.main import StartupError, uvicorn_options

pytestmark = pytest.mark.security


def test_plain_http_options_trust_only_loopback_proxies():
    options = uvicorn_options(UnishieldConfig())
    assert options["proxy_headers"] is True and options["forwarded_allow_ips"] == "127.0.0.1"
    assert "ssl_certfile" not in options and options["timeout_graceful_shutdown"] == 15
    assert options["host"] == "127.0.0.1" and options["reload"] is False


def test_tls_options_from_configuration(tmp_path):
    cert, key = tmp_path / "unishield.crt", tmp_path / "unishield.key"
    cert.write_text("-----BEGIN CERTIFICATE-----\n", encoding="ascii")
    key.write_text("-----BEGIN PRIVATE KEY-----\n", encoding="ascii")
    config = UnishieldConfig(tls={"certfile": str(cert), "keyfile": str(key), "keyfile_password": "pw"},
                             api={"host": "0.0.0.0", "port": 8443, "forwarded_allow_ips": "10.0.0.2"})
    options = uvicorn_options(config)
    assert options["ssl_certfile"] == str(cert) and options["ssl_keyfile"] == str(key)
    assert options["ssl_keyfile_password"] == "pw" and options["forwarded_allow_ips"] == "10.0.0.2"
    assert "pw" not in repr(config.tls)


def test_tls_files_must_exist(tmp_path):
    config = UnishieldConfig(tls={"certfile": str(tmp_path / "missing.crt")})
    with pytest.raises(StartupError, match="tls.certfile"):
        uvicorn_options(config)
    with pytest.raises(ValueError, match="tls.certfile is not"):
        UnishieldConfig(tls={"keyfile": "x.key"})


def test_tls_settings_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("UNISHIELD_TLS_CERTFILE", "/etc/unishield/tls/cert.pem")
    monkeypatch.setenv("UNISHIELD_TLS_KEYFILE", "/etc/unishield/tls/key.pem")
    monkeypatch.setenv("UNISHIELD_TLS_KEYFILE_PASSWORD", "from-env")
    monkeypatch.setenv("UNISHIELD_FORWARDED_ALLOW_IPS", "192.0.2.10")
    reset_config()
    try:
        config = get_config()
        assert config.tls.enabled and config.tls.keyfile_password == "from-env"
        assert config.api.forwarded_allow_ips == "192.0.2.10"
    finally:
        reset_config()


def test_hsts_only_on_https_responses(api_client, monkeypatch):
    client, _ = api_client
    assert "strict-transport-security" not in {k.lower() for k in client.get("/health").headers}
    https = TestClient(client.app, base_url="https://testserver")
    assert https.get("/health").headers["Strict-Transport-Security"] == "max-age=31536000"
    assert https.get("/dashboard").headers["Strict-Transport-Security"] == "max-age=31536000"
    monkeypatch.setattr(get_config().tls, "hsts_include_subdomains", True)
    assert https.get("/health").headers["Strict-Transport-Security"] == "max-age=31536000; includeSubDomains"
    monkeypatch.setattr(get_config().tls, "hsts_max_age", 0)
    assert "strict-transport-security" not in {k.lower() for k in https.get("/health").headers}


def test_https_login_gets_a_secure_cookie_and_hsts(api_client):
    client, _ = api_client
    https = TestClient(client.app, base_url="https://testserver")
    response = https.post("/auth/login", json={"username": "admin", "password": TEST_PASSWORD})
    assert response.status_code == 200
    assert "; secure" in response.headers["set-cookie"].lower()
    assert response.headers["Strict-Transport-Security"].startswith("max-age=")
