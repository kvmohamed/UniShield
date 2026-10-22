# Test-only TLS material

`test-server.crt` / `test-server.key` are a self-signed certificate and its
private key for `localhost` / `127.0.0.1`, used only by the tests to run
local TLS syslog and SMTPS receivers. They protect nothing; never use them
outside the test suite. Regenerate with:

    openssl req -x509 -newkey rsa:2048 -nodes -keyout test-server.key -out test-server.crt -days 7300 \
      -subj "/CN=localhost/O=UniShield test fixture" \
      -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "basicConstraints=critical,CA:TRUE"
