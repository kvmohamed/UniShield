"""Static security checks of the dashboard page."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.security


def test_dashboard_has_no_html_injection_sinks_or_external_resources():
    import re
    from pathlib import Path

    import unishield

    html = (Path(unishield.__file__).parent / "dashboard" / "index.html").read_text(encoding="utf-8")
    script = html.split("<script>", 1)[1]
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert sink not in script, sink
    urls = set(re.findall(r"https?://[^\s\"'`)]+", html))
    assert urls <= {"https://attack.mitre.org/techniques/", "http://www.w3.org/2000/svg"}, urls
    assert "This system is a passive defensive research prototype. It does not probe, block, decrypt, " \
           "or send commands to monitored systems." in html


def _page():
    from pathlib import Path

    import unishield

    html = (Path(unishield.__file__).parent / "dashboard" / "index.html").read_text(encoding="utf-8")
    return html, html.split("<script>", 1)[1]


def test_dashboard_shows_outputs_intel_and_intel_matches():
    html, script = _page()
    assert '"INTEL_MATCH"' in script
    for element in ('id="outputs"', 'id="out-syslog"', 'id="out-notify"', 'id="intel"', 'id="intel-sources"',
                    'id="intel-imports"'):
        assert element in html, element
    assert "renderOutputs(body.outputs" in script and "renderIntel(body.intel" in script
    assert "evidence || {}).intel_matches" in script and "Threat-intelligence matches" in script
    assert "nothing is ever sent into the monitored network" in html


def test_dashboard_login_keeps_credentials_out_of_page_storage():
    html, script = _page()
    for store in ("localStorage", "sessionStorage", "indexedDB", "document.cookie", "X-API-Key"):
        assert store not in script, store
    assert 'headers["X-CSRF-Token"] = state.me.csrf_token' in script
    assert 'credentials: "same-origin"' in script
    assert 'id="login-pass" name="password" type="password" autocomplete="current-password"' in html
    for field in ("nu-pass", "rp-pass", "pw-current", "pw-new", "pw-repeat"):
        assert f'id="{field}" type="password"' in html, field
    # administrative controls and data views start hidden until /auth/me says otherwise
    for element in ('id="run-card" hidden', 'id="main" hidden', 'data-tab="admin" aria-selected="false" hidden'):
        assert element in html, element
    assert script.count("e.preventDefault()") >= 4            # forms never submit (CSP form-action 'none')
