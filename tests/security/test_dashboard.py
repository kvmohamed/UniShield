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
