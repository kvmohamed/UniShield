"""
UniShield — Passive-Mode Verification

Two independent checks that UniShield only reads from the monitored network
and only sends to allow-listed analyst-side destinations:

Static (AST) scan of every module under ``src/unishield``:
    - imports of networking, process, HTTP-client, crypto or remote-shell
      modules that the code base has no reason to use
    - calls that send or capture packets (scapy send/sendp/sr/sr1/srp/
      sniff/AsyncSniffer...), open outbound connections
      (socket.connect/sendto/create_connection, urlopen) or run commands
      (os.system, subprocess)
    - scoped allowance: ``unishield/export/transport.py`` (the analyst-side
      export/notifier transport) may import socket/ssl/smtplib/http.client
      and call connect/create_connection/sendto/sendall. Every allowed
      occurrence is listed in the report; anything else in that file (and
      the same names anywhere else) is still a finding.

Runtime tripwire: socket connect/send/DNS-resolution functions and scapy's
send and capture functions are replaced by functions that record the
attempt and raise. Code running inside the outbound transport (found by
walking the call stack) may only reach addresses the destination policy
permits — allow-listed and outside ``network.home_networks``; every other
caller may only use loopback (event-loop internals). Under the tripwire the
pipeline runs over every supported input format with threat intelligence
loaded, the API handles a login, a replay and a demo and the read
endpoints, and the export/notification outputs deliver to loopback
receivers. Three probes must be refused: a monitored-network destination at
config load, at send time, and at socket level with the policy check
bypassed. Any other recorded attempt fails the check.

Neither check can prove the absence of every possible network effect (for
example from third-party libraries' internals), but together they show
that UniShield's own code paths contain no network capability outside the
transport, exercise none, and that the transport reaches only allowed
analyst-side destinations.
"""

from __future__ import annotations

import ast
import os
import secrets
import socket
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

FORBIDDEN_MODULES = {
    "subprocess", "requests", "urllib.request", "http.client", "httpx", "aiohttp", "paramiko", "telnetlib",
    "ftplib", "smtplib", "ssl", "cryptography", "Crypto", "nmap", "pexpect", "asyncssh",
}
FORBIDDEN_CALLS = {
    # scapy active / capture functions
    "send", "sendp", "sendpfast", "sr", "sr1", "srp", "srp1", "srloop", "srploop", "sniff", "AsyncSniffer",
    "traceroute", "arping", "send_raw",
    # sockets and HTTP
    "connect", "connect_ex", "sendto", "sendall", "create_connection", "urlopen",
    # processes
    "system", "popen", "Popen", "spawnl", "execv", "execve",
}
# Receiver.method calls that share a forbidden name but are local: SQLAlchemy
# engines connect to the configured database (SQLite file by default).
ALLOWED_DOTTED_CALLS = {"self.engine.connect", "engine.connect"}

# The one module allowed to open outbound connections (analyst side only),
# and exactly what it may use.
OUTBOUND_MODULE = "unishield/export/transport.py"
OUTBOUND_ALLOWED_IMPORTS = {"socket", "ssl", "smtplib", "http.client"}
OUTBOUND_ALLOWED_CALLS = {"connect", "create_connection", "sendto", "sendall"}


@dataclass
class StaticFinding:
    file: str
    line: int
    kind: str
    name: str


@dataclass
class PassiveReport:
    static_findings: list[StaticFinding] = field(default_factory=list)
    scoped_allowances: list[StaticFinding] = field(default_factory=list)
    files_scanned: int = 0
    runtime_attempts: list[str] = field(default_factory=list)
    runtime_exercised: list[str] = field(default_factory=list)
    runtime_outbound: list[str] = field(default_factory=list)
    runtime_refusals: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.static_findings and not self.runtime_attempts

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "files_scanned": self.files_scanned,
            "static_findings": [f.__dict__ for f in self.static_findings],
            "scoped_allowance": {
                "module": OUTBOUND_MODULE,
                "allowed_imports": sorted(OUTBOUND_ALLOWED_IMPORTS),
                "allowed_calls": sorted(OUTBOUND_ALLOWED_CALLS),
                "occurrences": [f.__dict__ for f in self.scoped_allowances],
            },
            "runtime_attempts": self.runtime_attempts,
            "runtime_exercised": self.runtime_exercised,
            "runtime_outbound_allowed": self.runtime_outbound,
            "runtime_expected_refusals": self.runtime_refusals,
        }


def _dotted(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _call_name(node: ast.Call) -> tuple[str | None, str | None]:
    """(dotted call path, final name) of a call."""
    func = node.func
    if isinstance(func, ast.Name):
        return func.id, func.id
    if isinstance(func, ast.Attribute):
        return _dotted(func), func.attr
    return None, None


def scan_with_allowances(root: Path | None = None) -> tuple[list[StaticFinding], list[StaticFinding], int]:
    """(findings, scoped allowances used by the outbound transport, files scanned)."""
    import unishield

    root = root or Path(unishield.__file__).parent
    findings: list[StaticFinding] = []
    allowances: list[StaticFinding] = []
    files = sorted(root.rglob("*.py"))
    for path in files:
        rel = path.relative_to(root.parent).as_posix()
        outbound = rel == OUTBOUND_MODULE
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))

        def report(kind: str, name: str, line: int, allowed: bool) -> None:
            (allowances if allowed else findings).append(StaticFinding(rel, line, kind, name))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in FORBIDDEN_MODULES or alias.name.split(".")[0] in FORBIDDEN_MODULES:
                        report("import", alias.name, node.lineno, outbound and alias.name in OUTBOUND_ALLOWED_IMPORTS)
                    elif outbound and alias.name == "socket":
                        report("import", alias.name, node.lineno, True)
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module in FORBIDDEN_MODULES or node.module.split(".")[0] in FORBIDDEN_MODULES:
                    report("import", node.module, node.lineno, outbound and node.module in OUTBOUND_ALLOWED_IMPORTS)
                if node.module.startswith("scapy"):
                    for alias in node.names:
                        if alias.name in FORBIDDEN_CALLS:
                            findings.append(StaticFinding(rel, node.lineno, "import", f"{node.module}.{alias.name}"))
            elif isinstance(node, ast.Call):
                dotted, name = _call_name(node)
                if name in FORBIDDEN_CALLS and dotted not in ALLOWED_DOTTED_CALLS:
                    report("call", dotted or name, node.lineno, outbound and name in OUTBOUND_ALLOWED_CALLS)
    findings.sort(key=lambda f: (f.file, f.line))
    allowances.sort(key=lambda f: (f.file, f.line))
    return findings, allowances, len(files)


def static_scan(root: Path | None = None) -> tuple[list[StaticFinding], int]:
    findings, _, files = scan_with_allowances(root)
    return findings, files


def _is_loopback_address(address: Any) -> bool:
    import ipaddress

    host = address[0] if isinstance(address, tuple) and address else address
    if isinstance(host, bytes):
        host = host.decode(errors="ignore")
    if host in ("localhost", "", None):
        return host == "localhost"
    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return False


def _host_of(address: Any) -> Optional[str]:
    host = address[0] if isinstance(address, tuple) and address else address
    if isinstance(host, bytes):
        host = host.decode(errors="ignore")
    return str(host) if host is not None else None


def _outbound_file() -> str:
    from unishield.export import transport

    return os.path.normcase(os.path.abspath(transport.__file__))


class _Tripwire:
    """
    Context manager replacing network-capable functions with recorders.

    Calls made from inside the outbound transport (``export/transport.py`` on
    the call stack) are allowed only to addresses ``outbound_policy`` permits
    (allow-listed, outside the monitored network) and are listed in
    ``outbound``; without a policy they are refused. Every other caller may
    use loopback peers (counted separately: asyncio on Windows builds its
    internal self-pipe from a loopback socket pair, and the in-process API
    client uses the event loop) unless ``allow_loopback`` is False. Anything
    else (another host, name resolution, scapy send/receive/sniff) is
    recorded and refused.
    """

    def __init__(self, outbound_policy: Any = None, allow_loopback: bool = True):
        self.attempts: list[str] = []
        self.outbound: list[str] = []
        self.loopback_calls = 0
        self.policy = outbound_policy
        self.allow_loopback = allow_loopback
        self._saved: list[tuple[Any, str, Any]] = []
        self._transport_file = _outbound_file()

    def _refuse(self, label: str):
        self.attempts.append(label)
        raise PermissionError(f"passive-mode tripwire: {label} called")

    def _replace(self, owner, name, replacement):
        if hasattr(owner, name):
            self._saved.append((owner, name, getattr(owner, name)))
            setattr(owner, name, replacement)

    def _from_transport(self) -> bool:
        frame = sys._getframe(2)
        while frame is not None:
            if os.path.normcase(os.path.abspath(frame.f_code.co_filename)) == self._transport_file:
                return True
            frame = frame.f_back
        return False

    def _decide(self, label: str, address: Any, name_lookup: bool = False) -> None:
        """Return normally to allow the call; raise PermissionError (recorded) to refuse it."""
        if self._from_transport():
            host = _host_of(address)
            permitted = self.policy is not None and host is not None and (
                self.policy.permits_name(host) if name_lookup else self.policy.permits_address(host))
            if permitted:
                self.outbound.append(label)
                return
            self._refuse(f"outbound transport: {label} (not allowed by the destination policy)")
        if address is not None and self.allow_loopback and _is_loopback_address(address):
            self.loopback_calls += 1
            return
        self._refuse(label)

    def _socket_method(self, name, original, address_arg: bool):
        wire = self

        def guarded(sock, *args, **kwargs):
            if getattr(socket, "AF_UNIX", None) is not None and sock.family == socket.AF_UNIX:
                wire.loopback_calls += 1                     # local IPC (asyncio self-pipe on POSIX)
                return original(sock, *args, **kwargs)
            if address_arg:
                address = args[0] if name != "sendto" else args[-1]
            else:
                try:
                    address = sock.getpeername()
                except OSError:
                    address = None
            wire._decide(f"socket.{name}({address!r})", address)
            return original(sock, *args, **kwargs)

        return guarded

    def _blocked(self, label):
        def blocked(*args, **kwargs):
            self._refuse(label)
        return blocked

    def __enter__(self):
        for name, has_address in (("connect", True), ("connect_ex", True), ("sendto", True),
                                  ("send", False), ("sendall", False), ("sendmsg", False)):
            if hasattr(socket.socket, name):
                self._replace(socket.socket, name, self._socket_method(name, getattr(socket.socket, name), has_address))
        for name in ("create_connection", "getaddrinfo", "gethostbyname", "gethostbyaddr"):
            original = getattr(socket, name)

            def resolver(*args, _name=name, _original=original, **kwargs):
                target = args[0] if args else None
                self._decide(f"socket.{_name}({target!r})", target, name_lookup=_name != "create_connection")
                return _original(*args, **kwargs)

            self._replace(socket, name, resolver)
        try:
            import scapy.sendrecv as sendrecv

            for name in ("send", "sendp", "sendpfast", "sr", "sr1", "srp", "srp1", "srloop", "srploop", "sniff"):
                self._replace(sendrecv, name, self._blocked(f"scapy.{name}"))
        except ImportError:                                   # pragma: no cover
            pass
        return self

    def __exit__(self, *exc):
        for owner, name, original in reversed(self._saved):
            setattr(owner, name, original)
        return False


class _PolicyBypass:
    """Stands in for a broken policy that allows everything (used to probe the socket-level check)."""

    def check_host(self, *args, **kwargs) -> None:
        return None

    def check_address(self, *args, **kwargs) -> None:
        return None


def sample_intel():
    """Indicators that match the synthetic scenarios (C2 server, legacy TLS server, a DNS name)."""
    from unishield.data.sample_generator import C2_SERVER, LEGACY_TLS_SERVER
    from unishield.intel.matcher import IntelEntry, IntelMatcher

    return IntelMatcher([
        IntelEntry("verification", "ip", C2_SERVER, "sample C2"),
        IntelEntry("verification", "cidr", "198.51.100.40/30", "sample network around the C2 server"),
        IntelEntry("verification", "domain", "example-c2.test", "sample domain"),
        IntelEntry("verification", "ip", LEGACY_TLS_SERVER, "sample legacy server"),
    ])


def _outbound_check(tmp_path: Path, exercised: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Deliver real alerts to loopback receivers under the tripwire; probe three refusals."""
    from pydantic import ValidationError

    from unishield.config import UnishieldConfig
    from unishield.data.sample_generator import SimulatedReader, build_scenario
    from unishield.evaluation.receivers import HttpReceiver, SmtpReceiver, TcpSyslogReceiver, UdpSyslogReceiver
    from unishield.export import transport
    from unishield.export.policy import DestinationRefused
    from unishield.export.service import OutputService
    from unishield.processing.pipeline import Pipeline

    attempts: list[str] = []
    refusals: list[str] = []
    alerts = Pipeline(intel=sample_intel()).run(SimulatedReader(build_scenario("beacon_30s", 1).flows)).alerts
    alerts += Pipeline().run(SimulatedReader(build_scenario("port_scan", 1).flows)).alerts
    with UdpSyslogReceiver() as udp, TcpSyslogReceiver() as tcp, SmtpReceiver() as smtp, HttpReceiver() as hook:
        config = UnishieldConfig(
            export={"continuous": True, "directory": str(tmp_path / "exports")},
            outbound={"allowed_destinations": ["127.0.0.1"], "syslog": {"enabled": True, "destinations": [
                {"name": "siem-udp", "host": "127.0.0.1", "port": udp.port, "protocol": "udp"},
                {"name": "siem-tcp", "host": "127.0.0.1", "port": tcp.port, "protocol": "tcp"}]},
                "email": {"enabled": True, "smtp_host": "127.0.0.1", "smtp_port": smtp.port, "security": "none",
                          "sender": "unishield@analyst.test", "recipients": ["soc@analyst.test"]},
                "webhook": {"enabled": True, "destinations": [
                    {"name": "soar", "url": f"http://127.0.0.1:{hook.port}/unishield"}]}})
        service = OutputService(config)
        with _Tripwire(outbound_policy=service.policy) as wire:
            service.process(alerts)
        attempts += wire.attempts
        status = service.status()
        for d in status["syslog"]["destinations"]:
            exercised.append(f"outbound:syslog/{d['protocol']} → {d['host']}:{d['port']} (allow-listed): "
                             f"{d['sent']} messages")
        for c in status["notifications"]:
            exercised.append(f"outbound:{c['kind']} → {c['target']} (allow-listed): {c['messages_sent']} message(s)")
        exercised.append(f"export files (local): {status['files']['alerts_written']} alerts written to "
                         f"{len(status['files']['active_files'])} rotating files")
        outbound = list(wire.outbound)

    home = "10.0.0.5"                                 # inside the default network.home_networks
    try:
        UnishieldConfig(outbound={"allowed_destinations": ["192.0.2.0/24"], "syslog": {
            "enabled": True, "destinations": [{"name": "bad", "host": home}]}})
        attempts.append(f"config load accepted a monitored-network destination {home}")
    except ValidationError:
        refusals.append(f"config load: syslog destination {home} refused (inside network.home_networks)")
    with _Tripwire(outbound_policy=service.policy) as probe:
        try:
            transport.deliver_datagrams(service.policy, home, 514, [b"probe"])
            attempts.append(f"send-time check allowed {home}")
        except DestinationRefused:
            refusals.append(f"send time: delivery to {home} refused by the destination policy before any socket use")
        try:
            transport.deliver_datagrams(_PolicyBypass(), home, 514, [b"probe"])
            attempts.append(f"socket-level check allowed {home}")
        except PermissionError:
            refusals.append(f"socket level: with the policy check bypassed, the tripwire refused sendto({home}, 514)")
    if probe.outbound:
        attempts += [f"probe reached the network: {o}" for o in probe.outbound]
    return attempts, outbound, refusals


def runtime_check() -> tuple[list[str], list[str]]:
    """Run every input path and the API under the tripwire; returns (attempts, exercised)."""
    attempts, exercised, _, _ = runtime_check_detailed()
    return attempts, exercised


def runtime_check_detailed() -> tuple[list[str], list[str], list[str], list[str]]:
    """(attempts, exercised paths, allowed outbound socket calls, expected refusals)."""
    from fastapi.testclient import TestClient

    from unishield.api.app import create_app
    from unishield.data import sample_files
    from unishield.data.sample_generator import SCENARIO_NAMES, SimulatedReader, build_scenario
    from unishield.ingest.detect import open_reader
    from unishield.processing.pipeline import Pipeline
    from unishield.storage import AlertRepository

    exercised: list[str] = []
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        inputs = {
            "pcap": sample_files.write_sample_pcap(tmp_path / "s.pcap").path,
            "pcapng": sample_files.write_sample_pcap(tmp_path / "s.pcapng", pcapng=True).path,
            "port_scan_pcap": sample_files.write_port_scan_pcap(tmp_path / "scan.pcap"),
            "syn_flood_pcap": sample_files.write_syn_flood_pcap(tmp_path / "flood.pcap"),
            "zeek_dir": sample_files.write_sample_zeek_dir(tmp_path / "zeek"),
            "zeek_tsv": sample_files.write_sample_zeek_tsv(tmp_path / "conn.log"),
            "flow_csv": sample_files.write_sample_flow_csv(tmp_path / "flows.csv"),
            "flow_jsonl": sample_files.write_sample_flow_jsonl(tmp_path / "flows.jsonl"),
            "cicids_csv": sample_files.write_cicids_style_csv(tmp_path / "cic.csv"),
        }
        intel = sample_intel()
        with _Tripwire(allow_loopback=False) as strict:
            for name, path in inputs.items():
                reader, fmt = open_reader(path)
                Pipeline(intel=intel).run(reader)
                exercised.append(f"pipeline:{name}:{fmt} (with threat intel)")
            for name in SCENARIO_NAMES:
                result = Pipeline(intel=intel).run(SimulatedReader(build_scenario(name, 1).flows))
                intel_alerts = sum(1 for a in result.alerts if a.threat_class.value == "INTEL_MATCH")
                exercised.append(f"pipeline:scenario:{name} ({intel_alerts} INTEL_MATCH alerts from the sample "
                                 "indicators)")
        attempts = list(strict.attempts)
        exercised.append(f"readers, pipeline and detectors: {strict.loopback_calls} socket operations of any kind "
                         "(loopback refused too)")
        with _Tripwire() as wire:
            app = create_app(AlertRepository.from_url("sqlite://"))
            password = secrets.token_urlsafe(18)
            app.state.ctx.accounts.create_user("passive-check", password, "admin")
            client = TestClient(app, client=("127.0.0.1", 50000))
            login = client.post("/auth/login", json={"username": "passive-check", "password": password})
            client.headers["X-CSRF-Token"] = login.json().get("csrf_token") or ""
            exercised.append(f"api:/auth/login:{login.status_code}")
            body = client.post("/replay/demo", params={"scenario": "port_scan", "wait": True}).json()
            exercised.append(f"api:/replay/demo:{body.get('status')}")
            for path in ("/health", "/alerts", "/incidents", "/metrics", "/metrics/traffic", "/system/architecture",
                         "/intel/status", "/outputs/status", "/auth/me", "/audit"):
                client.get(path)
                exercised.append(f"api:{path}")
            attempts += wire.attempts
            exercised.append(f"loopback socket operations allowed (event-loop internals): {wire.loopback_calls}")
        outbound_attempts, outbound, refusals = _outbound_check(tmp_path, exercised)
        attempts += outbound_attempts
    return attempts, exercised, outbound, refusals


def verify(run_runtime: bool = True) -> PassiveReport:
    report = PassiveReport()
    report.static_findings, report.scoped_allowances, report.files_scanned = scan_with_allowances()
    if run_runtime:
        (report.runtime_attempts, report.runtime_exercised, report.runtime_outbound,
         report.runtime_refusals) = runtime_check_detailed()
    return report


def _summarise_outbound(calls: list[str]) -> list[str]:
    counts: dict[str, int] = {}
    for call in calls:
        key = call.split("(", 1)[0] + "(" + call.split("(", 1)[1].split(",")[0].strip("(')") + ")"
        counts[key] = counts.get(key, 0) + 1
    return [f"{k} × {n}" for k, n in sorted(counts.items())]


def render_markdown(report: PassiveReport, generated_at: str) -> str:
    lines = [
        "# UniShield — Passive-Mode Verification", "",
        f"Generated {generated_at} by `scripts/verify_passive_mode.py`.", "",
        f"**Result: {'PASSED' if report.passed else 'FAILED'}**", "",
        "UniShield never sends anything into the monitored network. Its only outbound path is the optional "
        "export/notifier transport, which may reach analyst-side destinations listed in "
        "`outbound.allowed_destinations` that lie outside `network.home_networks`.", "",
        "## Static scan", "",
        f"{report.files_scanned} Python modules under `src/unishield` were parsed. Forbidden imports: "
        f"{', '.join(sorted(FORBIDDEN_MODULES))}. Forbidden calls: {', '.join(sorted(FORBIDDEN_CALLS))} "
        f"(allowed: {', '.join(sorted(ALLOWED_DOTTED_CALLS))} — the local alert database).", "",
    ]
    if report.static_findings:
        lines += ["| File | Line | Kind | Name |", "|---|---|---|---|"]
        lines += [f"| {f.file} | {f.line} | {f.kind} | `{f.name}` |" for f in report.static_findings]
    else:
        lines.append("No findings.")
    lines += ["", "### Scoped allowance: the analyst-side transport", "",
              f"`{OUTBOUND_MODULE}` is the only module allowed network capability: imports "
              f"{', '.join(f'`{m}`' for m in sorted(OUTBOUND_ALLOWED_IMPORTS))} and calls "
              f"{', '.join(f'`{c}`' for c in sorted(OUTBOUND_ALLOWED_CALLS))}. Every function in it checks the "
              "destination against the policy before resolving or connecting and connects only to the checked "
              "address. Any other forbidden name in that file, or any of these names elsewhere, is a finding. "
              "Allowed occurrences:", ""]
    if report.scoped_allowances:
        lines += ["| Line | Kind | Name |", "|---|---|---|"]
        lines += [f"| {f.line} | {f.kind} | `{f.name}` |" for f in report.scoped_allowances]
    else:
        lines.append("None.")
    lines += ["", "## Runtime tripwire", "",
              "Socket connect/send and name-resolution functions and scapy's send/receive/sniff functions were "
              "replaced by recorders. Calls from inside the outbound transport are allowed only to addresses the "
              "destination policy permits (allow-listed, outside `network.home_networks`); readers, pipeline and "
              "detectors ran with every socket operation refused, loopback included; the API ran with loopback "
              "allowed (asyncio's event loop uses an internal loopback socket pair on Windows). "
              "Exercised under the tripwire:", ""]
    lines += [f"- {e}" for e in report.runtime_exercised] or ["- (runtime check skipped)"]
    lines += ["", "Outbound socket operations allowed for the transport (loopback receivers standing in for the "
              "analyst-side SIEM, mail relay and webhook):", ""]
    lines += [f"- {c}" for c in _summarise_outbound(report.runtime_outbound)] or ["- none"]
    lines += ["", "Refusals that must happen (a destination inside the monitored network):", ""]
    lines += [f"- {r}" for r in report.runtime_refusals] or ["- (not run)"]
    lines += ["", f"Recorded unexpected network attempts: {len(report.runtime_attempts)}"]
    lines += [f"- {a}" for a in report.runtime_attempts]
    lines += ["", "## Scope", "",
              "The API itself listens on a socket when served by uvicorn (it receives requests); that is "
              "inbound. Outbound traffic is off by default and, when configured, goes only to the analyst "
              "network through the transport above. The checks cover UniShield's own code; they cannot exclude "
              "every behaviour of third-party libraries."]
    return "\n".join(lines) + "\n"
