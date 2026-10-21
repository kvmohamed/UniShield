"""
UniShield — Passive-Mode Verification

Two independent checks that UniShield only reads:

Static (AST) scan of every module under ``src/unishield``:
    - imports of networking, process, HTTP-client, crypto or remote-shell
      modules that the code base has no reason to use
    - calls that send or capture packets (scapy send/sendp/sr/sr1/srp/
      sniff/AsyncSniffer...), open outbound connections
      (socket.connect/sendto/create_connection, urlopen) or run commands
      (os.system, subprocess)

Runtime tripwire: socket connect/send/DNS-resolution functions and scapy's
send and capture functions are replaced by functions that record the
attempt and raise; then the pipeline is run over every supported input
format and the API handles a replay and a demo through an in-process
client. Any recorded attempt fails the check.

Neither check can prove the absence of every possible network effect (for
example from third-party libraries' internals), but together they show
that UniShield's own code paths contain no active network capability and
exercise none.
"""

from __future__ import annotations

import ast
import socket
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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


@dataclass
class StaticFinding:
    file: str
    line: int
    kind: str
    name: str


@dataclass
class PassiveReport:
    static_findings: list[StaticFinding] = field(default_factory=list)
    files_scanned: int = 0
    runtime_attempts: list[str] = field(default_factory=list)
    runtime_exercised: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return not self.static_findings and not self.runtime_attempts

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "files_scanned": self.files_scanned,
            "static_findings": [f.__dict__ for f in self.static_findings],
            "runtime_attempts": self.runtime_attempts,
            "runtime_exercised": self.runtime_exercised,
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


def static_scan(root: Path | None = None) -> tuple[list[StaticFinding], int]:
    import unishield

    root = root or Path(unishield.__file__).parent
    findings: list[StaticFinding] = []
    files = sorted(root.rglob("*.py"))
    for path in files:
        rel = path.relative_to(root.parent).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in FORBIDDEN_MODULES or alias.name.split(".")[0] in FORBIDDEN_MODULES:
                        findings.append(StaticFinding(rel, node.lineno, "import", alias.name))
            elif isinstance(node, ast.ImportFrom) and node.module:
                if node.module in FORBIDDEN_MODULES or node.module.split(".")[0] in FORBIDDEN_MODULES:
                    findings.append(StaticFinding(rel, node.lineno, "import", node.module))
                if node.module.startswith("scapy"):
                    for alias in node.names:
                        if alias.name in FORBIDDEN_CALLS:
                            findings.append(StaticFinding(rel, node.lineno, "import", f"{node.module}.{alias.name}"))
            elif isinstance(node, ast.Call):
                dotted, name = _call_name(node)
                if name in FORBIDDEN_CALLS and dotted not in ALLOWED_DOTTED_CALLS:
                    findings.append(StaticFinding(rel, node.lineno, "call", dotted or name))
    return findings, len(files)


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


class _Tripwire:
    """
    Context manager replacing network-capable functions with recorders.

    Connections and sends to loopback peers are allowed and counted
    separately: asyncio on Windows builds its internal self-pipe from a
    loopback socket pair, and the in-process API client uses the event loop.
    Anything else (another host, name resolution, scapy send/receive/sniff)
    is recorded and refused.
    """

    def __init__(self):
        self.attempts: list[str] = []
        self.loopback_calls = 0
        self._saved: list[tuple[Any, str, Any]] = []

    def _refuse(self, label: str):
        self.attempts.append(label)
        raise PermissionError(f"passive-mode tripwire: {label} called")

    def _replace(self, owner, name, replacement):
        if hasattr(owner, name):
            self._saved.append((owner, name, getattr(owner, name)))
            setattr(owner, name, replacement)

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
            if address is not None and _is_loopback_address(address):
                wire.loopback_calls += 1
                return original(sock, *args, **kwargs)
            wire._refuse(f"socket.{name}({address!r})")

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
                if args and _is_loopback_address(args[0]):
                    self.loopback_calls += 1
                    return _original(*args, **kwargs)
                self._refuse(f"socket.{_name}({args[0] if args else ''!r})")

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


def runtime_check() -> tuple[list[str], list[str]]:
    """Run every input path and the API under the tripwire; returns (attempts, exercised)."""
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
        with _Tripwire() as wire:
            for name, path in inputs.items():
                reader, fmt = open_reader(path)
                Pipeline().run(reader)
                exercised.append(f"pipeline:{name}:{fmt}")
            for name in SCENARIO_NAMES:
                Pipeline().run(SimulatedReader(build_scenario(name, 1).flows))
                exercised.append(f"pipeline:scenario:{name}")
            client = TestClient(create_app(AlertRepository.from_url("sqlite://")), client=("127.0.0.1", 50000))
            body = client.post("/replay/demo", params={"scenario": "port_scan", "wait": True}).json()
            exercised.append(f"api:/replay/demo:{body.get('status')}")
            for path in ("/health", "/alerts", "/incidents", "/metrics", "/metrics/traffic", "/system/architecture"):
                client.get(path)
                exercised.append(f"api:{path}")
            attempts = list(wire.attempts)
            exercised.append(f"loopback socket operations allowed (event-loop internals): {wire.loopback_calls}")
    return attempts, exercised


def verify(run_runtime: bool = True) -> PassiveReport:
    report = PassiveReport()
    report.static_findings, report.files_scanned = static_scan()
    if run_runtime:
        report.runtime_attempts, report.runtime_exercised = runtime_check()
    return report


def render_markdown(report: PassiveReport, generated_at: str) -> str:
    lines = [
        "# UniShield — Passive-Mode Verification", "",
        f"Generated {generated_at} by `scripts/verify_passive_mode.py`.", "",
        f"**Result: {'PASSED' if report.passed else 'FAILED'}**", "",
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
    lines += ["", "## Runtime tripwire", "",
              "Socket connect/send and name-resolution functions and scapy's send/receive/sniff functions were "
              "replaced by recorders that refuse any non-loopback peer (loopback is allowed because asyncio's "
              "event loop uses an internal loopback socket pair on Windows). Exercised under the tripwire:", ""]
    lines += [f"- {e}" for e in report.runtime_exercised] or ["- (runtime check skipped)"]
    lines += ["", f"Recorded network attempts: {len(report.runtime_attempts)}"]
    lines += [f"- {a}" for a in report.runtime_attempts]
    lines += ["", "## Scope", "",
              "The API itself listens on a socket when served by uvicorn (it receives requests); that is the only "
              "network use and it is inbound. The checks cover UniShield's own code; they cannot exclude every "
              "behaviour of third-party libraries."]
    return "\n".join(lines) + "\n"
