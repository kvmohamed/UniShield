"""
UniShield — Threat-intelligence indicator files

Parses operator-supplied lists of known-bad indicators. UniShield never
fetches intelligence: files are read from disk (``scripts/import_intel.py``)
or received in an administrative API request, on the analyst side.

Indicator kinds
    ip      an IPv4/IPv6 address
    cidr    an IPv4/IPv6 network (at least ``min_prefix_v4`` / ``min_prefix_v6`` bits)
    domain  a DNS name; it also matches its subdomains
    ja3     a JA3 client fingerprint (32 hex characters, MD5)

Formats
    text    one indicator per line; ``#`` starts a comment
    csv     a header row naming the indicator column (``indicator``, ``value``,
            ``ip``, ``dst_ip``, ``domain``, ``ja3_md5`` ...) and optionally
            ``type``, ``label``/``description``/``malware``, ``expires``/
            ``valid_until``, ``severity`` and ``techniques`` (ATT&CK IDs);
            without a recognised header the first column is the indicator
    stix    a STIX 2.1 bundle (or list of objects); ``indicator`` objects whose
            pattern consists only of ``ipv4-addr:value``, ``ipv6-addr:value``
            or ``domain-name:value`` comparisons (``=`` or ``ISSUBSET``) joined
            by ``OR`` are imported with ``valid_until`` as the expiry

Defanged values (``198.51.100[.]7``, ``evil[.]example``) are refanged.
URLs, single-label names and public suffixes are rejected: listing them
would flag unrelated traffic.

SECURITY CONSTRAINTS:
    - Pure parsing of text already read. No lookups, no network I/O.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable, Optional

from unishield.features.dns import _TWO_LABEL_SUFFIXES
from unishield.schemas.alert import Severity
from unishield.schemas.timeutil import ensure_utc

KINDS = ("ip", "cidr", "domain", "ja3")
FORMATS = ("auto", "text", "csv", "stix")

_KIND_ALIASES = {
    "ip": "ip", "ipv4": "ip", "ipv6": "ip", "ip-src": "ip", "ip-dst": "ip", "ipv4-addr": "ip",
    "ipv6-addr": "ip", "address": "ip",
    "cidr": "cidr", "subnet": "cidr", "network": "cidr", "netblock": "cidr", "range": "cidr",
    "domain": "domain", "hostname": "domain", "fqdn": "domain", "domain-name": "domain", "host": "domain",
    "ja3": "ja3", "ja3_md5": "ja3", "ja3-md5": "ja3", "ja3_hash": "ja3", "ja3-fingerprint": "ja3",
}
_VALUE_COLUMNS = ("indicator", "value", "ioc", "observable", "ip", "ip_address", "dst_ip", "src_ip",
                  "address", "cidr", "network", "domain", "hostname", "host", "fqdn", "ja3", "ja3_md5",
                  "ja3_hash")
_KIND_COLUMNS = ("type", "kind", "indicator_type", "ioc_type")
_LABEL_COLUMNS = ("label", "description", "comment", "name", "malware", "threat", "reason",
                  "listingreason", "tags")
_EXPIRY_COLUMNS = ("expires", "expires_at", "expiry", "expiration", "valid_until", "until")
_SEVERITY_COLUMNS = ("severity",)
_TECHNIQUE_COLUMNS = ("techniques", "technique", "mitre", "attack", "mitre_techniques")

_HEX32 = re.compile(r"^[0-9a-f]{32}$")
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")
_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_SOURCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:-]{0,127}$")
_DEFANG = (("[.]", "."), ("(.)", "."), ("{.}", "."), ("[dot]", "."), ("(dot)", "."), ("[:]", ":"))
_STIX_COMPARISON = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name):value\s*(=|ISSUBSET)\s*'((?:[^'\\]|\\.)*)'")
_BOM = chr(0xFEFF)
_MAX_LABEL = 200
_MAX_REJECTS_KEPT = 50


class IndicatorError(ValueError):
    """A value that cannot be used as an indicator (the message says why)."""


@dataclass(frozen=True)
class Indicator:
    """One known-bad indicator, normalised."""
    kind: str
    value: str
    label: str = ""
    expires_at: Optional[datetime] = None
    severity: Optional[str] = None
    techniques: tuple[str, ...] = ()


@dataclass
class ParseResult:
    """Accepted indicators and a sample of rejected entries (``rejected_total`` counts all)."""
    format: str
    indicators: list[Indicator] = field(default_factory=list)
    rejected: list[dict[str, Any]] = field(default_factory=list)
    rejected_total: int = 0
    duplicates: int = 0

    def reject(self, where: int, value: Any, reason: str) -> None:
        self.rejected_total += 1
        if len(self.rejected) < _MAX_REJECTS_KEPT:
            self.rejected.append({"record": where, "value": str(value)[:80], "reason": reason})

    def counts(self) -> dict[str, int]:
        out = {k: 0 for k in KINDS}
        for ind in self.indicators:
            out[ind.kind] += 1
        return out


@dataclass(frozen=True)
class ParseOptions:
    min_prefix_v4: int = 8
    min_prefix_v6: int = 32
    max_indicators: int = 1_000_000
    default_expires_at: Optional[datetime] = None


def valid_source_name(source: str) -> bool:
    return bool(_SOURCE.match(source or ""))


def refang(value: str) -> str:
    text = value.strip().strip("\"'")
    for old, new in _DEFANG:
        text = text.replace(old, new)
    return text.strip()


def _normalise_domain(text: str) -> str:
    name = text.lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name.isascii():
        try:
            name = name.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise IndicatorError("not a valid internationalised domain name") from exc
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(_LABEL.match(label) for label in labels):
        raise IndicatorError("not a valid domain name (needs at least two labels)")
    if name in _TWO_LABEL_SUFFIXES or labels[-1].isdigit():
        raise IndicatorError("a public suffix or numeric name would match unrelated traffic")
    return name


def classify(value: str, kind_hint: Optional[str] = None, options: ParseOptions = ParseOptions()) -> tuple[str, str]:
    """
    (kind, normalised value) for an indicator string. ``kind_hint`` (any
    alias in ``_KIND_ALIASES``) restricts the accepted kind. Raises
    IndicatorError with the reason when the value is unusable.
    """
    text = refang(value)
    if not text:
        raise IndicatorError("empty value")
    hint = _KIND_ALIASES.get(kind_hint.strip().lower()) if kind_hint else None
    if kind_hint and hint is None:
        raise IndicatorError(f"unsupported indicator type {kind_hint!r}")
    if "://" in text:
        raise IndicatorError("URLs are not supported; list the host as a domain or address")

    if hint in (None, "ja3") and _HEX32.match(text.lower()):
        return "ja3", text.lower()
    if hint == "ja3":
        raise IndicatorError("a JA3 fingerprint is 32 hexadecimal characters")

    if hint in (None, "ip", "cidr"):
        if "/" in text:
            try:
                net = ipaddress.ip_network(text, strict=False)
            except ValueError:
                net = None
            if net is not None:
                if net.prefixlen == net.max_prefixlen:
                    return "ip", str(net.network_address)
                minimum = options.min_prefix_v4 if net.version == 4 else options.min_prefix_v6
                if net.prefixlen < minimum:
                    raise IndicatorError(f"network broader than /{minimum} would match too much traffic")
                return "cidr", str(net)
        else:
            try:
                return "ip", str(ipaddress.ip_address(text.split("%")[0]))
            except ValueError:
                pass
        if hint in ("ip", "cidr"):
            raise IndicatorError("not a valid IP address or network")

    return "domain", _normalise_domain(text)


def parse_expiry(value: Any) -> Optional[datetime]:
    """ISO date (expires at the end of that day, UTC) or ISO datetime; None for empty."""
    if value is None or str(value).strip() in ("", "-", "never", "none", "null"):
        return None
    text = str(value).strip()
    try:
        if len(text) == 10:
            day = date.fromisoformat(text)
            return datetime(day.year, day.month, day.day, tzinfo=timezone.utc) + timedelta(days=1)
        return ensure_utc(datetime.fromisoformat(text.replace("Z", "+00:00")))
    except ValueError as exc:
        raise IndicatorError(f"unreadable expiry {text!r}") from exc


def _parse_severity(value: Any) -> Optional[str]:
    text = str(value or "").strip().upper()
    if not text:
        return None
    if text not in Severity.__members__:
        raise IndicatorError(f"unknown severity {value!r}")
    return text


def _parse_techniques(value: Any) -> tuple[str, ...]:
    tokens = re.split(r"[\s,;|]+", str(value or "").strip())
    return tuple(dict.fromkeys(t.upper() for t in tokens if _TECHNIQUE.match(t.upper())))


def _clean_label(value: Any) -> str:
    text = " ".join(str(value or "").split())
    return text[:_MAX_LABEL]


class _Collector:
    """Adds indicators to a ParseResult with de-duplication and the size limit."""

    def __init__(self, result: ParseResult, options: ParseOptions):
        self.result = result
        self.options = options
        self._seen: set[tuple[str, str]] = set()

    def add(self, where: int, raw: str, kind_hint: Optional[str] = None, label: Any = "", expires: Any = None,
            severity: Any = None, techniques: Any = None) -> None:
        if len(self.result.indicators) >= self.options.max_indicators:
            raise IndicatorError(f"more than {self.options.max_indicators} indicators in one import")
        try:
            kind, value = classify(raw, kind_hint, self.options)
            expires_at = parse_expiry(expires) if not isinstance(expires, datetime) else ensure_utc(expires)
            indicator = Indicator(
                kind=kind, value=value, label=_clean_label(label),
                expires_at=expires_at or self.options.default_expires_at,
                severity=_parse_severity(severity),
                techniques=_parse_techniques(techniques) if not isinstance(techniques, tuple) else techniques,
            )
        except IndicatorError as exc:
            self.result.reject(where, raw, str(exc))
            return
        key = (indicator.kind, indicator.value)
        if key in self._seen:
            self.result.duplicates += 1
            return
        self._seen.add(key)
        self.result.indicators.append(indicator)


def parse_text(text: str, options: ParseOptions = ParseOptions(), kind_hint: Optional[str] = None) -> ParseResult:
    result = ParseResult("text")
    collector = _Collector(result, options)
    for number, line in enumerate(text.splitlines(), 1):
        entry = line.split("#", 1)[0].strip() if not line.lstrip().startswith("#") else ""
        if entry:
            value, *label = entry.split(None, 1)
            collector.add(number, value, kind_hint, label=label[0] if label else "")
    return result


def _column(header: list[str], names: Iterable[str]) -> Optional[int]:
    lowered = [h.strip().lower().lstrip(_BOM + "#").strip() for h in header]
    for name in names:
        if name in lowered:
            return lowered.index(name)
    return None


def parse_csv(text: str, options: ParseOptions = ParseOptions(), kind_hint: Optional[str] = None) -> ParseResult:
    result = ParseResult("csv")
    collector = _Collector(result, options)
    rows = [r for r in csv.reader(io.StringIO(text)) if r and any(c.strip() for c in r)
            and not r[0].lstrip().startswith("#")]
    if not rows:
        return result
    header: list[str] = rows[0]
    value_col = _column(header, _VALUE_COLUMNS)
    if value_col is None:
        try:                                         # no header: indicator, then an optional label
            classify(header[0], kind_hint, options)
        except IndicatorError:
            result.reject(1, ",".join(header), "no indicator column in the header (e.g. 'indicator' or 'ip')")
            return result
        value_col, data, header = 0, rows, []
        cols: dict[str, Optional[int]] = {"kind": None, "label": 1, "expires": None, "severity": None,
                                          "techniques": None}
    else:
        data = rows[1:]
        cols = {
            "kind": _column(header, _KIND_COLUMNS),
            "label": _column(header, _LABEL_COLUMNS),
            "expires": _column(header, _EXPIRY_COLUMNS),
            "severity": _column(header, _SEVERITY_COLUMNS),
            "techniques": _column(header, _TECHNIQUE_COLUMNS),
        }
        if cols["kind"] is None and kind_hint is None:
            column_name = header[value_col].strip().lower().lstrip(_BOM + "#").strip()
            kind_hint = _KIND_ALIASES.get(column_name) or ("ip" if column_name.endswith("ip") else None)

    def cell(row: list[str], name: str) -> str:
        index = cols[name]
        return row[index].strip() if index is not None and index < len(row) else ""

    first = 2 if header else 1
    for number, row in enumerate(data, first):
        if value_col >= len(row):
            result.reject(number, ",".join(row), "missing indicator column")
            continue
        collector.add(number, row[value_col], cell(row, "kind") or kind_hint, label=cell(row, "label"),
                      expires=cell(row, "expires"), severity=cell(row, "severity"),
                      techniques=cell(row, "techniques"))
    return result


def _stix_values(pattern: str) -> list[tuple[str, str]]:
    """(kind hint, value) pairs of a supported STIX pattern; IndicatorError otherwise."""
    found = _STIX_COMPARISON.findall(pattern)
    remainder = _STIX_COMPARISON.sub(" ", pattern)
    if not found or re.sub(r"[\[\]()\s]|\bOR\b", "", remainder):
        raise IndicatorError("only ipv4-addr / ipv6-addr / domain-name value comparisons joined by OR are supported")
    out = []
    for obj, op, value in found:
        value = value.replace("\\'", "'").replace("\\\\", "\\")
        if obj == "domain-name":
            if op != "=":
                raise IndicatorError("ISSUBSET applies to addresses only")
            out.append(("domain", value))
        else:
            out.append(("cidr" if op == "ISSUBSET" or "/" in value else "ip", value))
    return out


def parse_stix(text: str, options: ParseOptions = ParseOptions()) -> ParseResult:
    result = ParseResult("stix")
    collector = _Collector(result, options)
    try:
        data = json.loads(text)
    except ValueError as exc:
        raise IndicatorError(f"not valid JSON: {exc}") from exc
    if isinstance(data, dict):
        objects = data.get("objects", [data]) if data.get("type") == "bundle" else [data]
    elif isinstance(data, list):
        objects = data
    else:
        raise IndicatorError("expected a STIX bundle, an object or a list of objects")
    for number, obj in enumerate(objects, 1):
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        if obj.get("revoked") or obj.get("pattern_type", "stix") != "stix":
            result.reject(number, obj.get("id", ""), "revoked or not a STIX pattern")
            continue
        try:
            values = _stix_values(str(obj.get("pattern", "")))
            expires = obj.get("valid_until")
            expires_at = parse_expiry(expires) if expires else None
        except IndicatorError as exc:
            result.reject(number, obj.get("pattern", obj.get("id", "")), str(exc))
            continue
        techniques = tuple(
            str(ref.get("external_id")).upper() for ref in obj.get("external_references", []) or []
            if isinstance(ref, dict) and ref.get("source_name") == "mitre-attack"
            and _TECHNIQUE.match(str(ref.get("external_id", "")).upper()))
        label = obj.get("name") or obj.get("description") or ", ".join(obj.get("indicator_types", []) or [])
        for hint, value in values:
            collector.add(number, value, hint, label=label, expires=expires_at, techniques=techniques)
    return result


def detect_format(text: str, filename: Optional[str] = None) -> str:
    name = (filename or "").lower()
    if name.endswith(".json"):
        return "stix"
    if name.endswith((".csv", ".tsv")):
        return "csv"
    stripped = text.lstrip(_BOM + " \t\r\n")
    if stripped.startswith(("{", "[")):
        return "stix"
    first = next((line for line in stripped.splitlines() if line.strip() and not line.startswith("#")), "")
    return "csv" if "," in first else "text"


def parse(text: str, fmt: str = "auto", filename: Optional[str] = None,
          options: ParseOptions = ParseOptions(), kind_hint: Optional[str] = None) -> ParseResult:
    """Parse indicator file content in ``fmt`` (``auto`` detects it from the name and content)."""
    if fmt not in FORMATS:
        raise IndicatorError(f"unknown format {fmt!r}; choose from {FORMATS}")
    fmt = detect_format(text, filename) if fmt == "auto" else fmt
    if fmt == "stix":
        return parse_stix(text, options)
    if fmt == "csv":
        return parse_csv(text, options, kind_hint)
    return parse_text(text, options, kind_hint)
