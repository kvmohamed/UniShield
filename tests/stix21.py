"""
Structural validation of STIX 2.1 bundles (test helper, no third-party library).

Checks what the STIX 2.1 specification (OASIS, 2021) requires of the object
types UniShield exports: the bundle envelope, identifier syntax (type prefix,
RFC 4122 UUID; deterministic UUIDv5 for cyber-observables), required and
typed properties, timestamp format and ordering, value ranges, non-empty
lists, custom-property naming, pattern syntax for the comparisons UniShield
writes, vocabularies, and that every *_ref / *_refs points to an object of an
allowed type inside the bundle. Returns a list of problems (empty = valid).
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid
from datetime import datetime
from typing import Any

SCO_NAMESPACE = uuid.UUID("00abedb4-aa42-466c-9c01-fed23315a9b7")
TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?Z$")
TYPE_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{1,248}[a-z0-9]$")
CUSTOM_PROPERTY = re.compile(r"^x_[a-z0-9_]{1,248}$")
RELATIONSHIP_TYPE = re.compile(r"^[a-z0-9-]+$")
COMPARISON = r"[a-z0-9-]+:[a-z0-9_.]+ (?:=|ISSUBSET) '(?:[^'\\]|\\.)*'"
PATTERN = re.compile(rf"^\[{COMPARISON}(?: (?:OR|AND) {COMPARISON})*\]$")
DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")

SDO = {"attack-pattern", "identity", "indicator", "observed-data", "incident", "malware", "note", "report",
       "grouping", "campaign", "infrastructure", "location", "threat-actor", "tool", "vulnerability"}
SRO = {"relationship", "sighting"}
SCO = {"ipv4-addr", "ipv6-addr", "domain-name", "network-traffic"}
COMMON = {"type", "spec_version", "id", "created", "modified", "created_by_ref", "revoked", "labels",
          "confidence", "lang", "external_references", "object_marking_refs", "granular_markings", "extensions"}
PROPERTIES = {
    "identity": ({"name"}, {"description", "roles", "identity_class", "sectors", "contact_information"}),
    "attack-pattern": ({"name"}, {"description", "aliases", "kill_chain_phases"}),
    "indicator": ({"pattern", "pattern_type", "valid_from"},
                  {"name", "description", "indicator_types", "pattern_version", "valid_until", "kill_chain_phases"}),
    "observed-data": ({"first_observed", "last_observed", "number_observed", "object_refs"}, set()),
    "sighting": ({"sighting_of_ref"}, {"description", "first_seen", "last_seen", "count", "observed_data_refs",
                                       "where_sighted_refs", "summary"}),
    "relationship": ({"relationship_type", "source_ref", "target_ref"},
                     {"description", "start_time", "stop_time"}),
    "incident": ({"name"}, {"description", "kill_chain_phases"}),
    "ipv4-addr": ({"value"}, {"resolves_to_refs", "belongs_to_refs", "defanged"}),
    "ipv6-addr": ({"value"}, {"resolves_to_refs", "belongs_to_refs", "defanged"}),
    "domain-name": ({"value"}, {"resolves_to_refs", "defanged"}),
}
INDICATOR_TYPES = {"anomalous-activity", "anonymization", "benign", "compromised", "malicious-activity",
                   "attribution", "unknown"}
IDENTITY_CLASSES = {"individual", "group", "system", "organization", "class", "unknown"}


def _uuid(value: str) -> uuid.UUID | None:
    try:
        u = uuid.UUID(value)
    except ValueError:
        return None
    return u if u.variant == uuid.RFC_4122 and str(u) == value else None


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not TIMESTAMP.match(value):
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _walk_lists(value: Any, path: str, problems: list[str]) -> None:
    if isinstance(value, list):
        if not value:
            problems.append(f"{path}: empty list")
        for i, v in enumerate(value):
            _walk_lists(v, f"{path}[{i}]", problems)
    elif isinstance(value, dict):
        for k, v in value.items():
            if v is None:
                problems.append(f"{path}.{k}: null value")
            elif isinstance(v, str) and v == "" and k not in ("description",):
                problems.append(f"{path}.{k}: empty string")
            _walk_lists(v, f"{path}.{k}", problems)


def validate_object(obj: dict[str, Any], problems: list[str]) -> None:
    t = obj.get("type", "")
    where = f"{obj.get('id', '?')}"
    if not TYPE_NAME.match(t):
        problems.append(f"{where}: invalid type {t!r}")
        return
    if t not in PROPERTIES:
        problems.append(f"{where}: unexpected object type {t}")
        return
    if obj.get("spec_version") != "2.1":
        problems.append(f"{where}: spec_version must be '2.1'")
    prefix, _, ident = str(obj.get("id", "")).partition("--")
    u = _uuid(ident)
    if prefix != t or u is None:
        problems.append(f"{where}: id must be '{t}--<RFC 4122 UUID>'")
    required, optional = PROPERTIES[t]
    for name in required:
        if name not in obj:
            problems.append(f"{where}: missing required property {name}")
    for name in obj:
        if name not in COMMON | required | optional and not CUSTOM_PROPERTY.match(name):
            problems.append(f"{where}: unknown property {name} (custom properties need an x_ prefix)")
    _walk_lists(obj, where, problems)

    if t in SCO:
        for forbidden in ("created", "modified", "created_by_ref"):
            if forbidden in obj:
                problems.append(f"{where}: cyber-observables have no {forbidden}")
        canonical = json.dumps({"value": obj.get("value")}, separators=(",", ":"), ensure_ascii=False)
        if u is not None and u != uuid.uuid5(SCO_NAMESPACE, canonical):
            problems.append(f"{where}: id is not the deterministic UUIDv5 of its value")
        value = str(obj.get("value", ""))
        try:
            if t == "ipv4-addr":
                ipaddress.IPv4Network(value, strict=False)
            elif t == "ipv6-addr":
                ipaddress.IPv6Network(value, strict=False)
        except ValueError:
            problems.append(f"{where}: invalid address {value!r}")
        if t == "domain-name" and not DOMAIN.match(value):
            problems.append(f"{where}: invalid domain name {value!r}")
        return

    created, modified = _time(obj.get("created")), _time(obj.get("modified"))
    if created is None or modified is None:
        problems.append(f"{where}: created/modified must be RFC 3339 UTC timestamps ending in Z")
    elif modified < created:
        problems.append(f"{where}: modified before created")
    if "confidence" in obj and not (isinstance(obj["confidence"], int) and 0 <= obj["confidence"] <= 100):
        problems.append(f"{where}: confidence must be an integer 0-100")
    for ref in obj.get("external_references", []):
        if not ref.get("source_name") or not ({"description", "url", "external_id"} & set(ref)):
            problems.append(f"{where}: external reference needs source_name and description/url/external_id")
        if ref.get("source_name") == "mitre-attack" and not re.match(r"^T\d{4}(\.\d{3})?$", ref.get("external_id", "")):
            problems.append(f"{where}: invalid ATT&CK id {ref.get('external_id')!r}")

    if t == "identity" and obj.get("identity_class") not in IDENTITY_CLASSES | {None}:
        problems.append(f"{where}: identity_class outside the vocabulary")
    if t == "indicator":
        if obj.get("pattern_type") != "stix" or not PATTERN.match(obj.get("pattern", "")):
            problems.append(f"{where}: invalid STIX pattern {obj.get('pattern')!r}")
        if not set(obj.get("indicator_types", [])) <= INDICATOR_TYPES:
            problems.append(f"{where}: indicator_types outside the vocabulary")
        start, end = _time(obj.get("valid_from")), _time(obj.get("valid_until")) if "valid_until" in obj else None
        if start is None:
            problems.append(f"{where}: invalid valid_from")
        if "valid_until" in obj and (end is None or (start and end <= start)):
            problems.append(f"{where}: valid_until must be later than valid_from")
    if t == "observed-data":
        first, last = _time(obj.get("first_observed")), _time(obj.get("last_observed"))
        if first is None or last is None or last < first:
            problems.append(f"{where}: invalid first_observed/last_observed")
        n = obj.get("number_observed")
        if not (isinstance(n, int) and 1 <= n <= 999_999_999):
            problems.append(f"{where}: number_observed must be 1-999999999")
    if t == "sighting":
        first, last = _time(obj.get("first_seen")), _time(obj.get("last_seen"))
        if ("first_seen" in obj and first is None) or ("last_seen" in obj and last is None) \
                or (first and last and last < first):
            problems.append(f"{where}: invalid first_seen/last_seen")
        if "count" in obj and not (isinstance(obj["count"], int) and 0 <= obj["count"] <= 999_999_999):
            problems.append(f"{where}: count must be 0-999999999")
    if t == "relationship" and not RELATIONSHIP_TYPE.match(obj.get("relationship_type", "")):
        problems.append(f"{where}: invalid relationship_type")


REF_TYPES = {
    "created_by_ref": {"identity"},
    "sighting_of_ref": SDO,
    "observed_data_refs": {"observed-data"},
    "where_sighted_refs": {"identity", "location"},
    "object_refs": SCO | SRO,
    "source_ref": SDO,
    "target_ref": SDO,
}


def validate_bundle(bundle: dict[str, Any]) -> list[str]:
    problems: list[str] = []
    if bundle.get("type") != "bundle":
        problems.append("bundle: type must be 'bundle'")
    prefix, _, ident = str(bundle.get("id", "")).partition("--")
    if prefix != "bundle" or _uuid(ident) is None:
        problems.append("bundle: id must be 'bundle--<UUID>'")
    if "spec_version" in bundle:
        problems.append("bundle: STIX 2.1 bundles have no spec_version")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        return problems + ["bundle: objects must be a non-empty list"]
    ids = [o.get("id") for o in objects]
    if len(ids) != len(set(ids)):
        problems.append("bundle: duplicate object ids")
    by_id = {o.get("id"): o for o in objects}
    for obj in objects:
        validate_object(obj, problems)
        for name, allowed in REF_TYPES.items():
            refs = obj.get(name)
            if refs is None:
                continue
            for ref in refs if isinstance(refs, list) else [refs]:
                target = by_id.get(ref)
                if target is None:
                    problems.append(f"{obj.get('id')}: {name} -> {ref} not in bundle")
                elif target["type"] not in allowed:
                    problems.append(f"{obj.get('id')}: {name} -> {target['type']} not allowed")
    return problems
