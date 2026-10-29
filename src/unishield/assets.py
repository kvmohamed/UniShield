"""
UniShield — Asset Inventory and Role Policies

A site tells UniShield what some of its hosts are for (``configs/assets.yaml``):
a vulnerability scanner scans, an off-site backup target receives large
uploads, a DNS resolver queries generated-looking names on behalf of its
clients. Detectors still analyse that traffic. After detection and
deduplication, ``AssetPolicy`` applies the role's action to each alert:

    alert     report unchanged
    info      report with severity INFO; the original severity and the
              matching asset are recorded in ``evidence["asset_policy"]``
    suppress  do not report; counted per action, class and role, and the
              most recent suppressed alerts are kept for review

Nothing is dropped silently: counts appear in the pipeline summary,
``/metrics`` and ``/system/assets``. Classes handled by a policy still count
as explained, so the statistical and Isolation Forest stages do not turn an
expected scan into a STATISTICAL_ANOMALY.

Matching: a policy applies on the ``source`` side when every source of the
alert holds the role (``source_ip``, or the ``clients`` of a DNS tunnelling
alert when the list is complete), and on the ``destination`` side when the
destination holds it. When several roles match, the most lenient action
wins (suppress > info > alert): each matching role explains the behaviour.

With IP anonymisation on, alerts carry salted hashes: single-address entries
still match (their hash is indexed); network (CIDR) entries cannot.

Threat intelligence wins over roles: an INTEL_MATCH alert, or any alert an
imported indicator matched (``evidence["intel_matches"]``), is reported as
it is even when a role would downgrade or suppress it; the overridden policy
is recorded in its evidence and counted (``kept_for_intel_match``).

SECURITY CONSTRAINTS:
    - Pure computation over alerts already produced. No lookups, no network I/O.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
from collections import Counter, deque
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from unishield.config import AssetInventoryConfig, get_assets, get_config
from unishield.schemas.alert import Alert, Severity, ThreatClass

logger = logging.getLogger("unishield.assets")

_C = ThreatClass
_SCANS = {_C.PORT_SCAN: "info", _C.HOST_SCAN: "info", _C.RECONNAISSANCE: "info"}

#: Built-in policies: role -> side -> threat class -> action. ``policies`` in
#: assets.yaml override single entries.
DEFAULT_ROLE_POLICIES: dict[str, dict[str, dict[ThreatClass, str]]] = {
    "vulnerability_scanner": {"source": {**_SCANS, _C.BRUTE_FORCE: "info"}},
    "backup_server": {"destination": {_C.DATA_EXFILTRATION: "suppress", _C.C2_BEACONING: "info"}},
    "dns_resolver": {"source": {_C.DGA_DETECTED: "info", _C.DNS_TUNNELLING: "info"}},
    "update_server": {"destination": {_C.C2_BEACONING: "info"}},
    "cdn_or_proxy": {"destination": {_C.C2_BEACONING: "info"}},
    "monitoring": {"source": {**_SCANS, _C.C2_BEACONING: "info"},
                   "destination": {_C.C2_BEACONING: "info"}},
    "mail_server": {"source": {_C.SPAM_ACTIVITY: "info"}},
    "server": {},
}

_LENIENCY = {"alert": 0, "info": 1, "suppress": 2}
_RECENT_SUPPRESSED = 200
_CACHE_LIMIT = 65_536


@dataclass(frozen=True)
class AssetMatch:
    asset: str
    role: str
    side: str
    address: str
    action: str

    def to_dict(self) -> dict[str, str]:
        return {"asset": self.asset, "role": self.role, "side": self.side, "address": self.address}


class AssetInventory:
    """Immutable address → asset lookup with the merged role policies."""

    def __init__(self, config: AssetInventoryConfig | None = None, anonymize_salt: Optional[str] = None):
        config = config or AssetInventoryConfig()
        self.entries = list(config.assets)
        self._networks: list[tuple[Any, Any]] = []
        self._hashed: dict[str, list[Any]] = {}
        for entry in self.entries:
            for address in entry.addresses:
                net = ipaddress.ip_network(address)
                self._networks.append((net, entry))
                if anonymize_salt is not None and net.num_addresses == 1:
                    ip = str(net.network_address)
                    key = hashlib.sha256(f"{anonymize_salt}:{ip}".encode()).hexdigest()[:16]
                    self._hashed.setdefault(key, []).append(entry)
        self.policies: dict[str, dict[str, dict[ThreatClass, str]]] = {
            role: {side: dict(classes) for side, classes in sides.items()}
            for role, sides in DEFAULT_ROLE_POLICIES.items()
        }
        for role, policy in config.policies.items():
            sides = self.policies.setdefault(role, {})
            for side in ("source", "destination"):
                sides.setdefault(side, {}).update(getattr(policy, side))
        self._cache: dict[str, tuple[Any, ...]] = {}

    @classmethod
    def from_config(cls) -> "AssetInventory":
        """Inventory from ``site.assets_file`` (hash-aware when IP anonymisation is on)."""
        security = get_config().security
        return cls(get_assets(), security.ip_hash_salt if security.anonymize_ips else None)

    def __len__(self) -> int:
        return len(self.entries)

    def lookup(self, ip: Optional[str]) -> tuple[Any, ...]:
        """Asset entries covering ``ip`` (empty for unknown hosts)."""
        if not ip or not self.entries:
            return ()
        cached = self._cache.get(ip)
        if cached is not None:
            return cached
        try:
            addr = ipaddress.ip_address(ip)
            found = tuple(entry for net, entry in self._networks
                          if net.version == addr.version and addr in net)
        except ValueError:
            found = tuple(self._hashed.get(ip, ()))
        if len(self._cache) >= _CACHE_LIMIT:
            self._cache.clear()
        self._cache[ip] = found
        return found

    def roles(self, ip: Optional[str]) -> set[str]:
        return {role for entry in self.lookup(ip) for role in entry.roles}

    def action(self, role: str, side: str, threat_class: ThreatClass) -> Optional[str]:
        return self.policies.get(role, {}).get(side, {}).get(threat_class)

    def _side_matches(self, ip: str, side: str, threat_class: ThreatClass) -> list[AssetMatch]:
        return [AssetMatch(entry.name, role, side, ip, action)
                for entry in self.lookup(ip) for role in entry.roles
                if (action := self.action(role, side, threat_class)) is not None]

    def decide(self, threat_class: ThreatClass, sources: Iterable[str],
               destination: Optional[str]) -> tuple[str, list[AssetMatch]]:
        """(action, matches) for an alert of ``threat_class`` between these endpoints."""
        candidates: list[tuple[str, list[AssetMatch]]] = []
        sources = [s for s in sources if s]
        if sources:
            per_source = [self._side_matches(s, "source", threat_class) for s in sources]
            if all(per_source):
                # every source must be explained: the side's action is its least lenient source
                best = [max(m, key=lambda x: _LENIENCY[x.action]) for m in per_source]
                weakest = min(best, key=lambda x: _LENIENCY[x.action])
                candidates.append((weakest.action, best))
        if destination:
            matches = self._side_matches(destination, "destination", threat_class)
            if matches:
                strongest = max(matches, key=lambda x: _LENIENCY[x.action])
                candidates.append((strongest.action, matches))
        if not candidates:
            return "alert", []
        action, matches = max(candidates, key=lambda c: _LENIENCY[c[0]])
        return action, matches

    def expected_destination(self, ip: Optional[str], threat_class: ThreatClass) -> bool:
        """True when a destination-side policy makes ``threat_class`` to ``ip`` expected (info/suppress)."""
        return any(m.action != "alert" for m in self._side_matches(ip, "destination", threat_class)) \
            if ip else False

    def expected_source(self, ip: Optional[str], threat_class: ThreatClass) -> bool:
        """True when a source-side policy makes ``threat_class`` from ``ip`` expected (info/suppress)."""
        return any(m.action != "alert" for m in self._side_matches(ip, "source", threat_class)) \
            if ip else False

    def describe(self) -> list[dict[str, Any]]:
        return [{"name": e.name, "addresses": e.addresses, "roles": list(e.roles), "description": e.description}
                for e in self.entries]


def alert_sources(alert: Alert) -> list[str]:
    """The alert's source hosts: ``source_ip``, or the complete client list of a DNS tunnelling alert."""
    if alert.source_ip:
        return [alert.source_ip]
    clients = alert.evidence.get("clients") or []
    if clients and alert.evidence.get("client_count", len(clients)) == len(clients):
        return list(clients)
    return []


class AssetPolicy:
    """Applies role policies to a pipeline's alerts and counts every change."""

    def __init__(self, inventory: AssetInventory | None = None):
        self.inventory = inventory if inventory is not None else AssetInventory.from_config()
        self.counts: Counter[tuple[str, str, str]] = Counter()      # (action, class, role)
        self.recent_suppressed: deque[dict[str, Any]] = deque(maxlen=_RECENT_SUPPRESSED)

    @property
    def active(self) -> bool:
        return len(self.inventory) > 0

    @property
    def suppressed(self) -> int:
        return sum(n for (action, _, _), n in self.counts.items() if action == "suppress")

    @property
    def downgraded(self) -> int:
        return sum(n for (action, _, _), n in self.counts.items() if action == "info")

    def apply(self, alerts: list[Alert]) -> list[Alert]:
        """Alerts to report: downgraded ones annotated, suppressed ones counted and kept for review."""
        if not self.active or not alerts:
            return alerts
        kept: list[Alert] = []
        for alert in alerts:
            sources = alert_sources(alert)
            action, matches = self.inventory.decide(alert.threat_class, sources, alert.destination_ip)
            self._annotate(alert, sources)
            if action == "alert":
                kept.append(alert)
                continue
            role = matches[0].role
            if alert.threat_class == ThreatClass.INTEL_MATCH or alert.evidence.get("intel_matches"):
                self.counts[("kept_for_intel_match", alert.threat_class.value, role)] += 1
                alert.evidence["asset_policy"] = {"action": "alert", "overridden": action,
                                                  "reason": "an imported threat-intel indicator matched",
                                                  "matches": [m.to_dict() for m in matches]}
                kept.append(alert)
                continue
            self.counts[(action, alert.threat_class.value, role)] += 1
            record = {"action": action, "original_severity": alert.severity.value,
                      "matches": [m.to_dict() for m in matches]}
            if action == "suppress":
                self.recent_suppressed.append({
                    "threat_class": alert.threat_class.value, "severity": alert.severity.value,
                    "source_ip": alert.source_ip, "destination_ip": alert.destination_ip,
                    "detector": alert.detector_name, "window_end": alert.window_end.isoformat(),
                    **record,
                })
                logger.debug("Suppressed %s %s -> %s (%s)", alert.threat_class.value, alert.source_ip,
                             alert.destination_ip, role)
                continue
            alert.evidence["asset_policy"] = record
            alert.severity = Severity.INFO
            kept.append(alert)
        return kept

    def _annotate(self, alert: Alert, sources: list[str]) -> None:
        """Record which endpoints are known assets (context for the analyst)."""
        known: dict[str, list[dict[str, Any]]] = {}
        for side, ips in (("source", sources), ("destination", [alert.destination_ip])):
            entries = [{"address": ip, "asset": e.name, "roles": list(e.roles)}
                       for ip in ips for e in self.inventory.lookup(ip)]
            if entries:
                known[side] = entries
        if known:
            alert.evidence["assets"] = known

    def stats(self) -> dict[str, Any]:
        by: dict[str, dict[str, dict[str, int]]] = {}
        for (action, threat, role), n in sorted(self.counts.items()):
            by.setdefault(action, {}).setdefault(threat, {})[role] = n
        return {
            "assets": len(self.inventory),
            "suppressed": self.suppressed,
            "downgraded_to_info": self.downgraded,
            "kept_for_intel_match": sum(n for (a, _, _), n in self.counts.items() if a == "kept_for_intel_match"),
            "by_action": by,
        }
