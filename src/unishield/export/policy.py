"""
UniShield — Outbound destination policy

UniShield sits on the receiving side of a one-way link; analysts work on a
separate network. Outbound delivery (syslog, email, webhooks) may only
reach analyst-side systems the operator listed, and never the monitored
network. The rules:

    allow-list  ``outbound.allowed_destinations`` holds IP addresses, CIDR
                networks and host names (exact, case-insensitive). Entries
                overlapping ``network.home_networks`` are refused.
    IP literal  a destination address must be inside an allow-listed
                address/network and outside every home network.
    host name   a destination name must be listed by name, and every address
                it resolves to (at send time) must be outside the home
                networks; the connection then goes to that checked address,
                so a later DNS answer cannot redirect it.
    always      unspecified, multicast and broadcast addresses are refused;
                outbound delivery needs ``network.home_networks`` to describe
                the monitored network.

The checks run when the configuration is loaded (``validate_outbound``) and
again before every connection (``export.transport``). The passive-mode
runtime tripwire applies ``permits_address`` independently at socket level.

SECURITY CONSTRAINTS:
    - Pure computation. No lookups and no network I/O in this module.
"""

from __future__ import annotations

import ipaddress
import re
import threading
from typing import Iterable, Optional
from urllib.parse import urlsplit

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network
IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*$")


class DestinationRefused(PermissionError):
    """An outbound destination the policy does not allow (the message says why)."""


def parse_address(host: str) -> Optional[IPAddress]:
    """IP address of a literal (IPv4-mapped IPv6 addresses as IPv4, so home checks see them); None for names."""
    try:
        address = ipaddress.ip_address(str(host).strip("[]").split("%")[0])
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


class DestinationPolicy:
    """Allow-list of analyst-side destinations, minus the monitored network."""

    def __init__(self, allowed: Iterable[str], home_networks: Iterable[str]):
        self.home_networks: tuple[IPNetwork, ...] = tuple(
            ipaddress.ip_network(n, strict=False) for n in home_networks)
        networks: list[IPNetwork] = []
        hosts: set[str] = set()
        for raw in allowed:
            entry = str(raw).strip().lower()
            if not entry:
                continue
            net = None
            try:
                net = ipaddress.ip_network(entry.strip("[]"), strict=False)
            except ValueError:
                if not _HOSTNAME.match(entry.rstrip(".")):
                    raise ValueError(f"outbound.allowed_destinations: {raw!r} is not an address, network or host name")
                hosts.add(entry.rstrip("."))
                continue
            overlap = next((h for h in self.home_networks if net.version == h.version and net.overlaps(h)), None)
            if overlap is not None:
                raise ValueError(f"outbound.allowed_destinations: {raw!r} overlaps the monitored network {overlap} "
                                 "(network.home_networks); outbound traffic may only go to the analyst network")
            if net.is_multicast or net.network_address.is_unspecified:
                raise ValueError(f"outbound.allowed_destinations: {raw!r} is not a unicast destination")
            networks.append(net)
        self.allowed_networks: tuple[IPNetwork, ...] = tuple(networks)
        self.allowed_hosts: frozenset[str] = frozenset(hosts)
        self._resolved: set[str] = set()                      # addresses checked for listed host names
        self._lock = threading.Lock()

    @classmethod
    def from_config(cls, config=None) -> "DestinationPolicy":
        if config is None:
            from unishield.config import get_config
            config = get_config()
        return cls(config.outbound.allowed_destinations, config.network.home_networks)

    @property
    def empty(self) -> bool:
        return not self.allowed_networks and not self.allowed_hosts

    def in_home_network(self, address: IPAddress) -> Optional[IPNetwork]:
        return next((n for n in self.home_networks if address.version == n.version and address in n), None)

    def _check_unicast(self, label: str, address: IPAddress) -> None:
        home = self.in_home_network(address)
        if home is not None:
            raise DestinationRefused(f"{label}: {address} is inside the monitored network {home}; "
                                     "UniShield never sends anything into the monitored network")
        if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
            raise DestinationRefused(f"{label}: {address} is not a unicast destination")

    def check_host(self, host: str, label: str = "destination") -> None:
        """Static check of a configured host (address or name), before any lookup."""
        if not self.home_networks:
            raise DestinationRefused("outbound delivery needs network.home_networks to describe the monitored network")
        address = parse_address(host)
        if address is not None:
            self._check_unicast(label, address)
            if not any(address.version == n.version and address in n for n in self.allowed_networks):
                raise DestinationRefused(f"{label}: {address} is not in outbound.allowed_destinations")
            return
        name = str(host).strip().lower().rstrip(".")
        if name not in self.allowed_hosts:
            raise DestinationRefused(f"{label}: host {host!r} is not in outbound.allowed_destinations "
                                     "(host names must be listed by name)")

    def check_address(self, host: str, address: str, label: str = "destination") -> None:
        """Check one address a destination resolved to; remembers it as checked for the tripwire."""
        self.check_host(host, label)
        parsed = parse_address(address)
        if parsed is None:
            raise DestinationRefused(f"{label}: {host!r} resolved to {address!r}, which is not an IP address")
        self._check_unicast(f"{label} ({host})", parsed)
        literal = parse_address(host)
        if literal is not None and literal != parsed:
            raise DestinationRefused(f"{label}: connection address {parsed} differs from {literal}")
        with self._lock:
            self._resolved.add(str(parsed))

    def permits_address(self, address: str) -> bool:
        """Socket-level rule: outside the home networks and allow-listed (directly or via a checked name)."""
        parsed = parse_address(address)
        if parsed is None or self.in_home_network(parsed) is not None:
            return False
        if any(parsed.version == n.version and parsed in n for n in self.allowed_networks):
            return True
        with self._lock:
            return str(parsed) in self._resolved

    def permits_name(self, host: str) -> bool:
        """Socket-level rule for name resolution: only listed host names (or allow-listed literals)."""
        address = parse_address(host)
        if address is not None:
            return self.permits_address(str(address))
        return str(host).strip().lower().rstrip(".") in self.allowed_hosts


def webhook_host(url: str) -> tuple[str, str, int]:
    """(scheme, host, port) of a webhook URL; ValueError for unusable URLs."""
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError(f"webhook URL must be http(s)://host[:port]/path, got {url[:40]!r}")
    if parts.username or parts.password:
        raise ValueError("webhook URL must not contain credentials; use headers_from_env")
    return parts.scheme, parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)


def validate_outbound(config) -> None:
    """
    Config-load check of every enabled outbound destination (raises ValueError):
    the allow-list itself, then each syslog host, the SMTP relay and each
    webhook host against the allow-list and the monitored network.
    """
    out = config.outbound
    enabled = out.syslog.enabled or out.email.enabled or out.webhook.enabled
    if not enabled:
        return
    if not config.network.home_networks:
        raise ValueError("outbound delivery needs network.home_networks to describe the monitored network")
    policy = DestinationPolicy(out.allowed_destinations, config.network.home_networks)
    targets: list[tuple[str, str]] = []
    if out.syslog.enabled:
        targets += [(f"syslog destination {d.name!r}", d.host) for d in out.syslog.destinations]
    if out.email.enabled:
        if not out.email.smtp_host or not out.email.sender or not out.email.recipients:
            raise ValueError("outbound.email needs smtp_host, sender and recipients when enabled")
        targets.append(("SMTP relay", out.email.smtp_host))
    if out.webhook.enabled:
        for d in out.webhook.destinations:
            targets.append((f"webhook {d.name!r}", webhook_host(d.url)[1]))
    for label, host in targets:
        try:
            policy.check_host(host, label)
        except DestinationRefused as exc:
            raise ValueError(str(exc)) from None
