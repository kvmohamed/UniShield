"""
UniShield — Receive-Only Flow-Export Collector (NetFlow v5/v9, IPFIX over UDP)

The only part of UniShield that listens on a socket for traffic data. It is
receive-only by construction: it creates one UDP socket, binds it, and calls
``recvfrom`` until stopped. It never sends, connects or replies (flow export
over UDP needs no acknowledgement), and it performs no name lookups.
``evaluation/passive.py`` allows this module to import ``socket`` and flags
any send or connect call in it; the runtime tripwire checks it as well.

Datagrams from exporters outside ``live.allowed_exporters`` are dropped and
counted. While no datagram arrives the reader yields ClockTick objects so the
pipeline can close windows on wall-clock time.

Default bind address: 127.0.0.1 (configure ``live.netflow_bind`` to the
interface facing the exporters, typically the receiving side of a data diode).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Iterable, Iterator, Optional

from unishield.ingest.base import BaseReader, ClockTick
from unishield.ingest.netflow import FlowExportDecoder, FlowExportError

logger = logging.getLogger("unishield.ingest.collector")


class FlowExportCollector(BaseReader):
    """Live reader for NetFlow v5/v9 and IPFIX datagrams (receive-only)."""

    packet_level = False
    live = True

    def __init__(self, host: str = "127.0.0.1", port: int = 2055, *,
                 allowed_exporters: Iterable[str] = (), tick_interval: float = 1.0,
                 max_datagram: int = 65535, receive_buffer: int = 4 * 1024 * 1024,
                 socket_factory: Callable[..., Any] = socket.socket):
        super().__init__(None)
        self.host, self.port = host, int(port)
        self._allowed = [ipaddress.ip_network(n, strict=False) for n in allowed_exporters]
        self.tick_interval = tick_interval
        self.max_datagram = max_datagram
        self.receive_buffer = receive_buffer
        self._socket_factory = socket_factory
        self._sock = None
        self._stop = threading.Event()
        self.decoder = FlowExportDecoder()
        self.datagrams = 0
        self.rejected_exporters = 0
        self.malformed = 0
        self._last_event: Optional[datetime] = None
        self._last_wall: float = 0.0

    def validate_source(self) -> bool:
        return 0 <= self.port < 65536                         # 0: an ephemeral port (tests)

    @property
    def bound_address(self) -> Optional[tuple[str, int]]:
        return self._sock.getsockname()[:2] if self._sock is not None else None

    def open(self) -> tuple[str, int]:
        """Create and bind the receive-only socket (idempotent); returns the bound address."""
        if self._sock is None:
            family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
            sock = self._socket_factory(family, socket.SOCK_DGRAM)
            try:                                        # exporters send in bursts; the OS default is small
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self.receive_buffer)
            except OSError as exc:
                logger.warning("Could not set the receive buffer to %d bytes: %s", self.receive_buffer, exc)
            sock.bind((self.host, self.port))
            sock.settimeout(self.tick_interval)
            self._sock = sock
            logger.info("Flow-export collector listening on %s:%d (receive-only)", *sock.getsockname()[:2])
        return self.bound_address

    def stop(self) -> None:
        self._stop.set()

    def _exporter_allowed(self, ip: str) -> bool:
        if not self._allowed:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._allowed)

    def _tick(self) -> ClockTick:
        if self._last_event is None:
            return ClockTick(None)
        return ClockTick(self._last_event + timedelta(seconds=time.monotonic() - self._last_wall))

    def read(self) -> Iterator:
        if not self.validate_source():
            raise ValueError(f"invalid collector port {self.port}")
        self.open()
        last_tick = time.monotonic()
        try:
            while not self._stop.is_set():
                try:
                    data, addr = self._sock.recvfrom(self.max_datagram)
                except socket.timeout:
                    yield self._tick()
                    last_tick = time.monotonic()
                    continue
                except OSError:
                    if self._stop.is_set():
                        break
                    raise
                self.datagrams += 1
                exporter = addr[0]
                if not self._exporter_allowed(exporter):
                    self.rejected_exporters += 1
                    continue
                try:
                    flows = self.decoder.decode(data, exporter)
                except FlowExportError as exc:
                    self.malformed += 1
                    self._errors += 1
                    logger.debug("Malformed flow export from %s: %s", exporter, exc)
                    continue
                for flow in flows:
                    self._records_read += 1
                    if self._last_event is None or flow.timestamp > self._last_event:
                        self._last_event = flow.timestamp
                        self._last_wall = time.monotonic()
                    yield flow
                if time.monotonic() - last_tick >= self.tick_interval:      # busy exporters: keep ticking
                    yield self._tick()
                    last_tick = time.monotonic()
        finally:
            self.close()

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None

    def stats(self) -> dict[str, Any]:
        return {
            "listening": f"{self.host}:{self.port}",
            "datagrams": self.datagrams,
            "records": self._records_read,
            "rejected_exporters": self.rejected_exporters,
            "malformed": self.malformed,
            "templates": self.decoder.templates,
            "lost_records": self.decoder.counts["lost_records"],          # sequence gaps (v5, IPFIX)
            "lost_datagrams": self.decoder.counts["lost_datagrams"],      # sequence gaps (v9)
            "records_without_template": self.decoder.counts["records_without_template"],
            "allowed_exporters": [str(n) for n in self._allowed] or "any",
            "last_record_time": self._last_event.isoformat() if self._last_event else None,
        }
