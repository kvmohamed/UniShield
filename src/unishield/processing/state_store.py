"""
UniShield — Restart-Safe Pipeline State

Several detections need history that spans many windows: beacon pair
histories, per-source upload baselines and destination rarity, the
statistical baseline, the Isolation Forest's warm-up, the detectors'
re-alert memory and the correlator's dedup cache. Without persistence a
restart forgets all of it, so a beacon running across the restart starts
over and every baseline warms up again.

``PipelineStateStore`` snapshots that state to one JSON file:

    {"format": "unishield-pipeline-state", "version": 1,
     "sha256": <hex of the canonical payload>,
     "payload": {"created_at", "unishield_version", "last_event_time",
                 "components": {"extractor:beaconing": {...}, ...}}}

    - JSON only: nothing is pickled, so loading a snapshot cannot run code.
      The Isolation Forest is rebuilt by refitting on its stored warm-up
      windows with the same random_state (an identical forest).
    - The SHA-256 of the canonical payload detects truncation, corruption
      and hand edits; a snapshot that fails it, has another format or
      version, or does not parse is refused and the pipeline starts cold.
      The refusal is logged and reported in the run summary, never silent.
    - Written atomically (temporary file, fsync, rename), periodically by
      wall clock, and when a run ends or is stopped.
    - Components are restored independently; one that fails (e.g. features
      changed between versions) starts cold and is listed as skipped.

What is not saved: records of the window still open at shutdown (up to one
window of traffic is not analysed across a restart), flow payloads (there
are none) and alerts (they live in the database).

Restore a snapshot only to continue the same site's traffic after a
restart; replaying older traffic on top of restored state counts it twice.

SECURITY CONSTRAINTS:
    - Local file I/O only. No network communication.
"""

from __future__ import annotations

import contextlib
import gc
import hashlib
import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator, Optional

from unishield import __version__
from unishield.schemas.timeutil import utc_now

logger = logging.getLogger("unishield.processing.state")

STATE_FORMAT = "unishield-pipeline-state"
STATE_VERSION = 1


@contextlib.contextmanager
def _collector_paused() -> Iterator[None]:
    """
    Pause the cyclic garbage collector while a snapshot is built or loaded.
    Both create hundreds of thousands of small acyclic objects, which would
    otherwise trigger full collections over the pipeline's large heap
    (measured: about 4x slower).
    """
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        yield
    finally:
        if was_enabled:
            gc.enable()


class StateSnapshotError(ValueError):
    """A snapshot file that cannot be trusted or used."""


def canonical_json(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def read_snapshot(path: Path) -> dict[str, Any]:
    """The verified payload of a snapshot file; raises StateSnapshotError if it cannot be trusted."""
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise StateSnapshotError(f"unreadable snapshot: {exc}") from exc
    if not isinstance(document, dict) or document.get("format") != STATE_FORMAT:
        raise StateSnapshotError("not a UniShield state snapshot")
    if document.get("version") != STATE_VERSION:
        raise StateSnapshotError(f"snapshot version {document.get('version')!r} is not {STATE_VERSION}")
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise StateSnapshotError("snapshot has no payload")
    digest = hashlib.sha256(canonical_json(payload)).hexdigest()
    if digest != document.get("sha256"):
        raise StateSnapshotError("checksum mismatch (file truncated, corrupted or edited)")
    return payload


def write_snapshot(path: Path, payload: dict[str, Any]) -> int:
    """Write ``payload`` atomically with its checksum; returns the file size in bytes."""
    body = canonical_json(payload)
    header = json.dumps({"format": STATE_FORMAT, "version": STATE_VERSION,
                         "sha256": hashlib.sha256(body).hexdigest()}, separators=(",", ":"))
    data = header[:-1].encode("utf-8") + b',"payload":' + body + b"}"     # the payload is serialised once
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    return len(data)


class PipelineStateStore:
    """Periodic and final snapshots of one pipeline's cross-window state."""

    def __init__(self, path: Path | str, snapshot_interval_sec: float = 300.0):
        self.path = Path(path)
        self.snapshot_interval_sec = snapshot_interval_sec
        self.saves = 0
        self.save_errors = 0
        self.last_save: dict[str, Any] = {}
        self.restore_status: dict[str, Any] = {"attempted": False}
        self._last_save_clock: Optional[float] = None

    @classmethod
    def from_config(cls, config=None) -> Optional["PipelineStateStore"]:
        """Store from the ``state`` section, or None when persistence is disabled."""
        if config is None:
            from unishield.config import get_config
            config = get_config()
        state = config.state
        return cls(state.path, state.snapshot_interval_sec) if state.enabled else None

    # ------------------------------------------------------------------ save

    def save(self, pipeline, last_event_time: Optional[datetime] = None) -> bool:
        """Snapshot ``pipeline`` now. Failures are logged and counted, not raised."""
        started = time.perf_counter()
        try:
            with _collector_paused():
                payload = {
                    "created_at": utc_now().isoformat(),
                    "unishield_version": __version__,
                    "last_event_time": last_event_time.isoformat() if last_event_time else None,
                    "components": pipeline.state_dict(),
                }
                size = write_snapshot(self.path, payload)
        except Exception as exc:                       # disk full, permissions, non-finite value...
            self.save_errors += 1
            logger.error("State snapshot to %s failed: %s", self.path, exc)
            return False
        self.saves += 1
        self._last_save_clock = time.monotonic()
        self.last_save = {"at": payload["created_at"], "bytes": size,
                          "ms": round((time.perf_counter() - started) * 1000.0, 1),
                          "components": sorted(payload["components"])}
        logger.debug("State snapshot written to %s (%d bytes)", self.path, size)
        return True

    def maybe_save(self, pipeline, last_event_time: Optional[datetime] = None) -> bool:
        """Snapshot if ``snapshot_interval_sec`` of wall time passed since the last one."""
        now = time.monotonic()
        if self._last_save_clock is None:
            self._last_save_clock = now                # first snapshot one interval after the start
            return False
        if now - self._last_save_clock < self.snapshot_interval_sec:
            return False
        return self.save(pipeline, last_event_time)

    # --------------------------------------------------------------- restore

    def restore(self, pipeline) -> dict[str, Any]:
        """Load the snapshot into ``pipeline`` if there is a trustworthy one; returns the status."""
        status: dict[str, Any] = {"attempted": True, "path": str(self.path), "restored": False}
        if not self.path.is_file():
            status["reason"] = "no snapshot (cold start)"
            logger.info("No state snapshot at %s; starting cold", self.path)
        else:
            try:
                with _collector_paused():
                    payload = read_snapshot(self.path)
            except StateSnapshotError as exc:
                status["reason"] = f"refused: {exc}"
                logger.error("State snapshot %s refused (%s); starting cold", self.path, exc)
            else:
                with _collector_paused():
                    outcome = pipeline.load_state_dict(payload.get("components") or {})
                status.update(restored=bool(outcome["restored"]), components=outcome["restored"],
                              skipped=outcome["skipped"], snapshot_created_at=payload.get("created_at"),
                              last_event_time=payload.get("last_event_time"))
                logger.info("State restored from %s (taken %s): %s%s", self.path, payload.get("created_at"),
                            ", ".join(outcome["restored"]) or "nothing",
                            f"; skipped {outcome['skipped']}" if outcome["skipped"] else "")
        self.restore_status = status
        self._last_save_clock = time.monotonic()
        return status

    def stats(self) -> dict[str, Any]:
        return {
            "path": str(self.path),
            "snapshot_interval_sec": self.snapshot_interval_sec,
            "restore": self.restore_status,
            "saves": self.saves,
            "save_errors": self.save_errors,
            "last_save": self.last_save,
        }
