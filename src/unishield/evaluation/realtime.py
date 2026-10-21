"""
UniShield — Paced Real-Time Replay with End-to-End Timestamps

Replays flows at a fixed multiple of their original pace (``speed``) through
the real pipeline while the real API (in-process ASGI client, no sockets)
polls ``GET /alerts`` for new alerts. For every alert it records:

    window end (replayed)   wall time at which the replay clock passed the
                            alert window's end
    window closed           wall time the pipeline closed the window (it closes
                            when the first record past the window end arrives,
                            so quiet traffic delays it)
    stored                  wall time the alert was written to the database
    visible                 wall time a poll of the API first returned it

and derives: close delay (closed - window end), processing (stored -
closed), API visibility (visible - stored, bounded by the poll interval)
and end-to-end (visible - window end). Times in traffic seconds are divided
by ``speed`` to give wall seconds.

Nothing is sent on any network.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import Any, Iterator

from unishield.data.sample_generator import generate_mixed_scenario
from unishield.evaluation.benchmark import describe, machine_info
from unishield.ingest.base import BaseReader
from unishield.processing.pipeline import Pipeline
from unishield.schemas.flow import NormalisedFlow
from unishield.storage import AlertRepository

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


class PacedReader(BaseReader):
    """Yields flows no earlier than their timestamp allows at ``speed`` times real time."""

    def __init__(self, flows: list[NormalisedFlow], speed: float):
        super().__init__(None)
        self._flows = flows
        self.speed = speed
        self.wall_start: float = 0.0
        self.traffic_start: datetime | None = flows[0].timestamp if flows else None

    def validate_source(self) -> bool:
        return True

    def wall_time_of(self, ts: datetime) -> float:
        return self.wall_start + (ts - self.traffic_start).total_seconds() / self.speed

    def read(self) -> Iterator[NormalisedFlow]:
        self.wall_start = time.time()
        for f in self._flows:
            delay = self.wall_time_of(f.timestamp) - time.time()
            if delay > 0:
                time.sleep(delay)
            self._records_read += 1
            yield f


class _ApiPoller(threading.Thread):
    """Polls GET /alerts through the in-process API and records when each alert id first appears."""

    def __init__(self, client, interval: float):
        super().__init__(daemon=True)
        self.client, self.interval = client, interval
        self.first_seen: dict[str, float] = {}
        self.polls = 0
        self._stop_event = threading.Event()

    def poll_once(self) -> None:
        response = self.client.get("/alerts", params={"limit": 1000})
        now = time.time()
        self.polls += 1
        for a in response.json():
            self.first_seen.setdefault(a["alert_id"], now)

    def run(self) -> None:
        while not self._stop_event.is_set():
            self.poll_once()
            self._stop_event.wait(self.interval)

    def stop(self) -> None:
        self._stop_event.set()
        self.join()
        self.poll_once()


def realtime_workload(seed: int) -> list[NormalisedFlow]:
    """About 3.3k flows over ~8 minutes of traffic: benign traffic, flood, scan, beacon, exfiltration."""
    return generate_mixed_scenario(normal_count=200, ddos_count=3000, scan_count=120, beacon_count=8,
                                   exfil_count=20, start_time=T0, seed=seed)


def paced_run(flows: list[NormalisedFlow], speed: float, poll_interval: float = 0.1) -> dict[str, Any]:
    from fastapi.testclient import TestClient

    from unishield.api.app import create_app

    repo = AlertRepository.from_url("sqlite://")
    client = TestClient(create_app(repo), client=("127.0.0.1", 50000))
    reader = PacedReader(flows, speed)
    poller = _ApiPoller(client, poll_interval)
    poller.start()
    pipeline = Pipeline(alert_callback=repo.add, detection_mode="rules")
    started = time.time()
    result = pipeline.run(reader)
    poller.stop()
    wall = time.time() - started

    rows = []
    for a in repo.all():
        window_end_wall = reader.wall_time_of(a.window_end)
        closed = a.window_closed_at.timestamp()
        stored = a.stored_at.timestamp()
        visible = poller.first_seen.get(a.alert_id)
        rows.append({
            "alert_id": a.alert_id,
            "threat_class": a.threat_class.value,
            "window_end": a.window_end.isoformat(),
            "close_delay_ms": round((closed - window_end_wall) * 1000, 1),
            "processing_ms": round((stored - closed) * 1000, 2),
            "api_visibility_ms": round((visible - stored) * 1000, 1) if visible else None,
            "end_to_end_ms": round((visible - window_end_wall) * 1000, 1) if visible else None,
        })
    return {
        "records": result.total_records,
        "windows": result.total_windows,
        "alerts": len(rows),
        "traffic_seconds": round((flows[-1].timestamp - flows[0].timestamp).total_seconds(), 1),
        "wall_seconds": round(wall, 2),
        "api_polls": poller.polls,
        "alerts_detail": rows,
    }


def _values(runs: list[dict], key: str) -> list[float]:
    return [r[key] for run in runs for r in run["alerts_detail"] if r[key] is not None]


def run_realtime(runs: int = 5, speed: float = 20.0, seed: int = 2000, poll_interval: float = 0.1) -> dict[str, Any]:
    per_run = [dict(paced_run(realtime_workload(seed + i), speed, poll_interval), seed=seed + i)
               for i in range(runs)]
    measures = {k: _values(per_run, k) for k in ("close_delay_ms", "processing_ms", "api_visibility_ms",
                                                 "end_to_end_ms")}
    per_run_p95 = [sorted(v)[int(0.95 * (len(v) - 1))] for v in
                   ([r["end_to_end_ms"] for r in run["alerts_detail"] if r["end_to_end_ms"] is not None]
                    for run in per_run) if v]
    missing = sum(1 for run in per_run for r in run["alerts_detail"] if r["end_to_end_ms"] is None)
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "machine": machine_info(),
        "runs": runs,
        "speed": speed,
        "poll_interval_sec": poll_interval,
        "workload": "generate_mixed_scenario(normal 200, SYN/UDP flood 3000, port scan 120, beacon 8, "
                    "exfiltration 20), ~8 min of traffic per run",
        "statistics_ms": {k: describe(v) for k, v in measures.items() if v},
        "end_to_end_p95_per_run_ms": describe(per_run_p95) if per_run_p95 else None,
        "alerts_not_seen_by_api": missing,
        "per_run": [{k: v for k, v in r.items() if k != "alerts_detail"} for r in per_run],
        "alerts": [dict(a, seed=run["seed"]) for run in per_run for a in run["alerts_detail"]],
    }


def render_verdict(report: dict[str, Any], benchmark: dict[str, Any] | None = None) -> str:
    s = report["statistics_ms"]
    m = report["machine"]

    def row(label, key):
        v = s.get(key)
        return f"| {label} | {v['mean']} | {v['median']} | {v['stdev']} | {v['min']} | {v['max']} |" if v else ""

    lines = [
        "# UniShield — Real-Time Verification", "",
        f"Generated {report['generated_at']} by `scripts/replay_stream.py`.", "",
        "## Classification", "",
        "**Near-real-time, event-time stream processing of replayed traffic.**", "",
        "Records are processed one at a time as they arrive; each 10 s window (sliding every 5 s) is "
        "analysed as soon as it closes, and alerts are stored and served by the API immediately. "
        "UniShield does not capture from a live interface: input is a file or a replayed stream, so it is "
        "not claimed to be a live network sensor.", "",
        "## Method", "",
        f"- {report['runs']} paced replays at {report['speed']}x real time ({report['workload']}).",
        f"- The API was polled every {report['poll_interval_sec']} s through an in-process client; "
        "an alert counts as visible at the first poll that returned it.",
        f"- Machine: {m['platform']}, {m['logical_cpus']} logical CPUs, Python {m['python']}.",
        "- Delays measured in wall time. Close delay is converted from traffic time; at "
        f"{report['speed']}x, 1 s of wall time is {report['speed']} s of traffic.", "",
        "## Per-alert latency across all runs (ms of wall time)", "",
        "| Stage | Mean | Median | SD | Min | Max |", "|---|---|---|---|---|---|",
        row("Window close delay (window end → window closed)", "close_delay_ms"),
        row("Processing (window closed → alert stored)", "processing_ms"),
        row("API visibility (stored → first returned by API)", "api_visibility_ms"),
        row("End to end (window end → visible in API)", "end_to_end_ms"),
        "",
    ]
    if report.get("end_to_end_p95_per_run_ms"):
        p = report["end_to_end_p95_per_run_ms"]
        lines += [f"P95 end-to-end latency per run: mean {p['mean']} ms, median {p['median']} ms, "
                  f"SD {p['stdev']}, min {p['min']}, max {p['max']} (n = {report['runs']} runs).", ""]
    lines += [f"Alerts never returned by the API: {report['alerts_not_seen_by_api']}.", "",
              "## Per run", "", "| Seed | Records | Windows | Alerts | Traffic (s) | Wall (s) |", "|---|---|---|---|---|---|"]
    for r in report["per_run"]:
        lines.append(f"| {r['seed']} | {r['records']:,} | {r['windows']} | {r['alerts']} | {r['traffic_seconds']} | "
                     f"{r['wall_seconds']} |")
    if benchmark:
        t = benchmark["statistics"]["throughput_records_per_sec"]
        lat = benchmark["statistics"]["alert_latency_after_close_p95_ms"]
        lines += ["", "## Throughput headroom (from reports/benchmark.md)", "",
                  f"Unpaced, the pipeline processed {t['mean']:,} records/s on average (min {t['min']:,}) with P95 "
                  f"alert latency after window close of {lat['mean']} ms, so at these replay rates it is idle most "
                  "of the time."]
    lines += ["", "## Interpretation", "",
              "- The dominant delay is waiting for a window to close. A window closes when the first record "
              "after its end arrives, so in quiet traffic the delay grows with the gap between records; "
              "`processing.allowed_lateness_sec` adds to it by design.",
              "- Detection, correlation and storage take milliseconds per window.",
              "- API visibility is bounded by the poll interval; the dashboard polls every 3 s.",
              "- In traffic time, an alert can be raised at most one window length plus the close delay after "
              "the activity starts; slow behaviours (beaconing, exfiltration baselines) need several windows "
              "of evidence by design."]
    return "\n".join(lines) + "\n"

