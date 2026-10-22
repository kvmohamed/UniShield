"""
UniShield — Soak Test

Streams continuous synthetic site traffic (``data.site_traffic``) through
one pipeline for a set wall-clock duration at a set record rate, the way a
long-running deployment would see it, and samples the process at a fixed
interval:

    - resident memory (RSS) and CPU of the process
    - records processed and how far processing lags behind the schedule
    - window processing latency (p50 / p95 / max of the windows in the interval)
    - alerts emitted in the interval, by class
    - size of the cross-window state (beacon pairs, upload baselines,
      statistical baseline, re-alert memories, dedup cache) and the last
      state snapshot's size and write time

Traffic time advances ``speedup`` times faster than wall time, so a short
run can cover hours of traffic; every record is still processed.

Sampling runs inside the pipeline's own loop (the paced reader), so it reads
pipeline state without locks and never races the detectors.

SECURITY CONSTRAINTS:
    - Synthetic records only; no network communication.
"""

from __future__ import annotations

import os
import platform
import statistics
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Optional

import psutil

from unishield.assets import AssetInventory
from unishield.data.site_traffic import SiteTraffic, site_assets
from unishield.processing.pipeline import Pipeline
from unishield.processing.state_store import PipelineStateStore
from unishield.schemas.alert import Alert
from unishield.schemas.flow import NormalisedFlow

_MB = 1_048_576


@dataclass
class SoakConfig:
    duration_sec: float = 1800.0          # wall-clock length of the run
    rate: float = 1000.0                  # records per wall-clock second
    speedup: float = 1.0                  # traffic seconds per wall-clock second
    sample_every_sec: float = 60.0        # wall-clock sampling interval
    profile: str = "site"                 # site traffic profile (see data.site_traffic)
    attack_every_sec: Optional[float] = 900.0   # traffic seconds between injected attacks (None: none)
    use_assets: bool = True               # apply the site profile's asset inventory
    state_path: Optional[str] = None      # snapshot file (None: no state persistence)
    snapshot_interval_sec: float = 60.0   # wall-clock seconds between snapshots
    seed: int = 7


def _percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(int(len(ordered) * p / 100), len(ordered) - 1)]


def _state_sizes(pipeline: Pipeline) -> dict[str, int]:
    sizes: dict[str, int] = {}
    for e in pipeline.extractors:
        if e.name == "beaconing":
            sizes["beacon_pairs"] = len(e._pairs)
            sizes["beacon_seen_ids"] = len(e._seen)
        elif e.name == "exfiltration":
            sizes["upload_baselines"] = len(e._baselines)
            sizes["upload_destinations"] = len(e._uploaders)
    for d in pipeline.detectors:
        if hasattr(d, "_reported"):
            sizes[f"{d.name}_memory"] = len(d._reported)
        if d.name == "statistical_detector":
            sizes["statistical_baseline"] = d.baseline_size
    if pipeline._correlator is not None:
        sizes["dedup_cache"] = len(pipeline._correlator._dedup_cache)
    return sizes


class _Sampler:
    """Collects one sample per interval; called from the paced reader between records."""

    def __init__(self, cfg: SoakConfig, pipeline: Pipeline, alerts: Counter,
                 progress: Optional[Callable[[dict[str, Any]], None]]):
        self.cfg = cfg
        self.pipeline = pipeline
        self.alerts = alerts
        self.progress = progress
        self.process = psutil.Process()
        self.process.cpu_percent(None)
        self.samples: list[dict[str, Any]] = []
        self.next_at = cfg.sample_every_sec
        self.records = 0
        self.max_lag = 0.0
        self._last = {"records": 0, "windows": 0, "alerts": Counter(), "elapsed": 0.0}

    def tick(self, elapsed: float, lag: float, traffic_time: datetime) -> None:
        self.records += 1
        self.max_lag = max(self.max_lag, lag)
        if elapsed >= self.next_at:
            self.take(elapsed, traffic_time)
            self.next_at += self.cfg.sample_every_sec

    def take(self, elapsed: float, traffic_time: Optional[datetime]) -> None:
        result = self.pipeline.result
        windows = result.total_windows if result else 0
        new_windows = windows - self._last["windows"]
        latencies = list(result.window_latencies_ms)[-new_windows:] if result and new_windows > 0 else []
        interval = elapsed - self._last["elapsed"] or 1e-9
        new_alerts = self.alerts - self._last["alerts"]
        store = self.pipeline.state_store
        sample = {
            "elapsed_sec": round(elapsed, 1),
            "traffic_time": traffic_time.isoformat() if traffic_time else None,
            "records": self.records,
            "records_per_sec": round((self.records - self._last["records"]) / interval, 1),
            "max_lag_sec": round(self.max_lag, 3),
            "rss_mb": round(self.process.memory_info().rss / _MB, 1),
            "cpu_percent": round(self.process.cpu_percent(None), 1),
            "windows": windows,
            "window_p50_ms": round(_percentile(latencies, 50), 2),
            "window_p95_ms": round(_percentile(latencies, 95), 2),
            "window_max_ms": round(max(latencies, default=0.0), 2),
            "alerts": sum(new_alerts.values()),
            "alerts_by_class": dict(new_alerts),
            "state": _state_sizes(self.pipeline),
            "snapshot": dict(store.last_save) if store is not None and store.last_save else None,
        }
        if sample["snapshot"]:
            sample["snapshot"].pop("components", None)
        self.samples.append(sample)
        self._last = {"records": self.records, "windows": windows, "alerts": Counter(self.alerts),
                      "elapsed": elapsed}
        self.max_lag = 0.0
        if self.progress:
            self.progress(sample)


class _PacedReader:
    """Feeds the pipeline in traffic-time order at ``speedup`` x wall time until the duration ends."""

    packet_level = False

    def __init__(self, cfg: SoakConfig, traffic: SiteTraffic):
        self.cfg = cfg
        self.traffic = traffic
        self.sampler: Optional[_Sampler] = None
        self.records_read = 0
        self.errors = 0
        self.elapsed = 0.0

    def read(self) -> Iterator[NormalisedFlow]:
        cfg, t0 = self.cfg, self.traffic.start
        wall0 = time.perf_counter()
        for flow in self.traffic.stream(chunk_sec=1.0):
            target = (flow.timestamp - t0).total_seconds() / cfg.speedup
            now = time.perf_counter() - wall0
            if target - now > 0.002:
                time.sleep(target - now)
                now = time.perf_counter() - wall0
            if now >= cfg.duration_sec:
                break
            self.records_read += 1
            if self.sampler is not None:
                self.sampler.tick(now, max(0.0, now - target), flow.timestamp)
            yield flow
        self.elapsed = time.perf_counter() - wall0


def _slope_mb_per_hour(samples: list[dict[str, Any]]) -> Optional[float]:
    """Least-squares slope of RSS over elapsed time, in MB per hour (None with < 3 samples)."""
    if len(samples) < 3:
        return None
    xs = [s["elapsed_sec"] / 3600.0 for s in samples]
    ys = [s["rss_mb"] for s in samples]
    mx, my = statistics.fmean(xs), statistics.fmean(ys)
    var = sum((x - mx) ** 2 for x in xs)
    return round(sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var, 2) if var else None


def run_soak(cfg: SoakConfig, progress: Optional[Callable[[dict[str, Any]], None]] = None) -> dict[str, Any]:
    """Run one soak test and return its measurements (see ``render_markdown``)."""
    traffic = SiteTraffic(rate_per_sec=cfg.rate / cfg.speedup, seed=cfg.seed, profile=cfg.profile,
                          attack_every_sec=cfg.attack_every_sec)
    alerts: Counter[str] = Counter()
    severities: Counter[str] = Counter()

    def count(alert: Alert) -> None:
        alerts[alert.threat_class.value] += 1
        severities[alert.severity.value] += 1

    store = PipelineStateStore(cfg.state_path, cfg.snapshot_interval_sec) if cfg.state_path else None
    if store is not None and store.path.exists():
        store.path.unlink()                         # each soak starts from a cold state
    assets = AssetInventory(site_assets()) if cfg.use_assets and cfg.profile == "site" else AssetInventory()
    pipeline = Pipeline(alert_callback=count, assets=assets, state_store=store)
    reader = _PacedReader(cfg, traffic)
    sampler = _Sampler(cfg, pipeline, alerts, progress)
    reader.sampler = sampler

    started = datetime.now(timezone.utc)
    result = pipeline.run(reader)
    sampler.take(reader.elapsed, traffic.now)
    samples = sampler.samples

    steady = samples[len(samples) // 2:] if len(samples) >= 6 else samples
    window_p95s = [s["window_p95_ms"] for s in samples if s["windows"]]
    summary = {
        "records": result.total_records,
        "windows": result.total_windows,
        "errors": result.errors,
        "wall_seconds": round(reader.elapsed, 1),
        "traffic_seconds": round((traffic.now - traffic.start).total_seconds(), 1),
        "records_per_sec": round(result.total_records / reader.elapsed, 1) if reader.elapsed else 0.0,
        "rss_first_mb": samples[0]["rss_mb"],
        "rss_last_mb": samples[-1]["rss_mb"],
        "rss_max_mb": max(s["rss_mb"] for s in samples),
        "rss_slope_mb_per_hour_second_half": _slope_mb_per_hour(steady),
        "rss_second_half_range_mb": round(max(s["rss_mb"] for s in steady) - min(s["rss_mb"] for s in steady), 1),
        "window_p50_ms_overall": round(_percentile(list(result.window_latencies_ms), 50), 2),
        "window_p95_ms_overall": round(_percentile(list(result.window_latencies_ms), 95), 2),
        "window_p95_ms_worst_interval": max(window_p95s, default=0.0),
        "window_max_ms": max((s["window_max_ms"] for s in samples), default=0.0),
        "max_lag_sec": max(s["max_lag_sec"] for s in samples),
        "alerts": sum(alerts.values()),
        "alerts_by_class": dict(alerts),
        "alerts_by_severity": dict(severities),
        "alerts_per_hour": round(sum(alerts.values()) / (reader.elapsed / 3600.0), 1) if reader.elapsed else 0.0,
        "attacks_injected": dict(traffic.injected),
        "asset_policy": pipeline.asset_policy.stats(),
        "state": store.stats() if store is not None else None,
        "final_state_sizes": _state_sizes(pipeline),
    }
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "started_at": started.isoformat(timespec="seconds"),
        "config": asdict(cfg),
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "logical_cpus": os.cpu_count(),
            "total_memory_gb": round(psutil.virtual_memory().total / 1e9, 1),
        },
        "summary": summary,
        "samples": samples,
    }


def _fmt_duration(seconds: float) -> str:
    if seconds >= 3600:
        return f"{seconds / 3600:.1f} h"
    if seconds >= 60:
        return f"{seconds / 60:.0f} min"
    return f"{seconds:.0f} s"


def render_markdown(report: dict[str, Any], *, commit: Optional[str] = None, notes: str = "") -> str:
    cfg, s, env = report["config"], report["summary"], report["environment"]
    lines = [
        "# UniShield — Soak Test", "",
        f"Generated {report['generated_at']} by `scripts/soak_test.py`"
        + (f" at commit `{commit}`" if commit else "") + ".", "",
        "Everything below was measured in this run on the machine listed. The traffic is UniShield's "
        "own synthetic site profile (`unishield.data.site_traffic`), not traffic from a real network.", "",
        "## Setup", "",
        "| Setting | Value |", "|---|---|",
        f"| Wall-clock duration | {_fmt_duration(cfg['duration_sec'])} |",
        f"| Record rate | {cfg['rate']:,.0f} records/s (wall clock) |",
        f"| Traffic time per wall second | {cfg['speedup']:g} s, so the run covered "
        f"{_fmt_duration(s['traffic_seconds'])} of traffic |",
        f"| Profile | `{cfg['profile']}`; asset inventory {'on' if cfg['use_assets'] else 'off'}; "
        f"attack every {_fmt_duration(cfg['attack_every_sec']) if cfg['attack_every_sec'] else '-'} of traffic |",
        "| State snapshots | "
        + (f"every {cfg['snapshot_interval_sec']:g} s to `{Path(cfg['state_path']).name}`" if cfg["state_path"]
           else "off") + " |",
        f"| Sampling | every {cfg['sample_every_sec']:g} s |",
        f"| Machine | {env['platform']}, {env['logical_cpus']} logical CPUs, {env['total_memory_gb']} GB, "
        f"Python {env['python']} |",
        "", "## Summary", "",
        "| Measure | Value |", "|---|---|",
        f"| Records processed | {s['records']:,} ({s['records_per_sec']:,.0f}/s) in {s['windows']:,} windows |",
        f"| Pipeline errors | {s['errors']} |",
        f"| Largest lag behind schedule | {s['max_lag_sec']:.3f} s |",
        f"| RSS first / last / max | {s['rss_first_mb']} / {s['rss_last_mb']} / {s['rss_max_mb']} MB |",
        "| RSS trend over the second half | "
        + (f"{s['rss_slope_mb_per_hour_second_half']:+.1f} MB/h (range {s['rss_second_half_range_mb']} MB)"
           if s["rss_slope_mb_per_hour_second_half"] is not None else "n/a (too few samples)") + " |",
        f"| Window processing p50 / p95 (all windows) | {s['window_p50_ms_overall']} / "
        f"{s['window_p95_ms_overall']} ms |",
        f"| Worst per-interval p95 / slowest window | {s['window_p95_ms_worst_interval']} / {s['window_max_ms']} ms |",
        f"| Alerts | {s['alerts']:,} ({s['alerts_per_hour']:,.1f} per wall-clock hour) |",
        f"| Alerts by class | {', '.join(f'{k} {v}' for k, v in sorted(s['alerts_by_class'].items())) or '-'} |",
        f"| Alerts by severity | {', '.join(f'{k} {v}' for k, v in sorted(s['alerts_by_severity'].items())) or '-'} |",
        f"| Attacks injected | {', '.join(f'{k} {v}' for k, v in sorted(s['attacks_injected'].items())) or '-'} |",
        f"| Asset policy | {s['asset_policy']['downgraded_to_info']} alerts downgraded to INFO, "
        f"{s['asset_policy']['suppressed']} suppressed |",
    ]
    if s["state"]:
        st = s["state"]
        lines.append(f"| State snapshots | {st['saves']} written, {st['save_errors']} failed; last "
                     f"{st['last_save'].get('bytes', 0) / 1e6:.2f} MB in {st['last_save'].get('ms', 0)} ms |")
    lines.append(f"| Final state sizes | {', '.join(f'{k} {v:,}' for k, v in s['final_state_sizes'].items())} |")

    samples = report["samples"]
    step = max(1, len(samples) // 60)
    shown = samples[::step] if samples[-1] in samples[::step] else samples[::step] + [samples[-1]]
    lines += ["", "## Samples", "",
              f"One row per sample{f' (every {step}th sample shown)' if step > 1 else ''}; window latencies are "
              "for the windows closed in that interval, alerts are those emitted in it.", "",
              "| Elapsed | Traffic time | Records/s | Lag s | RSS MB | CPU % | Window p50 / p95 / max ms "
              "| Alerts | Beacon pairs | Baselines | Snapshot MB / ms |",
              "|---|---|---|---|---|---|---|---|---|---|---|"]
    for x in shown:
        snap = x["snapshot"]
        lines.append(
            f"| {_fmt_duration(x['elapsed_sec'])} | {(x['traffic_time'] or '')[11:19]} | {x['records_per_sec']:,.0f} "
            f"| {x['max_lag_sec']:.3f} | {x['rss_mb']} | {x['cpu_percent']} "
            f"| {x['window_p50_ms']} / {x['window_p95_ms']} / {x['window_max_ms']} | {x['alerts']} "
            f"| {x['state'].get('beacon_pairs', 0):,} | {x['state'].get('upload_baselines', 0):,} "
            f"| {f'{snap['bytes'] / 1e6:.2f} / {snap['ms']}' if snap else '-'} |")
    if notes:
        lines += ["", "## Notes", "", notes]
    return "\n".join(lines) + "\n"
