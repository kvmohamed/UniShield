"""Unit tests for the event-time sliding window (audit D1, D2, D11, D12)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from unishield.processing.window import SlidingWindow
from unishield.schemas.flow import NormalisedFlow

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)      # on the 5-second grid


def flow(t: float, **kw) -> NormalisedFlow:
    return NormalisedFlow(timestamp=T0 + timedelta(seconds=t), source_ip="10.0.0.1",
                          destination_ip="10.0.0.2", **kw)


def bounds(window):
    return ((window.start - T0).total_seconds(), (window.end - T0).total_seconds())


def test_windows_are_aligned_to_the_grid_and_close_on_event_time():
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5)
    assert w.add(flow(1)) == []
    assert w.add(flow(4.9)) == []
    closed = w.add(flow(5.0))                     # event time reaches 5 → [-5, 5) closes
    assert [bounds(c) for c in closed] == [(-5.0, 5.0)]
    assert [len(c.records) for c in closed] == [2]
    closed = w.add(flow(12))                      # passes 10 → [0, 10) closes
    assert [bounds(c) for c in closed] == [(0.0, 10.0)]
    assert len(closed[0].records) == 3            # 1, 4.9, 5.0


def test_each_record_appears_in_size_over_slide_windows():
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5)
    windows = []
    for t in range(0, 60):
        windows += w.add(flow(t + 0.5))
    windows += w.flush()
    appearances = {}
    for win in windows:
        for r in win.records:
            appearances[r.event_id] = appearances.get(r.event_id, 0) + 1
    assert set(appearances.values()) == {2}


def test_flush_analyses_short_input():
    """A 3-second capture never fills a window; flush must still analyse it (D1)."""
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5)
    for i in range(30):
        assert w.add(flow(0.1 * i)) == []
    closed = w.flush()
    assert [bounds(c) for c in closed] == [(-5.0, 5.0), (0.0, 10.0)]
    assert all(len(c.records) == 30 for c in closed)
    assert w.size == 0


def test_observed_seconds_covers_only_the_observed_span():
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5)
    for i in range(31):
        w.add(flow(0.1 * i))                      # input spans 0 .. 3.0 s
    first, second = w.flush()
    assert first.observed_seconds == pytest.approx(3.0)
    assert second.observed_seconds == pytest.approx(3.0)


def test_observed_seconds_is_the_full_window_after_a_quiet_period():
    """One flow after 30 s of silence: the silence was observed, so rates use 10 s (D2)."""
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5)
    w.add(flow(0))
    w.add(flow(31))
    closed = w.add(flow(45))                      # closes windows holding the t=31 flow
    holding = [c for c in closed if any(r.timestamp == T0 + timedelta(seconds=31) for r in c.records)]
    assert holding and all(c.observed_seconds == pytest.approx(10.0) for c in holding)


def test_minimum_observed_duration():
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5, min_observed_sec=1.0)
    w.add(flow(1.0))
    w.add(flow(1.001))
    assert all(c.observed_seconds == 1.0 for c in w.flush())


def test_empty_windows_are_skipped_and_counted():
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5)
    w.add(flow(0))
    closed = w.add(flow(3600))                    # one hour gap
    assert len(closed) == 2                       # only the windows holding t=0
    assert w.empty_windows > 700
    assert w.stats()["windows_emitted"] == 2


def test_late_records_are_dropped_and_counted():
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5)
    w.add(flow(0))
    w.add(flow(20))                               # windows ending <= 20 closed; oldest open: [15, 25)
    assert w.add(flow(12)) == []                  # older than every open window
    assert w.late_dropped == 1
    w.add(flow(16))                               # inside the open window [15, 25): accepted
    assert w.late_dropped == 1 and w.size == 2


def test_allowed_lateness_accepts_out_of_order_records():
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5, allowed_lateness_sec=5)
    w.add(flow(1))
    assert w.add(flow(7)) == []                   # watermark 7 - 5 = 2: nothing closes yet
    assert w.add(flow(3)) == []                   # out of order but accepted
    closed = w.add(flow(11))                      # watermark 6 → [-5, 5) closes
    assert [len(c.records) for c in closed] == [2]
    assert w.late_dropped == 0


def test_advance_closes_windows_without_new_records():
    w = SlidingWindow(window_size_sec=10, slide_interval_sec=5)
    w.add(flow(1))
    closed = w.advance(T0 + timedelta(seconds=11))
    assert [bounds(c) for c in closed] == [(-5.0, 5.0), (0.0, 10.0)]


def test_capacity_evicts_oldest_and_counts():
    w = SlidingWindow(window_size_sec=100, slide_interval_sec=50, max_records=5)
    for i in range(10):
        w.add(flow(i))
    assert w.size == 5 and w.overflow_evicted == 5


def test_invalid_configuration_rejected():
    with pytest.raises(ValueError):
        SlidingWindow(window_size_sec=5, slide_interval_sec=10)
    with pytest.raises(ValueError):
        SlidingWindow(window_size_sec=10, slide_interval_sec=0)
