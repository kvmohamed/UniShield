"""In-memory SQLite shares one connection: a reader closing it must never undo another thread's write."""

from __future__ import annotations

import threading

from sqlalchemy import insert, select

from unishield.storage import AlertRepository
from unishield.storage.database import runs_table


def test_reader_cannot_roll_back_a_concurrent_write():
    repo = AlertRepository.from_url("sqlite://")
    reader_done = threading.Event()

    def reader():
        with repo.engine.connect() as conn:          # used to roll back the writer's open transaction on close
            conn.execute(select(1))
        reader_done.set()

    with repo.engine.begin() as conn:
        conn.execute(insert(runs_table).values(run_id="r1", source="s", detection_mode="rules",
                                               status="running"))
        thread = threading.Thread(target=reader)
        thread.start()
        # With the guard the reader waits for this transaction to end instead of running inside it.
        assert not reader_done.wait(0.3)
    thread.join(5)
    assert reader_done.is_set()
    with repo.engine.connect() as conn:
        assert conn.execute(select(runs_table.c.run_id)).scalars().all() == ["r1"]


def test_nested_use_in_one_thread_does_not_deadlock():
    repo = AlertRepository.from_url("sqlite://")
    with repo.engine.connect() as outer:
        outer.execute(select(1))
        assert repo.ping() and repo.count() == 0
