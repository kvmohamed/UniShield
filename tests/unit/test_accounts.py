"""Account store: users, password policy and hashing, lockout, sessions, service tokens; admin CLI."""

from __future__ import annotations

import io
from datetime import datetime, timedelta, timezone

import pytest

from unishield import cli
from unishield.accounts import AccountConflict, AccountError, AccountStore, Role
from unishield.accounts import passwords
from unishield.storage import AuditLog
from unishield.storage.database import make_engine

PASSWORD = "correct horse battery"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 10, 22, 12, 0, 0)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def store(clock):
    return AccountStore(make_engine("sqlite://"), clock=clock)


def test_roles_are_ordered():
    assert Role.ADMIN.allows(Role.ANALYST) and Role.ANALYST.allows(Role.VIEWER) and Role.VIEWER.allows(Role.VIEWER)
    assert not Role.VIEWER.allows(Role.ANALYST) and not Role.ANALYST.allows(Role.ADMIN)


def test_passwords_are_argon2id_hashes():
    h = passwords.hash_password(PASSWORD)
    assert h.startswith("$argon2id$") and PASSWORD not in h
    assert passwords.verify_password(h, PASSWORD) and not passwords.verify_password(h, PASSWORD + "x")
    assert not passwords.verify_password("not-a-hash", PASSWORD)
    assert not passwords.verify_password(h, "x" * 2000)
    assert passwords.hash_password(PASSWORD) != h                          # salted


def test_default_hasher_uses_rfc9106_parameters():
    from argon2 import PasswordHasher

    default = PasswordHasher()
    assert (default.time_cost, default.memory_cost, default.parallelism) == (3, 65536, 4)


@pytest.mark.parametrize("username,password,message", [
    ("alice", "short", "at least 12"),
    ("alice", "x" * 1025, "at most"),
    ("alice", "my-alice-password", "username"),
    ("alice", "aaaaaaaaaaaaaaaa", "4 different"),
])
def test_password_policy(store, username, password, message):
    with pytest.raises(AccountError, match=message):
        store.create_user(username, password, "viewer")


@pytest.mark.parametrize("username", ["ab", "Bad Name", "-dash", "x" * 65, "system", "anonymous", "a/b"])
def test_username_rules(store, username):
    with pytest.raises(AccountError):
        store.create_user(username, PASSWORD, "viewer")


def test_create_get_list_and_duplicates(store):
    user = store.create_user("Alice", PASSWORD, "admin", created_by="cli:test")
    assert user.username == "alice" and user.role == Role.ADMIN and not user.disabled
    assert store.get_user("ALICE") == user and store.get_user("nobody") is None
    with pytest.raises(AccountConflict):
        store.create_user("alice", PASSWORD, "viewer")
    with pytest.raises(AccountError):
        store.create_user("bob", PASSWORD, "superuser")
    store.create_user("bob", PASSWORD, "viewer")
    assert [u.username for u in store.list_users()] == ["alice", "bob"]
    assert "password_hash" not in user.public() and user.public()["role"] == "admin"


def test_authenticate_and_lockout(store, clock):
    store.create_user("alice", PASSWORD, "analyst")
    assert store.authenticate("alice", PASSWORD, 3, 15).ok
    assert store.authenticate("nobody", PASSWORD, 3, 15).reason == "unknown_user"
    results = [store.authenticate("alice", "wrong password!", 3, 15) for _ in range(3)]
    assert [r.reason for r in results] == ["bad_password"] * 3 and [r.locked_now for r in results] == [0, 0, 1]
    locked = store.authenticate("alice", PASSWORD, 3, 15)
    assert locked.reason == "locked" and store.get_user("alice").public(store.now())["locked"]
    clock.advance(minutes=14)
    assert store.authenticate("alice", PASSWORD, 3, 15).reason == "locked"
    clock.advance(minutes=2)
    ok = store.authenticate("alice", PASSWORD, 3, 15)
    assert ok.ok and ok.user.failed_logins == 0 and ok.user.last_login_at is not None


def test_success_resets_failure_count(store):
    store.create_user("alice", PASSWORD, "viewer")
    for _ in range(2):
        store.authenticate("alice", "wrong password!", 3, 15)
    assert store.authenticate("alice", PASSWORD, 3, 15).ok
    for _ in range(2):
        store.authenticate("alice", "wrong password!", 3, 15)
    assert store.authenticate("alice", PASSWORD, 3, 15).ok                 # never reached 3 in a row


def test_unlock_and_disabled_accounts(store):
    store.create_user("alice", PASSWORD, "viewer")
    for _ in range(3):
        store.authenticate("alice", "wrong password!", 3, 15)
    store.unlock("alice")
    assert store.authenticate("alice", PASSWORD, 3, 15).ok
    store.create_user("admin1", PASSWORD, "admin")
    store.update_user("alice", disabled=True)
    assert store.authenticate("alice", PASSWORD, 3, 15).reason == "disabled"


def test_password_is_rehashed_when_parameters_change(store, monkeypatch):
    from argon2 import PasswordHasher

    store.create_user("alice", PASSWORD, "viewer")
    stronger = PasswordHasher(time_cost=2, memory_cost=16, parallelism=1)
    monkeypatch.setattr(passwords, "_hasher", stronger)
    assert store.authenticate("alice", PASSWORD, 3, 15).ok
    from sqlalchemy import select

    from unishield.storage.database import users_table

    with store.engine.connect() as conn:
        stored = conn.execute(select(users_table.c.password_hash)).scalar_one()
    assert "t=2" in stored and not stronger.check_needs_rehash(stored)


def test_last_active_admin_is_protected(store):
    store.create_user("root1", PASSWORD, "admin")
    with pytest.raises(AccountConflict, match="last active administrator"):
        store.update_user("root1", role="viewer")
    with pytest.raises(AccountConflict):
        store.update_user("root1", disabled=True)
    with pytest.raises(AccountConflict):
        store.delete_user("root1")
    store.create_user("root2", PASSWORD, "admin")
    before, after = store.update_user("root1", role="viewer")
    assert before.role == Role.ADMIN and after.role == Role.VIEWER
    with pytest.raises(AccountConflict):
        store.delete_user("root2")
    with pytest.raises(AccountConflict, match="No user"):
        store.delete_user("ghost")


def test_sessions_expire_absolute_and_idle(store, clock):
    user = store.create_user("alice", PASSWORD, "viewer")
    raw, session = store.create_session(user, ttl_minutes=60, client_ip="10.0.0.1", user_agent="pytest")
    assert len(raw) >= 43 and session.id != raw and len(session.csrf_token) >= 43
    assert store.resolve_session(raw, idle_minutes=20).user.username == "alice"
    assert store.resolve_session(raw + "x", idle_minutes=20) is None and store.resolve_session("", 20) is None
    for _ in range(5):                                                     # activity keeps it alive...
        clock.advance(minutes=10)
        assert store.resolve_session(raw, idle_minutes=20) is not None
    clock.advance(minutes=11)                                              # ...until the absolute expiry
    assert store.resolve_session(raw, idle_minutes=20) is None

    raw, _ = store.create_session(user, ttl_minutes=60)
    clock.advance(minutes=21)
    assert store.resolve_session(raw, idle_minutes=20) is None             # idle timeout


def test_session_ids_are_stored_hashed(store):
    from sqlalchemy import select

    from unishield.storage.database import sessions_table

    user = store.create_user("alice", PASSWORD, "viewer")
    raw, session = store.create_session(user, ttl_minutes=60)
    with store.engine.connect() as conn:
        stored = conn.execute(select(sessions_table.c.id)).scalar_one()
    assert stored == session.id and raw not in stored


def test_role_change_password_change_and_disable_end_sessions(store):
    store.create_user("root1", PASSWORD, "admin")
    user = store.create_user("alice", PASSWORD, "viewer")
    keep, kept = store.create_session(user, 60)
    other, _ = store.create_session(user, 60)
    store.set_password("alice", "another good password", keep_session_id=kept.id)
    assert store.resolve_session(keep, 30) is not None and store.resolve_session(other, 30) is None
    store.update_user("alice", role="analyst")
    assert store.resolve_session(keep, 30) is None
    raw, _ = store.create_session(store.get_user("alice"), 60)
    store.update_user("alice", disabled=True)
    assert store.resolve_session(raw, 30) is None
    assert store.purge_expired_sessions(30) == 0


def test_service_tokens(store, clock):
    raw, token = store.create_token("SIEM", "viewer", created_by="cli:test")
    assert raw.startswith("us_") and token.name == "siem" and token.role == Role.VIEWER
    assert store.resolve_token(raw).name == "siem"
    assert store.resolve_token("us_wrong") is None and store.resolve_token("no-prefix") is None
    assert store.get_token("siem").last_used_at is not None
    with pytest.raises(AccountConflict):
        store.create_token("siem", "admin")
    store.revoke_token("siem")
    assert store.resolve_token(raw) is None
    with pytest.raises(AccountConflict):
        store.revoke_token("siem")
    raw, _ = store.create_token("ci", "admin", expires_at=datetime(2026, 10, 23, 12, tzinfo=timezone.utc))
    assert store.resolve_token(raw) is not None
    clock.advance(days=1, seconds=1)
    assert store.resolve_token(raw) is None
    with pytest.raises(AccountError):
        store.create_token("bad name", "viewer")


# --- CLI ------------------------------------------------------------------------

def _run(monkeypatch, url, *argv, stdin=""):
    monkeypatch.setattr("sys.stdin", io.StringIO(stdin))
    return cli.main(["--db-url", url, *argv])


def test_cli_creates_first_admin_and_manages_users(tmp_path, monkeypatch, capsys):
    url = f"sqlite:///{(tmp_path / 'cli.db').as_posix()}"
    assert _run(monkeypatch, url, "user", "list") == 0
    assert "No users" in capsys.readouterr().out
    assert _run(monkeypatch, url, "user", "create", "root", "--role", "admin", "--password-stdin",
                stdin=PASSWORD + "\n") == 0
    assert _run(monkeypatch, url, "user", "create", "eve", "--role", "viewer", "--password-stdin",
                stdin="short\n") == 1
    assert "at least 12" in capsys.readouterr().err
    assert _run(monkeypatch, url, "user", "create", "eve", "--role", "viewer", "--password-stdin",
                stdin=PASSWORD + "\n") == 0
    assert _run(monkeypatch, url, "user", "set-role", "eve", "analyst") == 0
    assert _run(monkeypatch, url, "user", "set-role", "root", "viewer") == 1        # last admin
    assert _run(monkeypatch, url, "user", "disable", "eve") == 0
    assert _run(monkeypatch, url, "user", "enable", "eve") == 0
    assert _run(monkeypatch, url, "user", "unlock", "eve") == 0
    assert _run(monkeypatch, url, "user", "set-password", "eve", "--password-stdin",
                stdin="a fresh long password\n") == 0
    capsys.readouterr()
    assert _run(monkeypatch, url, "user", "list") == 0
    listing = capsys.readouterr().out
    assert "root" in listing and "analyst" in listing
    assert _run(monkeypatch, url, "user", "delete", "eve") == 0

    store = AccountStore(make_engine(url))
    assert store.authenticate("root", PASSWORD, 5, 15).ok
    entries, _ = AuditLog(store.engine).list()
    assert [e["action"] for e in entries][::-1] == [
        "user.create", "user.create", "user.update", "user.update", "user.update", "user.unlock",
        "user.password_reset", "user.delete"]
    assert all(e["actor"].startswith("cli:") and e["actor_type"] == "cli" for e in entries)


def test_cli_tokens(tmp_path, monkeypatch, capsys):
    url = f"sqlite:///{(tmp_path / 'cli.db').as_posix()}"
    assert _run(monkeypatch, url, "token", "create", "--name", "siem", "--role", "viewer",
                "--expires-days", "30") == 0
    raw = capsys.readouterr().out.strip().splitlines()[-1]
    store = AccountStore(make_engine(url))
    assert store.resolve_token(raw).role == Role.VIEWER
    assert _run(monkeypatch, url, "token", "list") == 0
    assert "siem" in capsys.readouterr().out
    assert _run(monkeypatch, url, "token", "revoke", "siem") == 0
    assert store.resolve_token(raw) is None
    assert _run(monkeypatch, url, "token", "revoke", "siem") == 1
    assert _run(monkeypatch, url, "token", "create", "--name", "x", "--role", "admin", "--expires-days", "0") == 1
    actions = [e["action"] for e in AuditLog(store.engine).list()[0]]
    assert actions == ["token.revoke", "token.create"]
    assert raw not in str(AuditLog(store.engine).list()[0])


def test_rate_limiter_window_and_bounds():
    from unishield.accounts.ratelimit import LoginRateLimiter

    now = [1000.0]
    limiter = LoginRateLimiter(limit=3, window_sec=60, max_keys=2, clock=lambda: now[0])
    assert [limiter.failure("a") for _ in range(3)] == [False, False, True]
    assert limiter.retry_after("a") == 60 and limiter.retry_after("b") == 0
    now[0] += 30
    assert limiter.retry_after("a") == 30
    now[0] += 30.5
    assert limiter.retry_after("a") == 0                                  # the oldest failures left the window
    limiter.failure("b")
    limiter.failure("c")
    limiter.failure("d")                                                  # evicts the least recently used key
    assert set(limiter._failures) == {"c", "d"}
