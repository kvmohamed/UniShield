"""
UniShield — Account Store

Users, login sessions and service tokens on the alert database's engine.

- Usernames are lower-case ``[a-z0-9][a-z0-9_.-]{2,63}``.
- Passwords are Argon2id hashes (``accounts.passwords``).
- A session is a random 256-bit value in an HttpOnly cookie; the database
  keeps its SHA-256, the CSRF token bound to it, an absolute expiry and the
  time it was last used (for the idle timeout).
- A service token (``X-API-Key``) is ``us_`` + a random 256-bit value with a
  fixed role, optional expiry and revocation; the database keeps its SHA-256.
- After ``max_failed`` consecutive wrong passwords an account is locked for
  ``lockout_minutes``; while locked, even the right password is refused.
- The last active administrator cannot be demoted, disabled or deleted.

Times are stored as naive UTC and returned timezone-aware.
"""

from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from sqlalchemy import and_, delete, func, insert, or_, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

from unishield.accounts import passwords
from unishield.accounts.roles import Role
from unishield.storage.database import api_tokens_table, sessions_table, users_table, write_lock

USERNAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,63}$")
TOKEN_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}$")
RESERVED_USERNAMES = {"system", "anonymous"}
TOKEN_PREFIX = "us_"
_TOUCH_INTERVAL = timedelta(seconds=30)        # how stale last_seen_at / last_used_at may get


class AccountError(ValueError):
    """Invalid input: a malformed name, an unknown role, or a password that fails the policy."""


class AccountConflict(Exception):
    """The change conflicts with existing state (name taken, last administrator, not found)."""


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _aware(value: Optional[datetime]) -> Optional[datetime]:
    return value.replace(tzinfo=timezone.utc) if value is not None and value.tzinfo is None else value


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def normalise_username(username: str) -> str:
    name = (username or "").strip().lower()
    if not USERNAME_PATTERN.match(name):
        raise AccountError("Username must be 3-64 characters: a-z, 0-9, '_', '.', '-', starting with a letter "
                           "or digit")
    if name in RESERVED_USERNAMES:
        raise AccountError(f"Username {name!r} is reserved")
    return name


def parse_role(role: str | Role) -> Role:
    try:
        return Role(role)
    except ValueError:
        raise AccountError(f"Unknown role {role!r}; choose one of {[r.value for r in Role]}") from None


@dataclass(frozen=True)
class User:
    id: int
    username: str
    role: Role
    disabled: bool
    failed_logins: int
    locked_until: Optional[datetime]
    created_at: datetime
    created_by: Optional[str]
    password_changed_at: Optional[datetime]
    last_login_at: Optional[datetime]

    def locked(self, now: datetime) -> bool:
        return self.locked_until is not None and self.locked_until > now

    def public(self, now: Optional[datetime] = None) -> dict:
        now = now or datetime.now(timezone.utc)
        iso = lambda v: v.isoformat() if v else None                      # noqa: E731
        return {"username": self.username, "role": self.role.value, "disabled": self.disabled,
                "locked": self.locked(now), "locked_until": iso(self.locked_until) if self.locked(now) else None,
                "created_at": iso(self.created_at), "created_by": self.created_by,
                "password_changed_at": iso(self.password_changed_at), "last_login_at": iso(self.last_login_at)}


@dataclass(frozen=True)
class Session:
    id: str                      # SHA-256 of the cookie value
    user: User
    csrf_token: str
    created_at: datetime
    expires_at: datetime
    last_seen_at: datetime


@dataclass(frozen=True)
class ServiceToken:
    id: int
    name: str
    role: Role
    created_at: datetime
    created_by: Optional[str]
    expires_at: Optional[datetime]
    last_used_at: Optional[datetime]
    revoked_at: Optional[datetime]

    def public(self) -> dict:
        iso = lambda v: v.isoformat() if v else None                      # noqa: E731
        return {"name": self.name, "role": self.role.value, "created_at": iso(self.created_at),
                "created_by": self.created_by, "expires_at": iso(self.expires_at),
                "last_used_at": iso(self.last_used_at), "revoked_at": iso(self.revoked_at)}


@dataclass(frozen=True)
class LoginResult:
    user: Optional[User]
    reason: str                  # ok | unknown_user | bad_password | locked | disabled
    locked_now: bool = False     # this failure locked the account

    @property
    def ok(self) -> bool:
        return self.reason == "ok"


def _user(row) -> User:
    m = row._mapping
    return User(id=m["id"], username=m["username"], role=Role(m["role"]), disabled=bool(m["disabled"]),
                failed_logins=m["failed_logins"] or 0, locked_until=_aware(m["locked_until"]),
                created_at=_aware(m["created_at"]), created_by=m["created_by"],
                password_changed_at=_aware(m["password_changed_at"]), last_login_at=_aware(m["last_login_at"]))


def _token(row) -> ServiceToken:
    m = row._mapping
    return ServiceToken(id=m["id"], name=m["name"], role=Role(m["role"]), created_at=_aware(m["created_at"]),
                        created_by=m["created_by"], expires_at=_aware(m["expires_at"]),
                        last_used_at=_aware(m["last_used_at"]), revoked_at=_aware(m["revoked_at"]))


class AccountStore:
    """Users, sessions and service tokens. ``clock`` returns naive UTC (tests replace it)."""

    def __init__(self, engine: Engine, clock: Callable[[], datetime] = _utcnow):
        self.engine = engine
        self.clock = clock
        self._lock = write_lock(engine)

    def now(self) -> datetime:
        return _aware(self.clock())

    # --- users ---------------------------------------------------------------

    def get_user(self, username: str) -> Optional[User]:
        try:
            name = normalise_username(username)
        except AccountError:
            return None
        with self.engine.connect() as conn:
            row = conn.execute(select(users_table).where(users_table.c.username == name)).first()
        return _user(row) if row is not None else None

    def list_users(self) -> list[User]:
        with self.engine.connect() as conn:
            return [_user(r) for r in conn.execute(select(users_table).order_by(users_table.c.username)).all()]

    def has_users(self) -> bool:
        with self.engine.connect() as conn:
            return conn.execute(select(func.count()).select_from(users_table)).scalar_one() > 0

    def active_admin_count(self, conn=None) -> int:
        stmt = select(func.count()).select_from(users_table).where(
            users_table.c.role == Role.ADMIN.value, users_table.c.disabled == False)       # noqa: E712
        if conn is not None:
            return conn.execute(stmt).scalar_one()
        with self.engine.connect() as c:
            return c.execute(stmt).scalar_one()

    def create_user(self, username: str, password: str, role: str | Role, created_by: Optional[str] = None,
                    min_password_length: int = 12) -> User:
        name = normalise_username(username)
        role = parse_role(role)
        try:
            passwords.check_policy(name, password, min_password_length)
        except passwords.PasswordPolicyError as exc:
            raise AccountError(str(exc)) from None
        now = self.clock()
        values = dict(username=name, password_hash=passwords.hash_password(password), role=role.value,
                      disabled=False, failed_logins=0, created_at=now, created_by=created_by, updated_at=now,
                      password_changed_at=now)
        try:
            with self._lock, self.engine.begin() as conn:
                conn.execute(insert(users_table).values(**values))
        except IntegrityError:
            raise AccountConflict(f"User {name!r} already exists") from None
        return self.get_user(name)

    def _require(self, conn, username: str):
        name = normalise_username(username)
        row = conn.execute(select(users_table).where(users_table.c.username == name)).first()
        if row is None:
            raise AccountConflict(f"No user named {name!r}")
        return _user(row)

    def _guard_last_admin(self, conn, user: User, new_role: Role, new_disabled: bool) -> None:
        was_active_admin = user.role == Role.ADMIN and not user.disabled
        stays_active_admin = new_role == Role.ADMIN and not new_disabled
        if was_active_admin and not stays_active_admin and self.active_admin_count(conn) <= 1:
            raise AccountConflict("Cannot remove the last active administrator")

    def update_user(self, username: str, *, role: str | Role | None = None,
                    disabled: Optional[bool] = None) -> tuple[User, User]:
        """Change role and/or disabled flag; revokes the user's sessions. Returns (before, after)."""
        new_role = parse_role(role) if role is not None else None
        with self._lock, self.engine.begin() as conn:
            user = self._require(conn, username)
            target_role = new_role or user.role
            target_disabled = user.disabled if disabled is None else bool(disabled)
            self._guard_last_admin(conn, user, target_role, target_disabled)
            conn.execute(update(users_table).where(users_table.c.id == user.id).values(
                role=target_role.value, disabled=target_disabled, updated_at=self.clock()))
            if (target_role, target_disabled) != (user.role, user.disabled):
                conn.execute(delete(sessions_table).where(sessions_table.c.user_id == user.id))
        return user, self.get_user(user.username)

    def set_password(self, username: str, password: str, min_password_length: int = 12,
                     keep_session_id: Optional[str] = None) -> User:
        """Replace the password, clear any lockout and end the user's other sessions."""
        name = normalise_username(username)
        try:
            passwords.check_policy(name, password, min_password_length)
        except passwords.PasswordPolicyError as exc:
            raise AccountError(str(exc)) from None
        password_hash = passwords.hash_password(password)
        with self._lock, self.engine.begin() as conn:
            user = self._require(conn, name)
            now = self.clock()
            conn.execute(update(users_table).where(users_table.c.id == user.id).values(
                password_hash=password_hash, password_changed_at=now, updated_at=now, failed_logins=0,
                locked_until=None))
            condition = sessions_table.c.user_id == user.id
            if keep_session_id:
                condition = and_(condition, sessions_table.c.id != keep_session_id)
            conn.execute(delete(sessions_table).where(condition))
        return self.get_user(name)

    def unlock(self, username: str) -> User:
        with self._lock, self.engine.begin() as conn:
            user = self._require(conn, username)
            conn.execute(update(users_table).where(users_table.c.id == user.id).values(
                failed_logins=0, locked_until=None, updated_at=self.clock()))
        return self.get_user(user.username)

    def delete_user(self, username: str) -> User:
        with self._lock, self.engine.begin() as conn:
            user = self._require(conn, username)
            self._guard_last_admin(conn, user, Role.VIEWER, True)
            conn.execute(delete(sessions_table).where(sessions_table.c.user_id == user.id))
            conn.execute(delete(users_table).where(users_table.c.id == user.id))
        return user

    # --- login ---------------------------------------------------------------

    def authenticate(self, username: str, password: str, max_failed: int, lockout_minutes: int) -> LoginResult:
        """Check a password, applying and maintaining the lockout. Takes the same time for unknown users."""
        user = self.get_user(username)
        now = self.now()
        if user is None:
            passwords.dummy_verify(password)
            return LoginResult(None, "unknown_user")
        if user.locked(now):
            passwords.dummy_verify(password)
            return LoginResult(user, "locked")
        with self.engine.connect() as conn:
            stored_hash = conn.execute(select(users_table.c.password_hash)
                                       .where(users_table.c.id == user.id)).scalar_one()
        if not passwords.verify_password(stored_hash, password):
            with self._lock, self.engine.begin() as conn:
                failures = conn.execute(select(users_table.c.failed_logins)
                                        .where(users_table.c.id == user.id)).scalar_one() + 1
                locked_now = failures >= max_failed
                values: dict = {"failed_logins": failures}
                if locked_now:
                    values = {"failed_logins": 0, "locked_until": self.clock() + timedelta(minutes=lockout_minutes)}
                conn.execute(update(users_table).where(users_table.c.id == user.id).values(**values))
            return LoginResult(user, "bad_password", locked_now)
        if user.disabled:
            return LoginResult(user, "disabled")
        values = {"failed_logins": 0, "locked_until": None, "last_login_at": self.clock()}
        if passwords.needs_rehash(stored_hash):
            values["password_hash"] = passwords.hash_password(password)
        with self._lock, self.engine.begin() as conn:
            conn.execute(update(users_table).where(users_table.c.id == user.id).values(**values))
        return LoginResult(self.get_user(user.username), "ok")

    # --- sessions ------------------------------------------------------------

    def create_session(self, user: User, ttl_minutes: int, client_ip: Optional[str] = None,
                       user_agent: Optional[str] = None) -> tuple[str, Session]:
        """New session for ``user``: (cookie value, session)."""
        raw = secrets.token_urlsafe(32)
        now = self.clock()
        values = dict(id=_digest(raw), user_id=user.id, csrf_token=secrets.token_urlsafe(32), created_at=now,
                      expires_at=now + timedelta(minutes=ttl_minutes), last_seen_at=now,
                      client_ip=(client_ip or "")[:64] or None, user_agent=(user_agent or "")[:256] or None)
        with self._lock, self.engine.begin() as conn:
            conn.execute(insert(sessions_table).values(**values))
        return raw, Session(id=values["id"], user=user, csrf_token=values["csrf_token"], created_at=_aware(now),
                            expires_at=_aware(values["expires_at"]), last_seen_at=_aware(now))

    def resolve_session(self, raw: str, idle_minutes: int) -> Optional[Session]:
        """The live session for a cookie value, or None (unknown, expired, idle, or user disabled)."""
        if not raw or len(raw) > 128:
            return None
        sid = _digest(raw)
        with self.engine.connect() as conn:
            row = conn.execute(select(sessions_table).where(sessions_table.c.id == sid)).first()
            user_row = conn.execute(select(users_table).where(users_table.c.id == row.user_id)).first()                 if row is not None else None
        if row is None:
            return None
        m = row._mapping
        now = self.clock()
        user = _user(user_row) if user_row is not None else None
        if (user is None or user.disabled or m["expires_at"] <= now
                or m["last_seen_at"] + timedelta(minutes=idle_minutes) <= now):
            with self._lock, self.engine.begin() as conn:
                conn.execute(delete(sessions_table).where(sessions_table.c.id == sid))
            return None
        last_seen = m["last_seen_at"]
        if now - last_seen >= _TOUCH_INTERVAL:
            with self._lock, self.engine.begin() as conn:
                conn.execute(update(sessions_table).where(sessions_table.c.id == sid).values(last_seen_at=now))
            last_seen = now
        return Session(id=sid, user=user, csrf_token=m["csrf_token"], created_at=_aware(m["created_at"]),
                       expires_at=_aware(m["expires_at"]), last_seen_at=_aware(last_seen))

    def delete_session(self, session_id: str) -> None:
        with self._lock, self.engine.begin() as conn:
            conn.execute(delete(sessions_table).where(sessions_table.c.id == session_id))

    def revoke_sessions(self, username: str) -> int:
        with self._lock, self.engine.begin() as conn:
            user = self._require(conn, username)
            return conn.execute(delete(sessions_table).where(sessions_table.c.user_id == user.id)).rowcount or 0

    def purge_expired_sessions(self, idle_minutes: int) -> int:
        now = self.clock()
        with self._lock, self.engine.begin() as conn:
            return conn.execute(delete(sessions_table).where(or_(
                sessions_table.c.expires_at <= now,
                sessions_table.c.last_seen_at <= now - timedelta(minutes=idle_minutes)))).rowcount or 0

    # --- service tokens --------------------------------------------------------

    def create_token(self, name: str, role: str | Role, expires_at: Optional[datetime] = None,
                     created_by: Optional[str] = None) -> tuple[str, ServiceToken]:
        """New service token: (the token, shown once; its record)."""
        name = (name or "").strip().lower()
        if not TOKEN_NAME_PATTERN.match(name):
            raise AccountError("Token name must be 1-64 characters: a-z, 0-9, '_', '.', '-'")
        role = parse_role(role)
        raw = TOKEN_PREFIX + secrets.token_urlsafe(32)
        if expires_at is not None and expires_at.tzinfo is not None:
            expires_at = expires_at.astimezone(timezone.utc).replace(tzinfo=None)
        values = dict(name=name, token_hash=_digest(raw), role=role.value, created_at=self.clock(),
                      created_by=created_by, expires_at=expires_at)
        try:
            with self._lock, self.engine.begin() as conn:
                conn.execute(insert(api_tokens_table).values(**values))
        except IntegrityError:
            raise AccountConflict(f"A token named {name!r} already exists (revoked tokens keep their name)") from None
        return raw, self.get_token(name)

    def get_token(self, name: str) -> Optional[ServiceToken]:
        with self.engine.connect() as conn:
            row = conn.execute(select(api_tokens_table).where(api_tokens_table.c.name == name.lower())).first()
        return _token(row) if row is not None else None

    def list_tokens(self) -> list[ServiceToken]:
        with self.engine.connect() as conn:
            return [_token(r) for r in conn.execute(select(api_tokens_table).order_by(api_tokens_table.c.name))]

    def resolve_token(self, raw: str) -> Optional[ServiceToken]:
        """The valid token for an X-API-Key value, or None (unknown, revoked or expired)."""
        if not raw or not raw.startswith(TOKEN_PREFIX) or len(raw) > 128:
            return None
        with self.engine.connect() as conn:
            row = conn.execute(select(api_tokens_table).where(api_tokens_table.c.token_hash == _digest(raw))).first()
        if row is None:
            return None
        token = _token(row)
        now = self.now()
        if token.revoked_at is not None or (token.expires_at is not None and token.expires_at <= now):
            return None
        if token.last_used_at is None or now - token.last_used_at >= _TOUCH_INTERVAL:
            with self._lock, self.engine.begin() as conn:
                conn.execute(update(api_tokens_table).where(api_tokens_table.c.id == token.id)
                             .values(last_used_at=self.clock()))
        return token

    def revoke_token(self, name: str) -> ServiceToken:
        with self._lock, self.engine.begin() as conn:
            result = conn.execute(update(api_tokens_table).where(
                api_tokens_table.c.name == (name or "").lower(), api_tokens_table.c.revoked_at.is_(None))
                .values(revoked_at=self.clock()))
        if not result.rowcount:
            raise AccountConflict(f"No active token named {name!r}")
        return self.get_token(name)
