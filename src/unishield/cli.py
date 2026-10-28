"""
UniShield — Administration CLI (``unishield-admin``)

Local administration of the UniShield database. It works on the database
named by ``--db-url``, ``UNISHIELD_DB_URL`` or ``database.url``; whoever can
run it with access to that database is trusted.

    unishield-admin db upgrade            apply pending schema migrations
    unishield-admin db current            show the schema revision
    unishield-admin user create NAME --role admin     create a user (prompts for the password)
    unishield-admin user list | set-role | set-password | disable | enable | unlock | delete
    unishield-admin token create --name NAME --role viewer [--expires-days N]
    unishield-admin token list | revoke NAME

There are no default accounts: create the first administrator with
``user create``. Passwords are read from the terminal without echo, or with
``--password-stdin`` from the first line of standard input. Every change is
written to the audit log as ``cli:<operating-system user>``.
"""

from __future__ import annotations

import argparse
import getpass
import sys
from datetime import timedelta
from typing import Callable, Optional, Sequence

from unishield.accounts import AccountConflict, AccountError, AccountStore, Role
from unishield.config import get_config
from unishield.storage import AuditLog, migrate
from unishield.storage.database import make_engine


class CLIError(Exception):
    """A user-facing error: printed without a traceback, exit status 1."""


def _engine(args: argparse.Namespace, migrate_schema: bool = False):
    return make_engine(args.db_url or get_config().database.url, migrate=migrate_schema)


# --- db ------------------------------------------------------------------------

def cmd_db_upgrade(args: argparse.Namespace) -> None:
    engine = _engine(args)
    before = migrate.current_revision(engine)
    migrate.upgrade(engine)
    print(f"Database upgraded: {before or '(empty)'} -> {migrate.current_revision(engine)}")


def cmd_db_current(args: argparse.Namespace) -> None:
    engine = _engine(args)
    current = migrate.current_revision(engine)
    head = migrate.head_revision()
    print(f"current: {current or '(none)'}\nhead:    {head}")
    if current != head:
        raise CLIError("Database schema is not at the latest revision: run 'unishield-admin db upgrade'")


# --- users and tokens ----------------------------------------------------------

def _actor() -> str:
    try:
        return f"cli:{getpass.getuser()}"
    except Exception:                                    # pragma: no cover - no user name available
        return "cli:unknown"


def _stores(args: argparse.Namespace) -> tuple[AccountStore, AuditLog]:
    engine = _engine(args, migrate_schema=True)
    return AccountStore(engine), AuditLog(engine)


def _audit(audit: AuditLog, action: str, target: str, **details) -> None:
    audit.record(action, actor=_actor(), actor_type="cli", target=target, details=details or None)


def _read_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
    else:
        password = getpass.getpass("Password: ")
        if getpass.getpass("Repeat password: ") != password:
            raise CLIError("Passwords do not match")
    if not password:
        raise CLIError("Empty password")
    return password


def cmd_user_create(args: argparse.Namespace) -> None:
    accounts, audit = _stores(args)
    user = accounts.create_user(args.username, _read_password(args), args.role, created_by=_actor(),
                                min_password_length=get_config().auth.min_password_length)
    _audit(audit, "user.create", user.username, role=user.role.value)
    print(f"Created {user.role.value} {user.username!r}")


def cmd_user_list(args: argparse.Namespace) -> None:
    accounts, _ = _stores(args)
    users = accounts.list_users()
    if not users:
        print("No users. Create the first administrator with: unishield-admin user create <name> --role admin")
        return
    print(f"{'USERNAME':<24} {'ROLE':<8} {'STATE':<9} LAST LOGIN")
    for u in users:
        info = u.public()
        state = "disabled" if u.disabled else "locked" if info["locked"] else "active"
        print(f"{u.username:<24} {u.role.value:<8} {state:<9} {info['last_login_at'] or '-'}")


def cmd_user_set_role(args: argparse.Namespace) -> None:
    accounts, audit = _stores(args)
    before, after = accounts.update_user(args.username, role=args.role)
    _audit(audit, "user.update", after.username, role=[before.role.value, after.role.value])
    print(f"{after.username!r}: role {before.role.value} -> {after.role.value} (sessions ended)")


def cmd_user_set_password(args: argparse.Namespace) -> None:
    accounts, audit = _stores(args)
    user = accounts.set_password(args.username, _read_password(args), get_config().auth.min_password_length)
    _audit(audit, "user.password_reset", user.username)
    print(f"Password of {user.username!r} replaced (lockout cleared, sessions ended)")


def _set_disabled(args: argparse.Namespace, disabled: bool) -> None:
    accounts, audit = _stores(args)
    before, after = accounts.update_user(args.username, disabled=disabled)
    _audit(audit, "user.update", after.username, disabled=[before.disabled, after.disabled])
    print(f"{after.username!r} {'disabled (sessions ended)' if disabled else 'enabled'}")


def cmd_user_unlock(args: argparse.Namespace) -> None:
    accounts, audit = _stores(args)
    user = accounts.unlock(args.username)
    _audit(audit, "user.unlock", user.username)
    print(f"{user.username!r} unlocked")


def cmd_user_delete(args: argparse.Namespace) -> None:
    accounts, audit = _stores(args)
    user = accounts.delete_user(args.username)
    _audit(audit, "user.delete", user.username, role=user.role.value)
    print(f"Deleted {user.username!r}")


def cmd_token_create(args: argparse.Namespace) -> None:
    accounts, audit = _stores(args)
    if args.expires_days is not None and args.expires_days < 1:
        raise CLIError("--expires-days must be at least 1")
    expires = accounts.now() + timedelta(days=args.expires_days) if args.expires_days else None
    raw, token = accounts.create_token(args.name, args.role, expires, created_by=_actor())
    _audit(audit, "token.create", token.name, role=token.role.value,
           expires_at=token.expires_at.isoformat() if token.expires_at else None)
    print(f"Created {token.role.value} token {token.name!r}"
          + (f", expires {token.expires_at.isoformat()}" if token.expires_at else ", no expiry"))
    print("Send it as the X-API-Key header. It is shown only now:")
    print(raw)


def cmd_token_list(args: argparse.Namespace) -> None:
    accounts, _ = _stores(args)
    tokens = accounts.list_tokens()
    if not tokens:
        print("No service tokens")
        return
    now = accounts.now()
    print(f"{'NAME':<24} {'ROLE':<8} {'STATE':<8} {'EXPIRES':<26} LAST USED")
    for t in tokens:
        state = "revoked" if t.revoked_at else "expired" if t.expires_at and t.expires_at <= now else "active"
        info = t.public()
        print(f"{t.name:<24} {t.role.value:<8} {state:<8} {info['expires_at'] or '-':<26} "
              f"{info['last_used_at'] or '-'}")


def cmd_token_revoke(args: argparse.Namespace) -> None:
    accounts, audit = _stores(args)
    token = accounts.revoke_token(args.name)
    _audit(audit, "token.revoke", token.name, role=token.role.value)
    print(f"Revoked token {token.name!r}")


# --- parser --------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="unishield-admin", description="UniShield administration")
    parser.add_argument("--db-url", help="database URL (default: UNISHIELD_DB_URL or database.url)")
    groups = parser.add_subparsers(dest="group", required=True)

    db = groups.add_parser("db", help="schema migrations").add_subparsers(dest="command", required=True)
    db.add_parser("upgrade", help="apply pending migrations").set_defaults(func=cmd_db_upgrade)
    db.add_parser("current", help="show the schema revision").set_defaults(func=cmd_db_current)

    roles = [r.value for r in Role]
    user = groups.add_parser("user", help="user accounts").add_subparsers(dest="command", required=True)
    p = user.add_parser("create", help="create a user (the first one should be an admin)")
    p.add_argument("username")
    p.add_argument("--role", choices=roles, required=True)
    p.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    p.set_defaults(func=cmd_user_create)
    user.add_parser("list", help="list users").set_defaults(func=cmd_user_list)
    p = user.add_parser("set-role", help="change a user's role (ends their sessions)")
    p.add_argument("username")
    p.add_argument("role", choices=roles)
    p.set_defaults(func=cmd_user_set_role)
    p = user.add_parser("set-password", help="replace a user's password (ends their sessions)")
    p.add_argument("username")
    p.add_argument("--password-stdin", action="store_true", help="read the password from standard input")
    p.set_defaults(func=cmd_user_set_password)
    for name, disabled in (("disable", True), ("enable", False)):
        p = user.add_parser(name, help=f"{name} a user")
        p.add_argument("username")
        p.set_defaults(func=lambda a, d=disabled: _set_disabled(a, d))
    for name, func, text in (("unlock", cmd_user_unlock, "clear a login lockout"),
                             ("delete", cmd_user_delete, "delete a user (audit entries are kept)")):
        p = user.add_parser(name, help=text)
        p.add_argument("username")
        p.set_defaults(func=func)

    token = groups.add_parser("token", help="service tokens (X-API-Key)")
    tokens = token.add_subparsers(dest="command", required=True)
    p = tokens.add_parser("create", help="create a service token with a fixed role")
    p.add_argument("--name", required=True)
    p.add_argument("--role", choices=roles, required=True)
    p.add_argument("--expires-days", type=int, default=None, help="expire after this many days (default: never)")
    p.set_defaults(func=cmd_token_create)
    tokens.add_parser("list", help="list service tokens").set_defaults(func=cmd_token_list)
    p = tokens.add_parser("revoke", help="revoke a service token")
    p.add_argument("name")
    p.set_defaults(func=cmd_token_revoke)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    func: Callable[[argparse.Namespace], None] = args.func
    try:
        func(args)
    except (CLIError, AccountError, AccountConflict) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
