"""
UniShield — Administration CLI (``unishield-admin``)

Local administration of the UniShield database. It works on the database
named by ``--db-url``, ``UNISHIELD_DB_URL`` or ``database.url``; whoever can
run it with access to that database is trusted.

    unishield-admin db upgrade            apply pending schema migrations
    unishield-admin db current            show the schema revision
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable, Optional, Sequence

from unishield.config import get_config
from unishield.storage import migrate
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


# --- parser --------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="unishield-admin", description="UniShield administration")
    parser.add_argument("--db-url", help="database URL (default: UNISHIELD_DB_URL or database.url)")
    groups = parser.add_subparsers(dest="group", required=True)

    db = groups.add_parser("db", help="schema migrations").add_subparsers(dest="command", required=True)
    db.add_parser("upgrade", help="apply pending migrations").set_defaults(func=cmd_db_upgrade)
    db.add_parser("current", help="show the schema revision").set_defaults(func=cmd_db_current)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    func: Callable[[argparse.Namespace], None] = args.func
    try:
        func(args)
    except CLIError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
