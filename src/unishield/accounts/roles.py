"""
UniShield — Roles

    viewer   read endpoints and the dashboard
    analyst  everything a viewer can do; reserved for alert feedback and
             annotations (UniShield has no analyst-only endpoint yet)
    admin    replay and data sources, deleting data, user management, audit log

Each role includes the permissions of the roles below it.
"""

from __future__ import annotations

from enum import Enum


class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"

    @property
    def rank(self) -> int:
        return _RANK[self]

    def allows(self, required: "Role") -> bool:
        """True if this role has at least the permissions of ``required``."""
        return self.rank >= required.rank


_RANK = {Role.VIEWER: 1, Role.ANALYST: 2, Role.ADMIN: 3}
