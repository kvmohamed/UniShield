"""
UniShield — Password Hashing

Argon2id through argon2-cffi with its default parameters (RFC 9106 low-memory
profile: 3 passes, 64 MiB, 4 lanes; about 0.1 s per hash on the development
machine). Hashes carry their parameters, so stronger settings later only
need ``needs_rehash`` at the next successful login.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

MAX_PASSWORD_LENGTH = 1024           # bounds hashing work per request

_hasher = PasswordHasher()
_dummy: tuple[PasswordHasher, str] | None = None


class PasswordPolicyError(ValueError):
    """The password does not meet the policy; the message says why."""


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    if len(password) > MAX_PASSWORD_LENGTH:
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True


def dummy_verify(password: str) -> None:
    """Spend the time of one verification, so unknown and locked accounts answer as slowly as real ones."""
    global _dummy
    if _dummy is None or _dummy[0] is not _hasher:
        _dummy = (_hasher, _hasher.hash("unishield-dummy-password"))
    verify_password(_dummy[1], password)


def check_policy(username: str, password: str, min_length: int) -> None:
    if len(password) < min_length:
        raise PasswordPolicyError(f"Password must be at least {min_length} characters")
    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")
    if username and username.lower() in password.lower():
        raise PasswordPolicyError("Password must not contain the username")
    if len(set(password)) < 4:
        raise PasswordPolicyError("Password must use at least 4 different characters")
