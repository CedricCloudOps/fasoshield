"""Analyst identity primitives: password hashing, roles and session tokens.

Deliberately dependency-free — everything here is stdlib. Passwords use scrypt
(memory-hard, resistant to GPU cracking), sessions are opaque random tokens
stored only as their SHA-256 so a database dump cannot be replayed.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

# scrypt parameters: ~64 MiB of memory per hash, the interactive-login profile
# recommended by RFC 7914. Stored alongside the digest so they can be raised
# later without invalidating existing passwords.
SCRYPT_N = 2**16
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16
TOKEN_BYTES = 32


def _maxmem(n: int, r: int) -> int:
    """Memory ceiling to hand to OpenSSL.

    scrypt needs roughly 128*N*r bytes, which at our parameters is 64 MiB —
    above OpenSSL's 32 MiB default, so the limit has to be raised explicitly or
    every hash fails. The margin covers OpenSSL's internal overhead.
    """
    return 128 * n * r * 2

MIN_PASSWORD_LENGTH = 12


class Role(str, enum.Enum):
    """Console roles, ordered by privilege."""

    VIEWER = "viewer"  # read the dashboard and the exports
    ANALYST = "analyst"  # propose, review and publish signatures
    ADMIN = "admin"  # manage accounts, in addition to analyst rights

    @property
    def rank(self) -> int:
        return _ROLE_RANK[self]

    def covers(self, required: Role) -> bool:
        return self.rank >= required.rank


_ROLE_RANK = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}


class PasswordPolicyError(ValueError):
    """Raised when a password is too weak to be accepted."""


def hash_password(password: str) -> str:
    """Return a self-describing scrypt digest: scrypt$n$r$p$salt$hash."""
    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password must be at least {MIN_PASSWORD_LENGTH} characters long"
        )
    salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode(),
        salt=salt,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
        dklen=SCRYPT_DKLEN,
        maxmem=_maxmem(SCRYPT_N, SCRYPT_R),
    )
    return f"scrypt${SCRYPT_N}${SCRYPT_R}${SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Constant-time verification against a stored digest.

    Returns False rather than raising on a malformed digest, so a corrupted row
    denies access instead of crashing the login endpoint.
    """
    try:
        scheme, n, r, p, salt_hex, hash_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        candidate = hashlib.scrypt(
            password.encode(),
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(hash_hex) // 2,
            maxmem=_maxmem(int(n), int(r)),
        )
    except (ValueError, TypeError, MemoryError):
        return False
    return hmac.compare_digest(candidate.hex(), hash_hex)


def new_session_token() -> tuple[str, str]:
    """Return (token given to the client, SHA-256 stored server-side)."""
    token = secrets.token_urlsafe(TOKEN_BYTES)
    return token, hash_token(token)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def session_expiry(ttl_minutes: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)


def parse_role(value: str, default: Role = Role.VIEWER) -> Role:
    try:
        return Role(str(value).strip().lower())
    except ValueError:
        return default
