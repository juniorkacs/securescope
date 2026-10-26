"""Authentication, authorisation, CSRF protection and sign-in throttling."""

from __future__ import annotations

import hmac
import secrets
import time
from collections import defaultdict, deque
from collections.abc import Callable
from typing import Annotated

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError
from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.deps import get_db
from app.models import Role, User

_hasher = PasswordHasher()  # Argon2id with library defaults

#: A real hash of a random value, so unknown emails take as long as wrong passwords.
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

ROLE_RANK = {Role.viewer: 0, Role.analyst: 1, Role.admin: 2}


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


class LoginThrottle:
    """Locks an account out after too many recent failures.

    In-memory and per process: enough for a single-instance demo. A multi-instance
    deployment would keep this in a shared store such as Redis.
    """

    def __init__(self, max_failures: int, window_seconds: int, clock: Callable[[], float] = time.monotonic):
        self.max_failures = max_failures
        self.window = window_seconds
        self.clock = clock
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str) -> deque[float]:
        q = self._failures[key]
        cutoff = self.clock() - self.window
        while q and q[0] < cutoff:
            q.popleft()
        return q

    def is_locked(self, key: str) -> bool:
        return len(self._prune(key)) >= self.max_failures

    def record_failure(self, key: str) -> None:
        self._prune(key).append(self.clock())

    def reset(self, key: str) -> None:
        self._failures.pop(key, None)


def authenticate(db: Session, email: str, password: str) -> User | None:
    user = db.scalar(select(User).where(User.email == email.strip().lower()))
    if user is None or not user.active:
        verify_password(_DUMMY_HASH, password)  # equalise timing
        return None
    return user if verify_password(user.password_hash, password) else None


# ---------- session helpers ----------


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return str(token)


def check_csrf(request: Request, submitted: str | None) -> bool:
    expected = request.session.get("csrf")
    return bool(expected and submitted and hmac.compare_digest(str(expected), submitted))


class LoginRequiredError(Exception):
    """Raised when a page needs a signed-in user; handled by redirecting to /login."""


class ForbiddenError(Exception):
    def __init__(self, needed: Role):
        self.needed = needed


class CsrfError(Exception):
    pass


def current_user(request: Request, db: Annotated[Session, Depends(get_db)]) -> User:
    uid = request.session.get("uid")
    if uid is None:
        raise LoginRequiredError
    user = db.get(User, uid)
    if user is None or not user.active:
        request.session.clear()
        raise LoginRequiredError
    return user


def require_role(role: Role) -> Callable[..., User]:
    def dep(user: Annotated[User, Depends(current_user)]) -> User:
        if ROLE_RANK[user.role] < ROLE_RANK[role]:
            raise ForbiddenError(role)
        return user

    return dep


async def verify_csrf(request: Request) -> None:
    """Dependency for every state-changing route: token from form field or HTMX header."""
    submitted = request.headers.get("x-csrf-token")
    if submitted is None:
        form = await request.form()
        value = form.get("csrf")
        submitted = value if isinstance(value, str) else None
    if not check_csrf(request, submitted):
        raise CsrfError


CurrentUser = Annotated[User, Depends(current_user)]
Analyst = Annotated[User, Depends(require_role(Role.analyst))]
Admin = Annotated[User, Depends(require_role(Role.admin))]
Csrf = Depends(verify_csrf)
