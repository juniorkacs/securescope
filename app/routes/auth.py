"""Sign in and sign out."""

from __future__ import annotations

from typing import Annotated
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select

from app.deps import DB
from app.models import Role, User
from app.security import authenticate, csrf_token, verify_csrf
from app.web import render

router = APIRouter()


def _safe_next(target: str | None) -> str:
    """Only allow redirects to local paths, never to another site."""
    if not target:
        return "/"
    parsed = urlparse(target)
    if parsed.scheme or parsed.netloc or not target.startswith("/") or target.startswith("//"):
        return "/"
    return target


@router.get("/login")
def login_page(request: Request, next: str | None = None) -> Response:
    if request.session.get("uid"):
        return RedirectResponse(_safe_next(next), status_code=303)
    csrf_token(request)
    return render(request, "login.html", next=_safe_next(next), error=None, email="")


@router.post("/login", dependencies=[Depends(verify_csrf)])
def login(
    request: Request,
    db: DB,
    email: Annotated[str, Form(max_length=200)],
    password: Annotated[str, Form(max_length=200)],
    next: Annotated[str, Form()] = "/",
) -> Response:
    throttle = request.app.state.throttle
    key = email.strip().lower()
    if throttle.is_locked(key):
        return render(
            request,
            "login.html",
            429,
            next=_safe_next(next),
            email=email,
            error="Too many failed attempts. Wait 15 minutes, then try again.",
        )
    user = authenticate(db, email, password)
    if user is None:
        throttle.record_failure(key)
        return render(
            request,
            "login.html",
            401,
            next=_safe_next(next),
            email=email,
            error="That email and password don't match an active account.",
        )
    throttle.reset(key)
    _start_session(request, user)
    return RedirectResponse(_safe_next(next), status_code=303)


@router.post("/demo-login", dependencies=[Depends(verify_csrf)])
def demo_login(request: Request, db: DB, role: Annotated[Role, Form()]) -> Response:
    if not request.app.state.settings.demo_mode:
        return Response(status_code=404)
    user = db.scalar(select(User).where(User.role == role, User.active.is_(True)).order_by(User.id))
    if user is None:
        return Response(status_code=404)
    _start_session(request, user)
    return RedirectResponse("/", status_code=303)


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(request: Request) -> Response:
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


def _start_session(request: Request, user: User) -> None:
    # A fresh session on sign-in prevents session fixation; the CSRF token is rotated too.
    request.session.clear()
    request.session["uid"] = user.id
    csrf_token(request)
