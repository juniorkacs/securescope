"""Application factory."""

from __future__ import annotations

import datetime as dt
import logging
from collections.abc import Callable
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.config import Settings, get_settings
from app.db import Database
from app.models import User
from app.security import CsrfError, ForbiddenError, LoginRequiredError, LoginThrottle
from app.seed import seed
from app.web import templates

log = logging.getLogger("securescope")
HERE = Path(__file__).parent

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
        "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
}


def create_app(settings: Settings | None = None, today: Callable[[], dt.date] = dt.date.today) -> FastAPI:
    settings = settings or get_settings()
    if settings.is_production and settings.secret_key.startswith("dev-only"):
        raise RuntimeError(
            "Set SECURESCOPE_SECRET_KEY to a long random value before running outside development."
        )

    app = FastAPI(title="SecureScope", docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.state.settings = settings
    app.state.today = today
    app.state.throttle = LoginThrottle(settings.login_max_failures, settings.login_window_seconds)
    database = Database(settings.database_url)
    database.create_all()
    app.state.database = database

    with database.sessionmaker() as s:
        if s.scalar(select(User.id).limit(1)) is None:
            seed(s, today(), settings.demo_password)
            log.info("Seeded the Larkspur Freight demo data.")

    app.add_middleware(
        SessionMiddleware,
        secret_key=settings.secret_key,
        session_cookie="securescope_session",
        max_age=settings.session_max_age_seconds,
        same_site="lax",
        https_only=settings.is_production,
    )

    @app.middleware("http")
    async def security_headers(request: Request, call_next: Callable[[Request], object]) -> Response:
        response: Response = await call_next(request)  # type: ignore[misc]
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        if settings.is_production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.url.path.startswith(("/api", "/reports")) or request.method != "GET":
            response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")

    from app.routes import api, assets, auth, controls, dashboard, findings, reports

    for r in (
        auth.router,
        dashboard.router,
        assets.router,
        findings.router,
        controls.router,
        reports.router,
        api.router,
    ):
        app.include_router(r)

    @app.exception_handler(LoginRequiredError)
    async def _login(request: Request, _exc: LoginRequiredError) -> Response:
        if request.url.path.startswith("/api"):
            return JSONResponse({"error": "Sign in required."}, status_code=401)
        if request.headers.get("hx-request"):
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        return RedirectResponse(f"/login?next={request.url.path}", status_code=303)

    @app.exception_handler(ForbiddenError)
    async def _forbidden(request: Request, exc: ForbiddenError) -> Response:
        msg = f"This action needs the {exc.needed.value} role or higher."
        if request.url.path.startswith("/api"):
            return JSONResponse({"error": msg}, status_code=403)
        return templates.TemplateResponse(
            request, "error.html", {"title": "Not allowed", "message": msg}, 403
        )

    @app.exception_handler(CsrfError)
    async def _csrf(request: Request, _exc: CsrfError) -> Response:
        msg = "The form expired or was submitted from another site. Reload the page and try again."
        return templates.TemplateResponse(
            request, "error.html", {"title": "Form expired", "message": msg}, 400
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> Response:
        if request.url.path.startswith("/api"):
            return JSONResponse({"error": exc.detail}, status_code=exc.status_code)
        title = "Page not found" if exc.status_code == 404 else "Something went wrong"
        message = (
            "There's nothing at this address. Check the link, or go back to the dashboard."
            if exc.status_code == 404
            else str(exc.detail)
        )
        return templates.TemplateResponse(
            request, "error.html", {"title": title, "message": message}, exc.status_code
        )

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> Response:
        log.exception("Unhandled error on %s", request.url.path, exc_info=exc)
        return HTMLResponse("<h1>Unexpected server error</h1>", status_code=500)

    return app
