"""Dashboard, methodology and the RMF/STIG mapping view."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from fastapi.responses import RedirectResponse, Response

from app import scoring
from app.controls import ASSESSMENT_VALID_DAYS, RMF_STEPS, STIG_CATEGORIES
from app.db import Database
from app.deps import DB, get_database
from app.posture import RATING_ORDER, summarise
from app.security import Admin, CurrentUser, verify_csrf
from app.seed import seed
from app.web import render, today

router = APIRouter()


@router.get("/")
def dashboard(request: Request, db: DB, user: CurrentUser) -> Response:
    summary, _findings, controls = summarise(db, today(request))
    max_asset = max((t[2] for t in summary.risk_by_asset), default=1)
    return render(
        request,
        "dashboard.html",
        user=user,
        s=summary,
        controls=controls,
        ratings=RATING_ORDER,
        max_asset=max_asset,
    )


@router.get("/methodology")
def methodology(request: Request, user: CurrentUser) -> Response:
    return render(
        request,
        "methodology.html",
        user=user,
        sc=scoring,
        valid_days=ASSESSMENT_VALID_DAYS,
        rmf=RMF_STEPS,
        stig=STIG_CATEGORIES,
    )


@router.post("/admin/reset", dependencies=[Depends(verify_csrf)])
def reset_demo(request: Request, user: Admin, database: Database = Depends(get_database)) -> Response:  # noqa: B008
    if not request.app.state.settings.demo_mode:
        return Response(status_code=404)
    database.drop_all()
    database.create_all()
    with database.sessionmaker() as s:
        seed(s, today(request), request.app.state.settings.demo_password)
    # Accounts were recreated, so sign the admin back in by role.
    request.session.clear()
    return RedirectResponse("/login?reset=1", status_code=303)
