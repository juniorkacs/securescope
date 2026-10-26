"""Reports and exports. Every report is built from the current data on request."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import Response

from app.deps import DB
from app.posture import RATING_ORDER, summarise
from app.reports import DISCLAIMER, controls_csv, executive_headlines, executive_pdf, findings_csv
from app.security import CurrentUser
from app.seed import ORG_NAME
from app.web import render, today

router = APIRouter(prefix="/reports")


@router.get("")
def reports_home(request: Request, user: CurrentUser) -> Response:
    return render(request, "reports.html", user=user)


@router.get("/executive")
def executive(request: Request, db: DB, user: CurrentUser) -> Response:
    s, _f, controls = summarise(db, today(request))
    return render(
        request,
        "report_executive.html",
        user=user,
        s=s,
        controls=controls,
        ratings=RATING_ORDER,
        headlines=executive_headlines(s),
        disclaimer=DISCLAIMER,
        org=ORG_NAME,
    )


def _download(content: str | bytes, media: str, name: str) -> Response:
    return Response(
        content, media_type=media, headers={"Content-Disposition": f'attachment; filename="{name}"'}
    )


@router.get("/executive.pdf")
def executive_pdf_download(request: Request, db: DB, _user: CurrentUser) -> Response:
    s, _f, controls = summarise(db, today(request))
    return _download(executive_pdf(s, controls), "application/pdf", f"securescope-executive-{s.today}.pdf")


@router.get("/findings.csv")
def findings_export(request: Request, db: DB, _user: CurrentUser) -> Response:
    _s, findings, _c = summarise(db, today(request))
    return _download(
        findings_csv(findings), "text/csv; charset=utf-8", f"securescope-findings-{today(request)}.csv"
    )


@router.get("/controls.csv")
def controls_export(request: Request, db: DB, _user: CurrentUser) -> Response:
    _s, _f, controls = summarise(db, today(request))
    return _download(
        controls_csv(controls), "text/csv; charset=utf-8", f"securescope-controls-{today(request)}.csv"
    )
