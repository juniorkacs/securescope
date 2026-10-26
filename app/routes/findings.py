"""Vulnerability register and remediation tracking."""

from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy import func, select
from sqlalchemy.orm import selectinload

from app.controls import CATALOG
from app.deps import DB
from app.models import OPEN_STATUSES, Asset, Finding, FindingEvent, FindingStatus
from app.posture import RATING_ORDER, FindingView, all_findings, risk_for, view
from app.schemas import FindingCreate, FindingUpdate, errors_to_messages
from app.scoring import REMEDIATION_SLA_DAYS, due_date
from app.security import Analyst, CurrentUser, verify_csrf
from app.web import render, today

router = APIRouter(prefix="/findings")


def _filter(
    views: list[FindingView], q: str, rating: str, status: str, asset: str, overdue: bool
) -> list[FindingView]:
    out = views
    if q:
        needle = q.lower()
        out = [
            v
            for v in out
            if needle in f"{v.finding.id} {v.finding.title} {v.asset.name} {v.finding.cwe}".lower()
        ]
    if rating:
        out = [v for v in out if v.risk.rating.value == rating]
    if status == "active":
        out = [v for v in out if v.is_open]
    elif status:
        out = [v for v in out if v.finding.status.value == status]
    if asset:
        out = [v for v in out if v.asset.id == asset]
    if overdue:
        out = [v for v in out if v.overdue]
    return out


@router.get("")
def list_findings(
    request: Request,
    db: DB,
    user: CurrentUser,
    q: str = "",
    rating: str = "",
    status: str = "active",
    asset: str = "",
    overdue: bool = False,
) -> Response:
    views = _filter(all_findings(db, today(request)), q[:100], rating, status, asset, overdue)
    ctx: dict[str, object] = {
        "user": user,
        "views": views,
        "q": q,
        "rating": rating,
        "status": status,
        "asset": asset,
        "overdue": overdue,
        "ratings": RATING_ORDER,
        "statuses": list(FindingStatus),
        "assets": db.scalars(select(Asset).order_by(Asset.id)).all(),
    }
    # HTMX filter requests only need the table, not the whole page.
    template = "partials/findings_table.html" if request.headers.get("hx-request") else "findings.html"
    return render(request, template, 200, **ctx)


@router.get("/new")
def new_finding(request: Request, db: DB, user: Analyst) -> Response:
    return _new_page(request, db, user, form={"discovered": today(request).isoformat()})


def _new_page(request: Request, db: DB, user: object, status: int = 200, **ctx: object) -> Response:
    ctx.setdefault("errors", [])
    return render(
        request,
        "finding_new.html",
        status,
        user=user,
        catalog=CATALOG,
        assets=db.scalars(select(Asset).order_by(Asset.id)).all(),
        **ctx,
    )


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_finding(request: Request, db: DB, user: Analyst) -> Response:
    raw = await request.form()
    form: dict[str, object] = {k: v for k, v in raw.items() if k != "control_ids"}
    form["control_ids"] = raw.getlist("control_ids")
    try:
        data = FindingCreate.model_validate(form)
    except ValidationError as e:
        return _new_page(request, db, user, 400, errors=errors_to_messages(e), form=form)
    asset = db.get(Asset, data.asset_id)
    if asset is None:
        return _new_page(request, db, user, 400, errors=["asset: choose an existing asset"], form=form)

    n = (db.scalar(select(func.count()).select_from(Finding)) or 0) + 1
    fid = f"FND-{n:04d}"
    while db.get(Finding, fid):
        n += 1
        fid = f"FND-{n:04d}"
    finding = Finding(id=fid, status=FindingStatus.open, **data.model_dump())
    finding.asset = asset
    rating = risk_for(finding, asset).rating
    finding.due = due_date(data.discovered, rating)
    finding.history.append(
        FindingEvent(at=dt.datetime.now(), actor=user.email, summary=f"Recorded; rated {rating.value}")
    )
    db.add(finding)
    db.commit()
    return RedirectResponse(f"/findings/{fid}", status_code=303)


def _load(db: DB, finding_id: str) -> Finding:
    f = db.scalar(
        select(Finding)
        .where(Finding.id == finding_id)
        .options(selectinload(Finding.asset), selectinload(Finding.history))
    )
    if f is None:
        raise HTTPException(404, f"Finding {finding_id} does not exist.")
    return f


@router.get("/{finding_id}")
def finding_detail(finding_id: str, request: Request, db: DB, user: CurrentUser) -> Response:
    f = _load(db, finding_id)
    return render(
        request,
        "finding_detail.html",
        user=user,
        v=view(f, today(request)),
        statuses=list(FindingStatus),
        catalog=CATALOG,
        sla=REMEDIATION_SLA_DAYS,
        errors=[],
    )


@router.post("/{finding_id}", dependencies=[Depends(verify_csrf)])
async def update_finding(finding_id: str, request: Request, db: DB, user: Analyst) -> Response:
    f = _load(db, finding_id)
    try:
        data = FindingUpdate.model_validate(dict(await request.form()))
    except ValidationError as e:
        return render(
            request,
            "finding_detail.html",
            400,
            user=user,
            v=view(f, today(request)),
            statuses=list(FindingStatus),
            catalog=CATALOG,
            sla=REMEDIATION_SLA_DAYS,
            errors=errors_to_messages(e),
        )
    if data.status == FindingStatus.risk_accepted and not data.note:
        return render(
            request,
            "finding_detail.html",
            400,
            user=user,
            v=view(f, today(request)),
            statuses=list(FindingStatus),
            catalog=CATALOG,
            sla=REMEDIATION_SLA_DAYS,
            errors=["note: explain why the risk is being accepted, and who accepted it"],
        )

    changes = []
    if data.status != f.status:
        changes.append(f"status {f.status.value} to {data.status.value}")
        was_open = f.status in OPEN_STATUSES
        now_open = data.status in OPEN_STATUSES
        if was_open and not now_open:
            f.closed = today(request)
        elif now_open:
            f.closed = None
        f.status = data.status
    if data.owner != f.owner:
        changes.append(f"owner to {data.owner or 'unassigned'}")
        f.owner = data.owner
    if data.due != f.due:
        changes.append(f"due date to {data.due.isoformat() if data.due else 'none'}")
        f.due = data.due
    if changes or data.note:
        summary = "Changed " + ", ".join(changes) if changes else "Note added"
        if data.note:
            summary += f". Note: {data.note}"
        f.history.append(FindingEvent(at=dt.datetime.now(), actor=user.email, summary=summary))
    db.commit()
    return RedirectResponse(f"/findings/{finding_id}", status_code=303)
