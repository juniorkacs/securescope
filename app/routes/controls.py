"""Control assessment register."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import ValidationError

from app.controls import CATALOG, VERIFICATION_ORDER, Verification
from app.deps import DB
from app.models import AssessResult, ControlAssessment, ImplStatus
from app.posture import all_findings, control_views
from app.schemas import ControlUpdate, errors_to_messages
from app.security import Analyst, CurrentUser, verify_csrf
from app.web import render, today

router = APIRouter(prefix="/controls")


@router.get("")
def list_controls(request: Request, db: DB, user: CurrentUser, state: str = "") -> Response:
    views = control_views(db, all_findings(db, today(request)), today(request))
    if state:
        views = [c for c in views if c.state.verification.value == state]
    counts = {v: 0 for v in VERIFICATION_ORDER}
    for c in control_views(db, all_findings(db, today(request)), today(request)):
        counts[c.state.verification] += 1
    return render(
        request, "controls.html", user=user, views=views, counts=counts, state=state, V=Verification
    )


def _detail(
    request: Request,
    db: DB,
    user: object,
    control_id: str,
    status: int = 200,
    errors: list[str] | None = None,
) -> Response:
    views = control_views(db, all_findings(db, today(request)), today(request))
    cv = next((c for c in views if c.control_id == control_id), None)
    if cv is None:
        raise HTTPException(404, f"Control {control_id} is not in the catalog.")
    return render(
        request,
        "control_detail.html",
        status,
        user=user,
        c=cv,
        impl=list(ImplStatus),
        results=list(AssessResult),
        errors=errors or [],
    )


@router.get("/{control_id}")
def control_detail(control_id: str, request: Request, db: DB, user: CurrentUser) -> Response:
    return _detail(request, db, user, control_id)


@router.post("/{control_id}", dependencies=[Depends(verify_csrf)])
async def update_control(control_id: str, request: Request, db: DB, user: Analyst) -> Response:
    if control_id not in CATALOG:
        raise HTTPException(404, f"Control {control_id} is not in the catalog.")
    try:
        data = ControlUpdate.model_validate(dict(await request.form()))
        data.check()
    except (ValidationError, ValueError) as e:
        return _detail(request, db, user, control_id, 400, errors_to_messages(e))
    record = db.get(ControlAssessment, control_id)
    if record is None:
        record = ControlAssessment(control_id=control_id, implementation=data.implementation)
        db.add(record)
    for k, v in data.model_dump().items():
        setattr(record, k, v)
    db.commit()
    return RedirectResponse(f"/controls/{control_id}", status_code=303)
