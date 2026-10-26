"""Asset inventory."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from pydantic import ValidationError
from sqlalchemy import select

from app.deps import DB
from app.models import OPEN_STATUSES, Asset, AssetType, DataClass
from app.posture import all_findings
from app.schemas import AssetForm, AssetUpdate, errors_to_messages
from app.security import Admin, CurrentUser, verify_csrf
from app.web import render, today

router = APIRouter(prefix="/assets")


def _rows(request: Request, db: DB) -> list[dict[str, object]]:
    findings = all_findings(db, today(request))
    out = []
    for a in db.scalars(select(Asset).order_by(Asset.id)).all():
        mine = [v for v in findings if v.asset.id == a.id and v.finding.status in OPEN_STATUSES]
        out.append(
            {
                "asset": a,
                "open": len(mine),
                "top": max((v.risk for v in mine), key=lambda r: r.score, default=None),
                "overdue": sum(1 for v in mine if v.overdue),
            }
        )
    return out


def _page(request: Request, db: DB, user: object, status: int = 200, **ctx: object) -> Response:
    ctx.setdefault("errors", [])
    ctx.setdefault("form", {})
    return render(
        request,
        "assets.html",
        status,
        user=user,
        rows=_rows(request, db),
        types=list(AssetType),
        classes=list(DataClass),
        **ctx,
    )


@router.get("")
def list_assets(request: Request, db: DB, user: CurrentUser) -> Response:
    return _page(request, db, user)


@router.post("", dependencies=[Depends(verify_csrf)])
async def create_asset(request: Request, db: DB, user: Admin) -> Response:
    form = dict(await request.form())
    try:
        data = AssetForm.model_validate(form)
    except ValidationError as e:
        return _page(request, db, user, 400, errors=errors_to_messages(e), form=form, show_form=True)
    if db.get(Asset, data.id):
        return _page(
            request, db, user, 409, errors=[f"Asset {data.id} already exists."], form=form, show_form=True
        )
    db.add(Asset(**data.model_dump()))
    db.commit()
    return RedirectResponse(f"/assets#{data.id}", status_code=303)


@router.post("/{asset_id}", dependencies=[Depends(verify_csrf)])
async def update_asset(asset_id: str, request: Request, db: DB, user: Admin) -> Response:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, f"Asset {asset_id} does not exist.")
    form = dict(await request.form())
    try:
        data = AssetUpdate.model_validate(form)
    except ValidationError as e:
        return _page(request, db, user, 400, errors=errors_to_messages(e))
    for k, v in data.model_dump().items():
        setattr(asset, k, v)
    db.commit()
    return RedirectResponse(f"/assets#{asset_id}", status_code=303)


@router.post("/{asset_id}/delete", dependencies=[Depends(verify_csrf)])
def delete_asset(asset_id: str, db: DB, _user: Admin) -> Response:
    asset = db.get(Asset, asset_id)
    if asset is None:
        raise HTTPException(404, f"Asset {asset_id} does not exist.")
    db.delete(asset)
    db.commit()
    return RedirectResponse("/assets", status_code=303)
