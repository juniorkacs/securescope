"""Read-only JSON API for integrations. Requires a signed-in session."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Request

from app.deps import DB
from app.posture import summarise
from app.security import CurrentUser
from app.web import today

router = APIRouter(prefix="/api")


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/summary")
def summary(request: Request, db: DB, _user: CurrentUser) -> dict[str, Any]:
    s, _f, _c = summarise(db, today(request))
    return {
        "date": s.today.isoformat(),
        "assets": s.asset_count,
        "open_findings": s.open_total,
        "open_by_rating": {k.value: v for k, v in s.open_by_rating.items()},
        "overdue": len(s.overdue),
        "known_exploited_open": s.known_exploited_open,
        "median_days_to_remediate": s.median_days_to_remediate,
        "controls_by_verification": {k.value: v for k, v in s.controls_by_verification.items()},
        "verified_control_pct": s.verified_pct,
        "controls_with_conflicts": [c.control_id for c in s.conflicts],
    }


@router.get("/findings")
def findings(request: Request, db: DB, _user: CurrentUser) -> list[dict[str, Any]]:
    _s, views, _c = summarise(db, today(request))
    return [
        {
            "id": v.finding.id,
            "asset_id": v.asset.id,
            "title": v.finding.title,
            "cvss": v.finding.cvss,
            "known_exploited": v.finding.known_exploited,
            "status": v.finding.status.value,
            "risk_score": v.risk.score,
            "rating": v.risk.rating.value,
            "risk_breakdown": [{"factor": k, "points": p} for k, p in v.risk.breakdown],
            "due": v.finding.due.isoformat() if v.finding.due else None,
            "overdue": v.overdue,
            "controls": v.finding.control_ids,
        }
        for v in views
    ]
