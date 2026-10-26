"""Derived views over the data: scored findings, control states and summaries.

Nothing here is stored. Scores, ratings, overdue flags and control
verification states are recomputed from the records each time.
"""

from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass, field
from statistics import median

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.controls import CATALOG, VERIFICATION_ORDER, ControlState, Verification, classify, family
from app.models import (
    OPEN_STATUSES,
    AssessResult,
    Asset,
    ControlAssessment,
    Finding,
    FindingStatus,
    ImplStatus,
)
from app.scoring import Rating, RiskInput, RiskScore, is_overdue, score

RATING_ORDER = [Rating.critical, Rating.high, Rating.medium, Rating.low]


@dataclass
class FindingView:
    finding: Finding
    asset: Asset
    risk: RiskScore
    overdue: bool
    days_open: int

    @property
    def is_open(self) -> bool:
        return self.finding.status in OPEN_STATUSES


def risk_for(f: Finding, a: Asset) -> RiskScore:
    return score(
        RiskInput(
            cvss=f.cvss,
            criticality=a.criticality,
            internet_facing=a.internet_facing,
            known_exploited=f.known_exploited,
            data_class=a.data_class,
        )
    )


def view(f: Finding, today: dt.date) -> FindingView:
    is_open = f.status in OPEN_STATUSES
    end = f.closed if (not is_open and f.closed) else today
    return FindingView(
        finding=f,
        asset=f.asset,
        risk=risk_for(f, f.asset),
        overdue=is_overdue(f.due, is_open, today),
        days_open=max(0, (end - f.discovered).days),
    )


def all_findings(db: Session, today: dt.date) -> list[FindingView]:
    rows = db.scalars(select(Finding).options(selectinload(Finding.asset))).all()
    views = [view(f, today) for f in rows]
    return sorted(views, key=lambda v: (-v.risk.score, v.finding.id))


@dataclass
class ControlView:
    control_id: str
    title: str
    family: str
    assessment: ControlAssessment | None
    state: ControlState
    open_findings: list[FindingView] = field(default_factory=list)

    @property
    def conflict(self) -> bool:
        """Verified, yet open critical or high findings point at this control."""
        return self.state.verification == Verification.verified and any(
            v.risk.rating in (Rating.critical, Rating.high) for v in self.open_findings
        )


def control_views(db: Session, findings: list[FindingView], today: dt.date) -> list[ControlView]:
    assessments = {a.control_id: a for a in db.scalars(select(ControlAssessment)).all()}
    by_control: dict[str, list[FindingView]] = {}
    for v in findings:
        if v.is_open:
            for cid in v.finding.control_ids:
                by_control.setdefault(cid, []).append(v)
    out = []
    for cid, title in CATALOG.items():
        a = assessments.get(cid)
        if a is None:
            state = classify(ImplStatus.not_implemented, AssessResult.not_assessed, None, today)
        else:
            state = classify(a.implementation, a.result, a.assessed_on, today)
        out.append(ControlView(cid, title, family(cid), a, state, by_control.get(cid, [])))
    return out


@dataclass
class Summary:
    today: dt.date
    asset_count: int
    open_by_rating: dict[Rating, int]
    open_total: int
    overdue: list[FindingView]
    known_exploited_open: int
    closed_last_90: int
    median_days_to_remediate: float | None
    status_counts: dict[FindingStatus, int]
    top_risks: list[FindingView]
    controls_by_verification: dict[Verification, int]
    control_total: int
    verified_pct: float
    conflicts: list[ControlView]
    risk_by_asset: list[tuple[Asset, int, int]]  # asset, open findings, total risk points


def summarise(db: Session, today: dt.date) -> tuple[Summary, list[FindingView], list[ControlView]]:
    findings = all_findings(db, today)
    controls = control_views(db, findings, today)
    open_f = [v for v in findings if v.is_open]
    remediated = [
        v for v in findings if v.finding.status == FindingStatus.remediated and v.finding.closed is not None
    ]
    applicable = [c for c in controls if c.state.verification != Verification.not_applicable]
    verified = [c for c in applicable if c.state.verification == Verification.verified]

    per_asset: dict[str, tuple[Asset, int, int]] = {}
    for v in open_f:
        a, n, pts = per_asset.get(v.asset.id, (v.asset, 0, 0))
        per_asset[v.asset.id] = (a, n + 1, pts + v.risk.score)

    status_counts = Counter(v.finding.status for v in findings)
    rating_counts = Counter(v.risk.rating for v in open_f)
    ver_counts = Counter(c.state.verification for c in controls)

    summary = Summary(
        today=today,
        asset_count=len(db.scalars(select(Asset.id)).all()),
        open_by_rating={r: rating_counts.get(r, 0) for r in RATING_ORDER},
        open_total=len(open_f),
        overdue=[v for v in open_f if v.overdue],
        known_exploited_open=sum(1 for v in open_f if v.finding.known_exploited),
        closed_last_90=sum(
            1 for v in remediated if v.finding.closed and (today - v.finding.closed).days <= 90
        ),
        median_days_to_remediate=median([v.days_open for v in remediated]) if remediated else None,
        status_counts={s: status_counts.get(s, 0) for s in FindingStatus},
        top_risks=open_f[:10],
        controls_by_verification={k: ver_counts.get(k, 0) for k in VERIFICATION_ORDER},
        control_total=len(controls),
        verified_pct=round(100 * len(verified) / len(applicable), 1) if applicable else 0.0,
        conflicts=[c for c in controls if c.conflict],
        risk_by_asset=sorted(per_asset.values(), key=lambda t: -t[2]),
    )
    return summary, findings, controls
