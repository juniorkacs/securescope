"""Risk scoring. Every rule here is documented in docs/risk-scoring.md.

The score is deliberately additive and simple, so anyone reviewing a finding can
recompute it by hand and see exactly why it ranks where it does. It is a
prioritisation aid, not a measure of real-world likelihood or impact.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import StrEnum

from app.models import DataClass

#: Points for each factor. The total is capped at 100.
CVSS_WEIGHT = 4.0  # CVSS 0-10 contributes 0-40
CRITICALITY_POINTS = 8  # per criticality level, 1-5 contributes 8-40
INTERNET_FACING_POINTS = 12
KNOWN_EXPLOITED_POINTS = 15
DATA_CLASS_POINTS: dict[DataClass, int] = {
    DataClass.public: 0,
    DataClass.internal: 2,
    DataClass.confidential: 5,
    DataClass.restricted: 8,
}


class Rating(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


#: Lower bound (inclusive) of each rating band, checked from the top down.
RATING_THRESHOLDS: list[tuple[int, Rating]] = [
    (75, Rating.critical),
    (55, Rating.high),
    (35, Rating.medium),
    (0, Rating.low),
]

#: Days allowed to remediate, by rating. Due date = discovery date + SLA.
REMEDIATION_SLA_DAYS: dict[Rating, int] = {
    Rating.critical: 7,
    Rating.high: 30,
    Rating.medium: 90,
    Rating.low: 180,
}


@dataclass(frozen=True)
class RiskInput:
    cvss: float
    criticality: int
    internet_facing: bool
    known_exploited: bool
    data_class: DataClass


@dataclass(frozen=True)
class RiskScore:
    score: int
    rating: Rating
    #: (factor, points) pairs, in the order they were added, for explanation.
    breakdown: tuple[tuple[str, float], ...]


def score(inp: RiskInput) -> RiskScore:
    if not 0 <= inp.cvss <= 10:
        raise ValueError("CVSS base score must be between 0 and 10")
    if not 1 <= inp.criticality <= 5:
        raise ValueError("Asset criticality must be between 1 and 5")

    parts: list[tuple[str, float]] = [
        (f"CVSS {inp.cvss:.1f} x {CVSS_WEIGHT:g}", round(inp.cvss * CVSS_WEIGHT, 1)),
        (f"Asset criticality {inp.criticality} x {CRITICALITY_POINTS}", inp.criticality * CRITICALITY_POINTS),
    ]
    if inp.internet_facing:
        parts.append(("Internet-facing asset", INTERNET_FACING_POINTS))
    if inp.known_exploited:
        parts.append(("Known to be exploited", KNOWN_EXPLOITED_POINTS))
    dc_points = DATA_CLASS_POINTS[inp.data_class]
    if dc_points:
        parts.append((f"{inp.data_class.value.capitalize()} data", dc_points))

    total = min(100, round(sum(p for _, p in parts)))
    return RiskScore(score=total, rating=rating_for(total), breakdown=tuple(parts))


def rating_for(total: int) -> Rating:
    for threshold, rating in RATING_THRESHOLDS:
        if total >= threshold:
            return rating
    return Rating.low  # pragma: no cover (thresholds start at 0)


def due_date(discovered: dt.date, rating: Rating) -> dt.date:
    return discovered + dt.timedelta(days=REMEDIATION_SLA_DAYS[rating])


def is_overdue(due: dt.date | None, is_open: bool, today: dt.date) -> bool:
    return is_open and due is not None and today > due
