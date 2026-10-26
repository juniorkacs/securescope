import datetime as dt

import pytest

from app.models import DataClass
from app.scoring import Rating, RiskInput, due_date, is_overdue, rating_for, score


def inp(**kw):
    base = dict(
        cvss=5.0, criticality=3, internet_facing=False, known_exploited=False, data_class=DataClass.internal
    )
    base.update(kw)
    return RiskInput(**base)


def test_score_adds_documented_factors():
    r = score(
        inp(
            cvss=9.8,
            criticality=5,
            internet_facing=True,
            known_exploited=True,
            data_class=DataClass.restricted,
        )
    )
    # 39.2 + 40 + 12 + 15 + 8 = 114.2, capped at 100
    assert r.score == 100
    assert r.rating == Rating.critical
    assert [name for name, _ in r.breakdown] == [
        "CVSS 9.8 x 4",
        "Asset criticality 5 x 8",
        "Internet-facing asset",
        "Known to be exploited",
        "Restricted data",
    ]


def test_score_minimal_case():
    r = score(inp(cvss=0.0, criticality=1, data_class=DataClass.public))
    assert r.score == 8
    assert r.rating == Rating.low
    assert len(r.breakdown) == 2  # zero-point factors are not listed


def test_score_is_rounded():
    # 6.1 x 4 = 24.4, + 24 + 2 = 50.4 -> 50
    assert score(inp(cvss=6.1)).score == 50


@pytest.mark.parametrize(
    "total,expected",
    [
        (100, "critical"),
        (75, "critical"),
        (74, "high"),
        (55, "high"),
        (54, "medium"),
        (35, "medium"),
        (34, "low"),
        (0, "low"),
    ],
)
def test_rating_boundaries(total, expected):
    assert rating_for(total).value == expected


@pytest.mark.parametrize("bad", [dict(cvss=-0.1), dict(cvss=10.1), dict(criticality=0), dict(criticality=6)])
def test_rejects_out_of_range_inputs(bad):
    with pytest.raises(ValueError):
        score(inp(**bad))


def test_same_cvss_ranks_higher_on_critical_exposed_asset():
    low = score(inp(cvss=7.5, criticality=1))
    high = score(inp(cvss=7.5, criticality=5, internet_facing=True))
    assert high.score - low.score == 4 * 8 + 12


def test_due_dates_follow_sla():
    d = dt.date(2026, 1, 1)
    assert due_date(d, Rating.critical) == dt.date(2026, 1, 8)
    assert due_date(d, Rating.low) == dt.date(2026, 6, 30)


def test_overdue_only_when_open_and_past_due():
    today = dt.date(2026, 5, 2)
    assert is_overdue(dt.date(2026, 5, 1), True, today)
    assert not is_overdue(dt.date(2026, 5, 2), True, today)  # due today is not overdue
    assert not is_overdue(dt.date(2026, 5, 1), False, today)
    assert not is_overdue(None, True, today)
