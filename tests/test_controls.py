import datetime as dt

from app.controls import CATALOG, Verification, classify, family
from app.models import AssessResult, ImplStatus

TODAY = dt.date(2026, 10, 26)


def c(impl, result=AssessResult.not_assessed, days_ago=None):
    on = None if days_ago is None else TODAY - dt.timedelta(days=days_ago)
    return classify(impl, result, on, TODAY).verification


def test_implemented_but_unassessed_is_not_verified():
    assert c(ImplStatus.implemented) == Verification.unverified


def test_recent_satisfied_assessment_is_verified():
    assert c(ImplStatus.implemented, AssessResult.satisfied, 10) == Verification.verified
    assert c(ImplStatus.implemented, AssessResult.satisfied, 365) == Verification.verified


def test_old_assessment_expires():
    assert c(ImplStatus.implemented, AssessResult.satisfied, 366) == Verification.expired


def test_other_than_satisfied_is_deficient_regardless_of_claim():
    assert c(ImplStatus.implemented, AssessResult.other_than_satisfied, 5) == Verification.deficient


def test_planned_is_not_implemented_even_if_marked_satisfied():
    assert c(ImplStatus.planned, AssessResult.satisfied, 5) == Verification.not_implemented


def test_not_applicable():
    assert c(ImplStatus.not_applicable) == Verification.not_applicable


def test_catalog_ids_are_well_formed():
    for cid in CATALOG:
        assert family(cid)
        fam, num = cid.split("-")
        assert fam.isalpha() and num.isdigit()
