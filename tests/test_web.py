import csv
import io
import re

from tests.conftest import TODAY, csrf_of, make_settings

# ---------- authentication ----------


def test_pages_require_sign_in(client):
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("/login")
    assert client.get("/api/summary").status_code == 401


def test_health_is_public(client):
    assert client.get("/api/health").json() == {"status": "ok"}


def test_password_sign_in_and_out(client):
    token = csrf_of(client)
    r = client.post(
        "/login",
        data={"email": "ANALYST@larkspur.example", "password": "demo-pass-123", "csrf": token},
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "Ana Analyst" in client.get("/").text
    client.post("/logout", data={"csrf": csrf_of(client, "/")})
    assert client.get("/", follow_redirects=False).status_code == 303


def test_wrong_password_is_rejected_without_saying_which_part_was_wrong(client):
    token = csrf_of(client)
    r = client.post("/login", data={"email": "analyst@larkspur.example", "password": "nope", "csrf": token})
    assert r.status_code == 401
    assert "don&#39;t match an active account" in r.text


def test_lockout_after_repeated_failures(client):
    token = csrf_of(client)
    for _ in range(5):
        client.post("/login", data={"email": "admin@larkspur.example", "password": "x", "csrf": token})
    r = client.post(
        "/login", data={"email": "admin@larkspur.example", "password": "demo-pass-123", "csrf": token}
    )
    assert r.status_code == 429


def test_login_requires_csrf(client):
    client.get("/login")
    r = client.post("/login", data={"email": "analyst@larkspur.example", "password": "demo-pass-123"})
    assert r.status_code == 400
    assert "Form expired" in r.text


def test_open_redirect_is_blocked(client):
    token = csrf_of(client)
    r = client.post(
        "/login",
        data={
            "email": "viewer@larkspur.example",
            "password": "demo-pass-123",
            "csrf": token,
            "next": "https://evil.example/",
        },
        follow_redirects=False,
    )
    assert r.headers["location"] == "/"


def test_demo_login_disabled_outside_demo_mode():
    from fastapi.testclient import TestClient

    from app.main import create_app

    with TestClient(create_app(make_settings(demo_mode=False), today=lambda: TODAY)) as c:
        html = c.get("/login").text
        assert "/demo-login" not in html
        token = csrf_of(c)
        assert c.post("/demo-login", data={"role": "admin", "csrf": token}).status_code == 404


def test_production_refuses_default_secret():
    import pytest

    from app.main import create_app

    with pytest.raises(RuntimeError):
        create_app(make_settings(environment="production", secret_key="dev-only-insecure-key-change-me"))


# ---------- authorisation ----------


def test_viewer_cannot_change_anything(viewer):
    client, token = viewer
    r = client.post("/findings/FND-0001", data={"status": "remediated", "csrf": token})
    assert r.status_code == 403
    r = client.post(
        "/assets/AST-001", data={"criticality": 1, "data_class": "public", "owner": "x y", "csrf": token}
    )
    assert r.status_code == 403
    assert "Record a finding" not in client.get("/findings").text


def test_analyst_cannot_administer(analyst):
    client, token = analyst
    assert client.post("/assets/AST-001/delete", data={"csrf": token}).status_code == 403
    assert client.post("/admin/reset", data={"csrf": token}).status_code == 403


# ---------- pages render ----------


def test_all_pages_render(admin):
    client, _ = admin
    for path in [
        "/",
        "/assets",
        "/findings",
        "/findings?status=&rating=critical",
        "/findings/new",
        "/findings/FND-0001",
        "/controls",
        "/controls/SI-2",
        "/methodology",
        "/reports",
        "/reports/executive",
    ]:
        r = client.get(path)
        assert r.status_code == 200, path


def test_unknown_pages_return_404(admin):
    client, _ = admin
    assert client.get("/findings/FND-9999").status_code == 404
    assert client.get("/controls/XX-1").status_code == 404
    assert "Page not found" in client.get("/nowhere").text


def test_htmx_filter_returns_only_the_table(viewer):
    client, _ = viewer
    r = client.get("/findings?rating=critical", headers={"HX-Request": "true"})
    assert "<html" not in r.text and "<table>" in r.text


def test_security_headers(viewer):
    client, _ = viewer
    r = client.get("/")
    assert "default-src 'self'" in r.headers["content-security-policy"]
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["x-content-type-options"] == "nosniff"
    cookie = r.request.headers.get("cookie", "")
    assert "securescope_session" in cookie


# ---------- findings workflow ----------


def test_dashboard_numbers_match_api(viewer):
    client, _ = viewer
    s = client.get("/api/summary").json()
    findings = client.get("/api/findings").json()
    open_f = [f for f in findings if f["status"] in ("open", "in progress")]
    assert s["open_findings"] == len(open_f)
    assert s["overdue"] == sum(1 for f in open_f if f["overdue"])
    assert sum(s["open_by_rating"].values()) == len(open_f)
    # Findings are sorted by risk, highest first
    scores = [f["risk_score"] for f in findings]
    assert scores == sorted(scores, reverse=True)


def test_risk_breakdown_adds_up(viewer):
    client, _ = viewer
    for f in client.get("/api/findings").json():
        total = sum(p["points"] for p in f["risk_breakdown"])
        assert f["risk_score"] == min(100, round(total))


def test_record_finding_computes_rating_and_due_date(analyst):
    client, token = analyst
    r = client.post(
        "/findings",
        data={
            "csrf": token,
            "asset_id": "AST-002",
            "title": "Exposed debug endpoint",
            "source": "Penetration test",
            "cvss": "9.1",
            "known_exploited": "on",
            "discovered": "2026-10-20",
            "control_ids": ["CM-7", "SC-7"],
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    fid = r.headers["location"].rsplit("/", 1)[1]
    f = next(x for x in client.get("/api/findings").json() if x["id"] == fid)
    # 36.4 + 40 + 12 + 15 + 5 (confidential) = 108.4 -> 100, critical, 7-day SLA
    assert f["risk_score"] == 100 and f["rating"] == "critical"
    assert f["due"] == "2026-10-27"
    assert f["controls"] == ["CM-7", "SC-7"]


def test_record_finding_validation(analyst):
    client, token = analyst
    r = client.post(
        "/findings",
        data={
            "csrf": token,
            "asset_id": "AST-002",
            "title": "x",
            "source": "s",
            "cvss": "11",
            "discovered": "2026-10-20",
            "control_ids": ["ZZ-9"],
        },
    )
    assert r.status_code == 400
    text = r.text
    assert "title" in text and "cvss" in text and "Unknown control ID" in text


def test_remediation_update_records_history(analyst):
    client, token = analyst
    fid = next(f["id"] for f in client.get("/api/findings").json() if f["status"] == "open")
    r = client.post(
        f"/findings/{fid}",
        data={
            "csrf": token,
            "status": "remediated",
            "owner": "Platform team",
            "due": "",
            "note": "Patched in October cycle",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    page = client.get(f"/findings/{fid}").text
    assert "status open to remediated" in page
    assert "Patched in October cycle" in page
    f = next(x for x in client.get("/api/findings").json() if x["id"] == fid)
    assert f["status"] == "remediated" and f["overdue"] is False


def test_risk_acceptance_requires_a_note(analyst):
    client, token = analyst
    fid = next(f["id"] for f in client.get("/api/findings").json() if f["status"] == "open")
    r = client.post(
        f"/findings/{fid}", data={"csrf": token, "status": "risk accepted", "owner": "x", "due": ""}
    )
    assert r.status_code == 400
    assert "explain why the risk is being accepted" in r.text


def test_changing_asset_criticality_rescores_findings(admin):
    client, token = admin
    before = {
        f["id"]: f["risk_score"] for f in client.get("/api/findings").json() if f["asset_id"] == "AST-013"
    }
    client.post(
        "/assets/AST-013",
        data={"csrf": token, "criticality": "5", "data_class": "internal", "owner": "Platform team"},
    )
    after = {
        f["id"]: f["risk_score"] for f in client.get("/api/findings").json() if f["asset_id"] == "AST-013"
    }
    assert before and all(after[k] == min(100, before[k] + 24) or after[k] == 100 for k in before)


def test_asset_validation_and_duplicates(admin):
    client, token = admin
    bad = client.post(
        "/assets",
        data={
            "csrf": token,
            "id": "BAD",
            "name": "x",
            "type": "server",
            "environment": "p",
            "owner": "o",
            "criticality": "9",
            "data_class": "public",
        },
    )
    assert bad.status_code == 400
    dup = client.post(
        "/assets",
        data={
            "csrf": token,
            "id": "AST-001",
            "name": "Dup",
            "type": "server",
            "environment": "prod",
            "owner": "Ops",
            "criticality": "3",
            "data_class": "public",
        },
    )
    assert dup.status_code == 409


# ---------- controls ----------


def test_seeded_control_states_are_distinguished(viewer):
    client, _ = viewer
    s = client.get("/api/summary").json()["controls_by_verification"]
    assert s["verified"] > 0 and s["implemented, not verified"] > 0
    assert s["deficient"] == 2 and s["assessment expired"] == 1 and s["not implemented"] == 2


def test_assessment_validation(analyst):
    client, token = analyst
    r = client.post(
        "/controls/SC-28",
        data={"csrf": token, "implementation": "implemented", "result": "satisfied", "assessed_on": ""},
    )
    assert r.status_code == 400 and "needs the date" in r.text


def test_recording_assessment_changes_verification(analyst):
    client, token = analyst
    r = client.post(
        "/controls/IA-5",
        data={
            "csrf": token,
            "implementation": "implemented",
            "result": "satisfied",
            "assessed_on": "2026-10-01",
            "assessor": "Internal audit",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "Assessed as satisfied on 2026-10-01" in client.get("/controls/IA-5").text


# ---------- reports ----------


def test_findings_csv_matches_api(viewer):
    client, _ = viewer
    r = client.get("/reports/findings.csv")
    assert r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert len(rows) == len(client.get("/api/findings").json())
    assert set(rows[0]) >= {"id", "risk_score", "rating", "overdue", "controls"}


def test_executive_pdf_is_generated(viewer):
    client, _ = viewer
    r = client.get("/reports/executive.pdf")
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert len(r.content) > 2000


def test_executive_report_states_limitations(viewer):
    client, _ = viewer
    text = client.get("/reports/executive").text
    assert "not an audit opinion" in text
    open_total = client.get("/api/summary").json()["open_findings"]
    assert re.search(rf"\b{open_total} findings are open", text)


def test_csv_formula_injection_is_neutralised(analyst):
    client, token = analyst
    client.post(
        "/findings",
        data={
            "csrf": token,
            "asset_id": "AST-014",
            "title": '=HYPERLINK("http://x")',
            "source": "Manual",
            "cvss": "3.0",
            "discovered": "2026-10-20",
        },
    )
    body = client.get("/reports/findings.csv").text
    assert "'=HYPERLINK" in body


# ---------- demo reset ----------


def test_admin_can_reset_demo(admin):
    client, token = admin
    client.post("/assets/AST-001/delete", data={"csrf": token})
    r = client.post("/admin/reset", data={"csrf": token}, follow_redirects=False)
    assert r.status_code == 303
    token = csrf_of(client)
    client.post("/demo-login", data={"role": "viewer", "csrf": token})
    assert "Customer shipment portal" in client.get("/assets").text
