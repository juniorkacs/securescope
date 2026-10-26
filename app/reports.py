"""Report generation: CSV exports and the executive PDF, all from live data."""

from __future__ import annotations

import csv
import io
from collections.abc import Sequence

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.controls import VERIFICATION_ORDER
from app.posture import RATING_ORDER, ControlView, FindingView, Summary
from app.scoring import REMEDIATION_SLA_DAYS
from app.seed import ORG_NAME

DISCLAIMER = (
    "This report is generated from synthetic demonstration data. It summarises recorded findings and "
    "control assessments. It is not an audit opinion, an authorization decision or evidence of compliance "
    "with NIST SP 800-53, RMF or any other framework."
)


def _safe(value: object) -> str:
    """Prevent spreadsheet formula injection in CSV cells."""
    s = "" if value is None else str(value)
    return f"'{s}" if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def findings_csv(findings: list[FindingView]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "id",
            "asset_id",
            "asset",
            "title",
            "cwe",
            "cvss",
            "known_exploited",
            "risk_score",
            "rating",
            "status",
            "owner",
            "discovered",
            "due",
            "overdue",
            "closed",
            "controls",
        ]
    )
    for v in findings:
        f = v.finding
        w.writerow(
            [
                _safe(x)
                for x in [
                    f.id,
                    v.asset.id,
                    v.asset.name,
                    f.title,
                    f.cwe or "",
                    f.cvss,
                    f.known_exploited,
                    v.risk.score,
                    v.risk.rating.value,
                    f.status.value,
                    f.owner,
                    f.discovered.isoformat(),
                    f.due.isoformat() if f.due else "",
                    v.overdue,
                    f.closed.isoformat() if f.closed else "",
                    ";".join(f.control_ids),
                ]
            ]
        )
    return buf.getvalue()


def controls_csv(controls: list[ControlView]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(
        [
            "control",
            "title",
            "family",
            "implementation",
            "assessment_result",
            "assessed_on",
            "verification",
            "open_findings",
        ]
    )
    for c in controls:
        a = c.assessment
        w.writerow(
            [
                _safe(x)
                for x in [
                    c.control_id,
                    c.title,
                    c.family,
                    a.implementation.value if a else "not recorded",
                    a.result.value if a else "not assessed",
                    a.assessed_on.isoformat() if a and a.assessed_on else "",
                    c.state.verification.value,
                    len(c.open_findings),
                ]
            ]
        )
    return buf.getvalue()


def executive_headlines(s: Summary) -> list[str]:
    """Plain-language key points, derived only from the numbers in the summary."""
    lines = []
    crit, high = s.open_by_rating[RATING_ORDER[0]], s.open_by_rating[RATING_ORDER[1]]
    lines.append(f"{s.open_total} findings are open: {crit} critical and {high} high.")
    if s.overdue:
        lines.append(f"{len(s.overdue)} open findings are past their remediation due date.")
    if s.known_exploited_open:
        lines.append(f"{s.known_exploited_open} open findings involve weaknesses known to be exploited.")
    lines.append(
        f"{s.verified_pct:g}% of applicable controls have a current, satisfied assessment; "
        "the rest are unverified, expired, deficient or not implemented."
    )
    if s.conflicts:
        ids = ", ".join(c.control_id for c in s.conflicts)
        lines.append(f"Assessed as satisfied but contradicted by open high or critical findings: {ids}.")
    if s.median_days_to_remediate is not None:
        lines.append(f"Median time to remediate closed findings: {s.median_days_to_remediate:g} days.")
    return lines


def executive_pdf(s: Summary, controls: list[ControlView]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        topMargin=16 * mm,
        bottomMargin=16 * mm,
        title=f"{ORG_NAME} security posture report",
        author="SecureScope",
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Heading1"], fontSize=17, spaceAfter=2)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12, spaceBefore=10, spaceAfter=4)
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle(
        "small", parent=body, fontSize=8, leading=10.5, textColor=colors.HexColor("#4a607a")
    )
    ink = colors.HexColor("#0b2545")
    grid = colors.HexColor("#c9d6e4")

    def table(rows: Sequence[Sequence[object]], widths: list[float]) -> Table:
        t = Table(rows, colWidths=widths, repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("FONT", (0, 0), (-1, 0), "Helvetica-Bold", 8.5),
                    ("FONT", (0, 1), (-1, -1), "Helvetica", 8.5),
                    ("TEXTCOLOR", (0, 0), (-1, -1), ink),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.8, ink),
                    ("LINEBELOW", (0, 1), (-1, -1), 0.3, grid),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ]
            )
        )
        return t

    story: list[object] = [
        Paragraph(f"{ORG_NAME}: security posture report", h1),
        Paragraph(
            f"Generated by SecureScope on {s.today.isoformat()}. {s.asset_count} assets in scope.", small
        ),
        Spacer(1, 6),
        Paragraph("Key points", h2),
    ]
    story += [Paragraph(f"&bull; {line}", body) for line in executive_headlines(s)]

    story += [Paragraph("Open findings by rating", h2)]
    story.append(
        table(
            [["Rating", "Open", "Remediation target"]]
            + [
                [r.value.capitalize(), s.open_by_rating[r], f"{REMEDIATION_SLA_DAYS[r]} days"]
                for r in RATING_ORDER
            ],
            [40 * mm, 25 * mm, 45 * mm],
        )
    )

    story += [Paragraph("Ten highest-risk open findings", h2)]
    story.append(
        table(
            [["Finding", "Asset", "Issue", "Score", "Due"]]
            + [
                [
                    v.finding.id,
                    Paragraph(v.asset.name, small),
                    Paragraph(v.finding.title, small),
                    f"{v.risk.score} {v.risk.rating.value}",
                    (v.finding.due.isoformat() if v.finding.due else "") + (" overdue" if v.overdue else ""),
                ]
                for v in s.top_risks
            ],
            [20 * mm, 36 * mm, 66 * mm, 24 * mm, 28 * mm],
        )
    )

    story += [Paragraph("Control assessment status", h2)]
    story.append(
        table(
            [["Verification state", "Controls"]]
            + [[k.value.capitalize(), s.controls_by_verification[k]] for k in VERIFICATION_ORDER],
            [70 * mm, 25 * mm],
        )
    )
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            '"Verified" means an assessment found the control satisfied within the last 365 days. A control '
            "the organisation reports as implemented but that has not been assessed "
            "is counted as unverified.",
            small,
        )
    )
    needs = [c for c in controls if c.state.verification.value in ("deficient", "not implemented")]
    if needs:
        story += [Paragraph("Controls needing action", h2)]
        story.append(
            table(
                [["Control", "Title", "State", "Open findings"]]
                + [
                    [
                        c.control_id,
                        Paragraph(c.title, small),
                        c.state.verification.value,
                        len(c.open_findings),
                    ]
                    for c in needs
                ],
                [20 * mm, 85 * mm, 40 * mm, 25 * mm],
            )
        )

    story += [Spacer(1, 10), Paragraph("Limitations", h2), Paragraph(DISCLAIMER, small)]
    doc.build(story)
    return buf.getvalue()
