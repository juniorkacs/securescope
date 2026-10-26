"""Synthetic demo data for "Larkspur Freight Co.", a fictional logistics company.

Generated deterministically from a fixed random seed, with dates relative to
`today` so the demo always looks current. No real organisation, system,
person or vulnerability scan is represented.
"""

from __future__ import annotations

import datetime as dt
import random
from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models import (
    AssessResult,
    Asset,
    AssetType,
    ControlAssessment,
    DataClass,
    Finding,
    FindingEvent,
    FindingStatus,
    ImplStatus,
    Role,
    User,
)
from app.scoring import RiskInput, due_date, score
from app.security import hash_password

ORG_NAME = "Larkspur Freight Co."

ASSETS: list[tuple[str, str, AssetType, str, str, int, DataClass, bool]] = [
    # id, name, type, environment, owner, criticality, data class, internet-facing
    (
        "AST-001",
        "Customer shipment portal",
        AssetType.application,
        "production",
        "Digital team",
        5,
        DataClass.confidential,
        True,
    ),
    (
        "AST-002",
        "Portal web servers",
        AssetType.server,
        "production",
        "Platform team",
        5,
        DataClass.confidential,
        True,
    ),
    (
        "AST-003",
        "Shipments database",
        AssetType.database,
        "production",
        "Data team",
        5,
        DataClass.restricted,
        False,
    ),
    (
        "AST-004",
        "Route planning service",
        AssetType.application,
        "production",
        "Logistics engineering",
        4,
        DataClass.internal,
        False,
    ),
    (
        "AST-005",
        "Fleet telematics gateway",
        AssetType.server,
        "production",
        "Fleet systems",
        4,
        DataClass.internal,
        True,
    ),
    ("AST-006", "Payroll system", AssetType.cloud, "production", "Finance", 4, DataClass.restricted, True),
    (
        "AST-007",
        "Corporate email",
        AssetType.cloud,
        "corporate",
        "IT operations",
        3,
        DataClass.confidential,
        True,
    ),
    (
        "AST-008",
        "Edge firewall pair",
        AssetType.network,
        "production",
        "Network team",
        5,
        DataClass.internal,
        True,
    ),
    (
        "AST-009",
        "Warehouse Wi-Fi controllers",
        AssetType.network,
        "corporate",
        "Network team",
        3,
        DataClass.internal,
        False,
    ),
    (
        "AST-010",
        "Depot scanner workstations",
        AssetType.workstation,
        "corporate",
        "Depot operations",
        2,
        DataClass.internal,
        False,
    ),
    (
        "AST-011",
        "Finance laptops",
        AssetType.workstation,
        "corporate",
        "IT operations",
        3,
        DataClass.confidential,
        False,
    ),
    (
        "AST-012",
        "Backup storage",
        AssetType.server,
        "production",
        "Platform team",
        4,
        DataClass.restricted,
        False,
    ),
    (
        "AST-013",
        "Staging environment",
        AssetType.server,
        "staging",
        "Platform team",
        2,
        DataClass.internal,
        False,
    ),
    (
        "AST-014",
        "Marketing website",
        AssetType.application,
        "production",
        "Marketing",
        2,
        DataClass.public,
        True,
    ),
    (
        "AST-015",
        "Identity provider",
        AssetType.cloud,
        "corporate",
        "IT operations",
        5,
        DataClass.confidential,
        True,
    ),
    (
        "AST-016",
        "Log collection cluster",
        AssetType.server,
        "production",
        "Security team",
        3,
        DataClass.internal,
        False,
    ),
]


@dataclass(frozen=True)
class Template:
    title: str
    cwe: str | None
    cvss: tuple[float, float]
    controls: tuple[str, ...]
    source: str
    types: tuple[AssetType, ...]
    exploited_chance: float = 0.0


TEMPLATES: list[Template] = [
    Template(
        "Operating system missing security updates",
        "CWE-1395",
        (6.5, 9.8),
        ("SI-2", "RA-5"),
        "Vulnerability scan",
        (AssetType.server, AssetType.workstation),
        0.35,
    ),
    Template(
        "Outdated web framework with known vulnerabilities",
        "CWE-1395",
        (7.0, 9.8),
        ("SI-2", "RA-5"),
        "Vulnerability scan",
        (AssetType.application,),
        0.4,
    ),
    Template(
        "TLS 1.0 and 1.1 still enabled",
        "CWE-327",
        (5.3, 7.4),
        ("SC-8", "CM-6"),
        "Configuration review",
        (AssetType.server, AssetType.application, AssetType.network),
    ),
    Template(
        "Default administrative credentials",
        "CWE-1392",
        (8.8, 9.8),
        ("IA-5", "CM-6"),
        "Penetration test",
        (AssetType.network, AssetType.server),
        0.3,
    ),
    Template(
        "Management interface reachable from the internet",
        "CWE-284",
        (7.2, 9.1),
        ("SC-7", "AC-17"),
        "Penetration test",
        (AssetType.network, AssetType.server),
    ),
    Template(
        "Multi-factor authentication not enforced for administrators",
        "CWE-308",
        (7.5, 8.8),
        ("IA-2", "AC-2"),
        "Configuration review",
        (AssetType.cloud, AssetType.application),
    ),
    Template(
        "Dormant accounts not disabled",
        "CWE-284",
        (4.3, 6.5),
        ("AC-2",),
        "Access review",
        (AssetType.cloud, AssetType.application, AssetType.database),
    ),
    Template(
        "Excessive database privileges for application account",
        "CWE-250",
        (5.5, 7.1),
        ("AC-6",),
        "Configuration review",
        (AssetType.database,),
    ),
    Template(
        "Unencrypted backups",
        "CWE-311",
        (5.9, 7.5),
        ("SC-28", "CP-9"),
        "Configuration review",
        (AssetType.server, AssetType.database),
    ),
    Template(
        "Security event logging disabled",
        "CWE-778",
        (4.0, 6.5),
        ("AU-2", "SI-4"),
        "Configuration review",
        (AssetType.server, AssetType.cloud, AssetType.network),
    ),
    Template(
        "Reflected cross-site scripting in search",
        "CWE-79",
        (5.4, 6.1),
        ("SI-2",),
        "Penetration test",
        (AssetType.application,),
    ),
    Template(
        "SQL injection in report filter",
        "CWE-89",
        (8.1, 9.8),
        ("SI-2",),
        "Penetration test",
        (AssetType.application,),
        0.2,
    ),
    Template(
        "Unnecessary services listening",
        "CWE-1188",
        (3.1, 5.3),
        ("CM-7",),
        "Vulnerability scan",
        (AssetType.server, AssetType.workstation),
    ),
    Template(
        "Host not covered by baseline configuration",
        None,
        (3.5, 5.0),
        ("CM-2",),
        "Configuration review",
        (AssetType.server, AssetType.workstation),
    ),
    Template(
        "Weak password policy",
        "CWE-521",
        (5.3, 7.5),
        ("IA-5",),
        "Configuration review",
        (AssetType.cloud, AssetType.application),
    ),
    Template(
        "Firmware out of vendor support",
        "CWE-1104",
        (6.0, 8.0),
        ("SI-2", "RA-5"),
        "Vulnerability scan",
        (AssetType.network,),
        0.25,
    ),
]

CONTROL_ASSESSMENTS: list[tuple[str, ImplStatus, AssessResult, int | None, str, str]] = [
    # control, implementation, result, assessed N days ago, owner, evidence
    (
        "AC-2",
        ImplStatus.implemented,
        AssessResult.satisfied,
        120,
        "IT operations",
        "Quarterly access review records.",
    ),
    (
        "AC-6",
        ImplStatus.partial,
        AssessResult.not_assessed,
        None,
        "Data team",
        "Role design drafted; not yet rolled out.",
    ),
    (
        "AC-17",
        ImplStatus.implemented,
        AssessResult.satisfied,
        60,
        "Network team",
        "VPN with device certificates.",
    ),
    (
        "AU-2",
        ImplStatus.implemented,
        AssessResult.other_than_satisfied,
        45,
        "Security team",
        "Logging disabled on several production hosts.",
    ),
    (
        "AU-6",
        ImplStatus.planned,
        AssessResult.not_assessed,
        None,
        "Security team",
        "Weekly log review planned.",
    ),
    (
        "CA-7",
        ImplStatus.partial,
        AssessResult.not_assessed,
        None,
        "Security team",
        "Monthly scanning; no dashboard yet.",
    ),
    (
        "CM-2",
        ImplStatus.implemented,
        AssessResult.satisfied,
        410,
        "Platform team",
        "Hardened images documented in 2025.",
    ),
    (
        "CM-6",
        ImplStatus.implemented,
        AssessResult.not_assessed,
        None,
        "Platform team",
        "CIS-aligned settings applied.",
    ),
    (
        "CM-7",
        ImplStatus.implemented,
        AssessResult.satisfied,
        200,
        "Platform team",
        "Service allow-lists per host role.",
    ),
    (
        "CP-9",
        ImplStatus.implemented,
        AssessResult.satisfied,
        30,
        "Platform team",
        "Nightly backups; restore test passed.",
    ),
    (
        "IA-2",
        ImplStatus.partial,
        AssessResult.other_than_satisfied,
        20,
        "IT operations",
        "MFA enforced for staff, not for all admin accounts.",
    ),
    (
        "IA-5",
        ImplStatus.implemented,
        AssessResult.not_assessed,
        None,
        "IT operations",
        "Password policy configured in IdP.",
    ),
    (
        "IR-4",
        ImplStatus.implemented,
        AssessResult.satisfied,
        90,
        "Security team",
        "Tabletop exercise completed.",
    ),
    ("RA-3", ImplStatus.implemented, AssessResult.satisfied, 150, "Security team", "Annual risk assessment."),
    (
        "RA-5",
        ImplStatus.implemented,
        AssessResult.satisfied,
        75,
        "Security team",
        "Authenticated scans monthly.",
    ),
    ("SC-7", ImplStatus.implemented, AssessResult.satisfied, 100, "Network team", "Firewall rule review."),
    (
        "SC-8",
        ImplStatus.partial,
        AssessResult.not_assessed,
        None,
        "Platform team",
        "TLS 1.2+ on most services.",
    ),
    ("SC-28", ImplStatus.not_implemented, AssessResult.not_assessed, None, "Platform team", ""),
    (
        "SI-2",
        ImplStatus.implemented,
        AssessResult.satisfied,
        50,
        "Platform team",
        "Patch policy and monthly cycle.",
    ),
    (
        "SI-4",
        ImplStatus.implemented,
        AssessResult.not_assessed,
        None,
        "Security team",
        "Log cluster collects host events.",
    ),
]

OWNERS = ["Platform team", "Network team", "IT operations", "Data team", "Digital team", "Security team"]


def seed(db: Session, today: dt.date, demo_password: str, rng_seed: int = 7) -> None:
    rng = random.Random(rng_seed)
    pw_hash = hash_password(demo_password)
    db.add_all(
        [
            User(
                email="viewer@larkspur.example", name="Vera Viewer", role=Role.viewer, password_hash=pw_hash
            ),
            User(
                email="analyst@larkspur.example", name="Ana Analyst", role=Role.analyst, password_hash=pw_hash
            ),
            User(email="admin@larkspur.example", name="Adi Admin", role=Role.admin, password_hash=pw_hash),
        ]
    )
    assets = [
        Asset(id=i, name=n, type=t, environment=e, owner=o, criticality=c, data_class=d, internet_facing=x)
        for i, n, t, e, o, c, d, x in ASSETS
    ]
    db.add_all(assets)

    n = 0
    for asset in assets:
        options = [t for t in TEMPLATES if asset.type in t.types]
        for tmpl in rng.sample(options, k=min(len(options), rng.randint(1, 4))):
            n += 1
            cvss = round(rng.uniform(*tmpl.cvss), 1)
            exploited = rng.random() < tmpl.exploited_chance
            status = rng.choices(list(FindingStatus), weights=[40, 20, 6, 30, 4], k=1)[0]
            # Open work skews recent; closed findings were found longer ago.
            age = (
                rng.randint(2, 70)
                if status in (FindingStatus.open, FindingStatus.in_progress)
                else rng.randint(30, 220)
            )
            discovered = today - dt.timedelta(days=age)
            risk = score(
                RiskInput(cvss, asset.criticality, asset.internet_facing, exploited, asset.data_class)
            )
            due = due_date(discovered, risk.rating)
            closed = None
            if status in (FindingStatus.remediated, FindingStatus.false_positive):
                closed = min(today, discovered + dt.timedelta(days=rng.randint(2, 80)))
            f = Finding(
                id=f"FND-{n:04d}",
                asset_id=asset.id,
                title=tmpl.title,
                description=f"Synthetic finding generated for the demo. Source: {tmpl.source.lower()}.",
                cwe=tmpl.cwe,
                source=tmpl.source,
                cvss=cvss,
                known_exploited=exploited,
                status=status,
                owner=asset.owner if rng.random() < 0.85 else rng.choice(OWNERS),
                discovered=discovered,
                due=due,
                closed=closed,
                control_ids=list(tmpl.controls),
            )
            f.history.append(
                FindingEvent(
                    at=dt.datetime.combine(discovered, dt.time(9, 0)),
                    actor="Import",
                    summary=f"Recorded from {tmpl.source.lower()}",
                )
            )
            if closed:
                f.history.append(
                    FindingEvent(
                        at=dt.datetime.combine(closed, dt.time(16, 30)),
                        actor=f.owner,
                        summary=f"Status changed to {status.value}",
                    )
                )
            db.add(f)

    for cid, impl, result, days_ago, owner, evidence in CONTROL_ASSESSMENTS:
        db.add(
            ControlAssessment(
                control_id=cid,
                implementation=impl,
                result=result,
                assessed_on=None if days_ago is None else today - dt.timedelta(days=days_ago),
                assessor="" if days_ago is None else "Internal audit",
                evidence=evidence,
                owner=owner,
            )
        )
    db.commit()
