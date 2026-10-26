"""NIST SP 800-53 Rev. 5 control catalog subset, plus assessment classification.

Only a selection of controls relevant to the demo organisation is included.
Titles follow SP 800-53 Rev. 5. The RMF and STIG material is illustrative
context for the mapping view, not an authoritative crosswalk.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass
from enum import StrEnum

from app.models import AssessResult, ImplStatus

FAMILIES: dict[str, str] = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "RA": "Risk Assessment",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
}

CATALOG: dict[str, str] = {
    "AC-2": "Account Management",
    "AC-6": "Least Privilege",
    "AC-17": "Remote Access",
    "AU-2": "Event Logging",
    "AU-6": "Audit Record Review, Analysis, and Reporting",
    "CA-7": "Continuous Monitoring",
    "CM-2": "Baseline Configuration",
    "CM-6": "Configuration Settings",
    "CM-7": "Least Functionality",
    "CP-9": "System Backup",
    "IA-2": "Identification and Authentication (Organizational Users)",
    "IA-5": "Authenticator Management",
    "IR-4": "Incident Handling",
    "RA-3": "Risk Assessment",
    "RA-5": "Vulnerability Monitoring and Scanning",
    "SC-7": "Boundary Protection",
    "SC-8": "Transmission Confidentiality and Integrity",
    "SC-28": "Protection of Information at Rest",
    "SI-2": "Flaw Remediation",
    "SI-4": "System Monitoring",
}

#: An assessment older than this is treated as expired, so the control counts as unverified.
ASSESSMENT_VALID_DAYS = 365


def family(control_id: str) -> str:
    return FAMILIES[control_id.split("-")[0]]


class Verification(StrEnum):
    verified = "verified"
    deficient = "deficient"
    expired = "assessment expired"
    unverified = "implemented, not verified"
    not_implemented = "not implemented"
    not_applicable = "not applicable"


#: Display order, from best to most in need of attention.
VERIFICATION_ORDER = [
    Verification.verified,
    Verification.unverified,
    Verification.expired,
    Verification.deficient,
    Verification.not_implemented,
    Verification.not_applicable,
]


@dataclass(frozen=True)
class ControlState:
    verification: Verification
    explanation: str


def classify(
    implementation: ImplStatus,
    result: AssessResult,
    assessed_on: dt.date | None,
    today: dt.date,
) -> ControlState:
    """Separate what the organisation *claims* from what an assessment has *shown*."""
    if implementation == ImplStatus.not_applicable:
        return ControlState(Verification.not_applicable, "Marked not applicable to this system.")
    if result == AssessResult.other_than_satisfied:
        return ControlState(Verification.deficient, "Assessed and found other than satisfied.")
    if implementation in (ImplStatus.planned, ImplStatus.not_implemented):
        return ControlState(Verification.not_implemented, f"Implementation is {implementation.value}.")
    if result == AssessResult.satisfied and assessed_on is not None:
        age = (today - assessed_on).days
        if age > ASSESSMENT_VALID_DAYS:
            return ControlState(
                Verification.expired,
                f"Last satisfied assessment was {age} days ago, older than {ASSESSMENT_VALID_DAYS} days.",
            )
        partial = " Implementation is only partial." if implementation == ImplStatus.partial else ""
        return ControlState(
            Verification.verified, f"Assessed as satisfied on {assessed_on.isoformat()}.{partial}"
        )
    return ControlState(
        Verification.unverified,
        f"Reported as {implementation.value}, but no assessment has confirmed it.",
    )


#: RMF steps (NIST SP 800-37 Rev. 2) and where this demo supports each one.
RMF_STEPS: list[tuple[str, str, str]] = [
    (
        "Prepare",
        "Establish context and priorities for managing risk.",
        "Asset owners and criticality ratings",
    ),
    ("Categorize", "Categorise the system by the impact of a loss.", "Asset data classification"),
    ("Select", "Choose the controls that apply.", "Control register (selected SP 800-53 controls)"),
    ("Implement", "Put controls in place and document how.", "Implementation status and evidence notes"),
    (
        "Assess",
        "Check controls are implemented correctly and working.",
        "Assessment result, date and assessor",
    ),
    ("Authorize", "A senior official accepts the remaining risk.", "Not implemented: needs a human decision"),
    ("Monitor", "Keep watching controls and risk over time.", "Findings, remediation tracking, expiry"),
]

#: STIG severity categories, paraphrased, with how this demo's ratings loosely correspond.
STIG_CATEGORIES: list[tuple[str, str, str]] = [
    (
        "CAT I",
        "Weaknesses that can directly and immediately lead to loss of confidentiality, "
        "availability or integrity.",
        "Usually critical in SecureScope",
    ),
    (
        "CAT II",
        "Weaknesses with the potential to lead to loss of confidentiality, availability or integrity.",
        "Usually high or medium",
    ),
    (
        "CAT III",
        "Weaknesses that degrade the measures protecting against loss.",
        "Usually medium or low",
    ),
]
