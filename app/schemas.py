"""Validation for everything a user can submit."""

from __future__ import annotations

import datetime as dt
import re
from typing import Annotated

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator

from app.controls import CATALOG
from app.models import AssessResult, AssetType, DataClass, FindingStatus, ImplStatus


def _blank_to_none(v: object) -> object:
    return None if isinstance(v, str) and v.strip() == "" else v


def _checkbox(v: object) -> object:
    # HTML checkboxes send "on" when ticked and nothing when not.
    if isinstance(v, str):
        return v.lower() in {"on", "true", "1", "yes"}
    return v


OptDate = Annotated[dt.date | None, BeforeValidator(_blank_to_none)]
Checkbox = Annotated[bool, BeforeValidator(_checkbox)]
Text = Annotated[str, Field(max_length=2000)]


class _Form(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="ignore")


class AssetForm(_Form):
    id: Annotated[str, Field(pattern=r"^AST-\d{3,5}$")]
    name: Annotated[str, Field(min_length=2, max_length=120)]
    type: AssetType
    environment: Annotated[str, Field(min_length=2, max_length=40)]
    owner: Annotated[str, Field(min_length=2, max_length=120)]
    criticality: Annotated[int, Field(ge=1, le=5)]
    data_class: DataClass
    internet_facing: Checkbox = False


class AssetUpdate(_Form):
    criticality: Annotated[int, Field(ge=1, le=5)]
    data_class: DataClass
    internet_facing: Checkbox = False
    owner: Annotated[str, Field(min_length=2, max_length=120)]


class FindingCreate(_Form):
    asset_id: Annotated[str, Field(pattern=r"^AST-\d{3,5}$")]
    title: Annotated[str, Field(min_length=4, max_length=200)]
    description: Text = ""
    cwe: Annotated[str | None, BeforeValidator(_blank_to_none), Field(pattern=r"^CWE-\d{1,5}$")] = None
    source: Annotated[str, Field(min_length=2, max_length=60)]
    cvss: Annotated[float, Field(ge=0, le=10)]
    known_exploited: Checkbox = False
    owner: Annotated[str, Field(max_length=120)] = ""
    discovered: dt.date
    control_ids: list[str] = []

    @field_validator("control_ids", mode="before")
    @classmethod
    def split_controls(cls, v: object) -> object:
        if isinstance(v, str):
            return [c for c in re.split(r"[\s,]+", v.upper()) if c]
        return v

    @field_validator("control_ids")
    @classmethod
    def known_controls(cls, v: list[str]) -> list[str]:
        unknown = [c for c in v if c not in CATALOG]
        if unknown:
            raise ValueError(f"Unknown control ID(s): {', '.join(unknown)}")
        return sorted(set(v), key=lambda c: (c.split("-")[0], int(c.split("-")[1])))

    @field_validator("discovered")
    @classmethod
    def not_future(cls, v: dt.date) -> dt.date:
        if v > dt.date.today() + dt.timedelta(days=1):
            raise ValueError("Discovery date cannot be in the future")
        return v


class FindingUpdate(_Form):
    status: FindingStatus
    owner: Annotated[str, Field(max_length=120)] = ""
    due: OptDate = None
    note: Annotated[str, Field(max_length=1000)] = ""


class ControlUpdate(_Form):
    implementation: ImplStatus
    result: AssessResult
    assessed_on: OptDate = None
    assessor: Annotated[str, Field(max_length=120)] = ""
    evidence: Text = ""
    owner: Annotated[str, Field(max_length=120)] = ""

    def check(self) -> None:
        if self.result != AssessResult.not_assessed and self.assessed_on is None:
            raise ValueError("An assessment result needs the date it was assessed")
        if self.result == AssessResult.not_assessed and self.assessed_on is not None:
            raise ValueError("Remove the assessment date, or record the result")
        if self.assessed_on and self.assessed_on > dt.date.today() + dt.timedelta(days=1):
            raise ValueError("Assessment date cannot be in the future")


def errors_to_messages(exc: Exception) -> list[str]:
    """Turn a pydantic ValidationError (or ValueError) into readable messages."""
    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        out = []
        for e in exc.errors():
            field = ".".join(str(p) for p in e["loc"]) or "form"
            msg = str(e["msg"]).removeprefix("Value error, ")
            out.append(f"{field.replace('_', ' ')}: {msg}")
        return out
    return [str(exc)]
