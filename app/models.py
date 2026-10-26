"""Database tables."""

from __future__ import annotations

import datetime as dt
import enum

from sqlalchemy import JSON, Boolean, Date, DateTime, Enum, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class Role(enum.StrEnum):
    viewer = "viewer"
    analyst = "analyst"
    admin = "admin"


class AssetType(enum.StrEnum):
    server = "server"
    workstation = "workstation"
    network = "network device"
    cloud = "cloud service"
    application = "application"
    database = "database"


class DataClass(enum.StrEnum):
    public = "public"
    internal = "internal"
    confidential = "confidential"
    restricted = "restricted"


class FindingStatus(enum.StrEnum):
    open = "open"
    in_progress = "in progress"
    risk_accepted = "risk accepted"
    remediated = "remediated"
    false_positive = "false positive"


OPEN_STATUSES = (FindingStatus.open, FindingStatus.in_progress)


class ImplStatus(enum.StrEnum):
    implemented = "implemented"
    partial = "partially implemented"
    planned = "planned"
    not_implemented = "not implemented"
    not_applicable = "not applicable"


class AssessResult(enum.StrEnum):
    not_assessed = "not assessed"
    satisfied = "satisfied"
    other_than_satisfied = "other than satisfied"


def _enum(e: type[enum.Enum]) -> Enum:
    # Store the human-readable value, not the Python name.
    return Enum(e, values_callable=lambda x: [m.value for m in x], native_enum=False, validate_strings=True)


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(120))
    role: Mapped[Role] = mapped_column(_enum(Role))
    password_hash: Mapped[str] = mapped_column(String(255))
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    type: Mapped[AssetType] = mapped_column(_enum(AssetType))
    environment: Mapped[str] = mapped_column(String(40))
    owner: Mapped[str] = mapped_column(String(120))
    #: 1 (low) to 5 (mission critical). Set by the organisation; drives risk scoring.
    criticality: Mapped[int] = mapped_column(Integer)
    data_class: Mapped[DataClass] = mapped_column(_enum(DataClass))
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    findings: Mapped[list[Finding]] = relationship(back_populates="asset", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[str] = mapped_column(String(20), primary_key=True)
    asset_id: Mapped[str] = mapped_column(ForeignKey("assets.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")
    cwe: Mapped[str | None] = mapped_column(String(20), nullable=True)
    source: Mapped[str] = mapped_column(String(60))
    cvss: Mapped[float] = mapped_column(Float)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[FindingStatus] = mapped_column(_enum(FindingStatus), default=FindingStatus.open)
    owner: Mapped[str] = mapped_column(String(120), default="")
    discovered: Mapped[dt.date] = mapped_column(Date)
    due: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    closed: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    #: NIST SP 800-53 control IDs this finding is evidence against.
    control_ids: Mapped[list[str]] = mapped_column(JSON, default=list)
    asset: Mapped[Asset] = relationship(back_populates="findings")
    history: Mapped[list[FindingEvent]] = relationship(
        back_populates="finding", cascade="all, delete-orphan", order_by="FindingEvent.at.desc()"
    )


class FindingEvent(Base):
    __tablename__ = "finding_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[str] = mapped_column(ForeignKey("findings.id", ondelete="CASCADE"), index=True)
    at: Mapped[dt.datetime] = mapped_column(DateTime)
    actor: Mapped[str] = mapped_column(String(200))
    summary: Mapped[str] = mapped_column(Text)
    finding: Mapped[Finding] = relationship(back_populates="history")


class ControlAssessment(Base):
    __tablename__ = "control_assessments"
    control_id: Mapped[str] = mapped_column(String(12), primary_key=True)
    implementation: Mapped[ImplStatus] = mapped_column(_enum(ImplStatus))
    result: Mapped[AssessResult] = mapped_column(_enum(AssessResult), default=AssessResult.not_assessed)
    assessed_on: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    assessor: Mapped[str] = mapped_column(String(120), default="")
    evidence: Mapped[str] = mapped_column(Text, default="")
    owner: Mapped[str] = mapped_column(String(120), default="")
