"""Domain models for AX9. Plain frozen dataclasses: no behaviour, just data."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Status(str, Enum):
    """Audit verdicts. Order in STATUS_PRECEDENCE decides which one wins."""

    MISSING = "MISSING"
    FAIL = "FAIL"
    STALE = "STALE"
    PASS = "PASS"
    EXCEPTION = "EXCEPTION"
    NOT_EVALUATED = "NOT_EVALUATED"


@dataclass(frozen=True)
class Asset:
    """A system from the inventory (source of truth for what SHOULD log)."""

    asset_id: str
    hostname: str
    environment: str
    pci_scope: bool
    owner: str
    criticality: str


@dataclass(frozen=True)
class LogSource:
    """A host as seen by the SIEM (what IS logging)."""

    hostname: str
    source_type: str
    last_event_at: datetime
    retention_days: int
    hot_retention_days: int


@dataclass(frozen=True)
class RiskException:
    """A formally approved risk acceptance for one asset and one control.

    Named RiskException to avoid shadowing Python's builtin Exception.
    """

    asset_id: str
    control_id: str
    reason: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class DataQualityIssue:
    """A row that could not be trusted. Reported, never fatal."""

    source_file: str
    row: int
    field: str
    value: str
    problem: str
    key: str = ""  # hostname / asset_id of the affected record when known


@dataclass(frozen=True)
class Evidence:
    """Everything an auditor needs to re-perform one check."""

    source_file: str
    value: str
    observed_at: datetime | None
    rule: str
    threshold: str
    evaluated_at: datetime


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one check (one row of results.csv)."""

    check_id: str
    status: Status
    reason: str
    evidence: Evidence
    requirements: tuple[str, ...]


@dataclass(frozen=True)
class AssetFinding:
    """Verdict for one in-scope asset under one control."""

    control_id: str
    asset: Asset
    status: Status  # final, after precedence and exceptions
    underlying_status: Status  # before exceptions: the original finding stays visible
    checks: tuple[CheckResult, ...]
    failed_checks: tuple[str, ...]
    exception: RiskException | None
    exception_state: str  # none | valid | expired | not_yet_effective


@dataclass(frozen=True)
class RunResult:
    """Complete, reproducible outcome of one AX9 run."""

    as_of: datetime
    tool_version: str
    input_hashes: dict[str, str]
    findings: tuple[AssetFinding, ...]
    untracked: tuple[LogSource, ...]
    out_of_scope_count: int
    data_quality: tuple[DataQualityIssue, ...]
