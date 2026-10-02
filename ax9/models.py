"""Domain models: the "nouns" of AX9.

Every piece of data that flows through the tool is one of these dataclasses.
They hold data only (no logic), and they are all frozen (immutable): once a
finding is created nobody can silently change it later, which is exactly the
property you want for audit evidence.

Data flow:

    CSV rows ──ingest.py──► Asset / LogSource / RiskException / DataQualityIssue
                                   │
                              engine.py
                                   ▼
               Evidence ─► CheckResult ─► AssetFinding ─► RunResult
                                                              │
                                                       reporters.py
                                                              ▼
                                            results.json / .csv / report.md

To add a new input column: add the field here, add it to the matching
*_FIELDS tuple in ingest.py (and a converter if it is not plain text).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Status(str, Enum):
    """Audit verdicts.

    Which status "wins" when several checks fail is NOT decided here: it comes
    from `status_precedence` in controls.json, so auditors can review it.
    Inheriting from `str` makes each value serialise as plain text in JSON/CSV.
    """

    MISSING = "MISSING"  # no trustworthy evidence the asset logs at all
    FAIL = "FAIL"  # evidence exists but breaks a rule (retention, future timestamp)
    STALE = "STALE"  # the asset logged, but not recently enough
    PASS = "PASS"  # every check passed
    EXCEPTION = "EXCEPTION"  # would fail, but a valid approved risk acceptance covers it
    NOT_EVALUATED = "NOT_EVALUATED"  # check skipped because a prerequisite (coverage) failed


# ---------------------------------------------------------------------------
# Inputs: one dataclass per input file row
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Asset:
    """One system from the inventory (assets.csv).

    The inventory is the source of truth for SCOPE: it says what *should* be
    sending logs. In production this would come from the CMDB.
    """

    asset_id: str
    hostname: str  # join key with the SIEM export
    environment: str
    pci_scope: bool  # True = handles card data, so control LOG-01 applies
    owner: str  # who gets the ticket when it fails
    criticality: str  # critical | high | medium | low (used to rank risks)


@dataclass(frozen=True)
class LogSource:
    """One host as seen by the SIEM (siem_sources.csv): what *is* logging."""

    hostname: str
    source_type: str  # e.g. linux_syslog, database_audit, firewall
    last_event_at: datetime  # always timezone-aware UTC (see ingest.parse_timestamp)
    retention_days: int  # total time logs are kept (hot + archive)
    hot_retention_days: int  # time logs stay immediately searchable


@dataclass(frozen=True)
class RiskException:
    """A formally approved risk acceptance (exceptions.csv).

    "We know asset X fails control Y, and person Z accepts the risk until date D."
    Named RiskException so it does not shadow Python's built-in `Exception`.
    """

    asset_id: str
    control_id: str  # an exception only covers the control it names
    reason: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime  # after this moment the exception no longer applies


@dataclass(frozen=True)
class DataQualityIssue:
    """An input row (or value) that could not be trusted as evidence.

    Bad rows are reported, never fatal and never silently "fixed": an auditor
    must be able to see exactly what was rejected and why.
    """

    source_file: str
    row: int  # CSV line number (header = 1); 0 when not tied to one line
    field: str
    value: str
    problem: str
    key: str = ""  # hostname / asset_id of the affected record, when known


# ---------------------------------------------------------------------------
# Outputs: what the engine produces
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Evidence:
    """Everything an auditor needs to re-perform one check by hand.

    "Which file did you look at, what value did you see, when was it observed,
    which rule and threshold did you apply, and at what time?"
    """

    source_file: str
    value: str  # the value actually compared, as text (e.g. "180d", "age=66.8h")
    observed_at: datetime | None  # timestamp of the evidence itself, if any
    rule: str  # human-readable rule, e.g. "retention_days >= min_days"
    threshold: str  # e.g. ">= 365d"
    evaluated_at: datetime  # the --as-of moment of the run


@dataclass(frozen=True)
class CheckResult:
    """Outcome of one check on one asset (= one row of results.csv)."""

    check_id: str  # coverage | freshness | retention | hot_retention
    status: Status
    reason: str  # short explanation shown in reports
    evidence: Evidence
    requirements: tuple[str, ...]  # e.g. ("PCI DSS v4.0.1 10.5.1",), from controls.json


@dataclass(frozen=True)
class AssetFinding:
    """Final verdict for one in-scope asset under one control."""

    control_id: str
    asset: Asset
    status: Status  # final: after precedence AND exceptions
    underlying_status: Status  # before exceptions: the real problem never disappears
    checks: tuple[CheckResult, ...]  # every check, passed or not
    failed_checks: tuple[str, ...]  # ALL failed checks, not only the one that set the status
    exception: RiskException | None
    exception_state: str  # none | valid | expired | not_yet_effective


@dataclass(frozen=True)
class RunResult:
    """Complete, reproducible outcome of one AX9 run. Reporters read only this."""

    as_of: datetime
    tool_version: str
    input_hashes: dict[str, str]  # file name -> SHA-256, proves which evidence was used
    findings: tuple[AssetFinding, ...]
    untracked: tuple[LogSource, ...]  # in the SIEM but not in the inventory
    out_of_scope_count: int
    data_quality: tuple[DataQualityIssue, ...]
