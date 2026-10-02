"""Control evaluation: the "brain" of AX9.

Everything here is a pure function: it reads no files and never looks at the
clock (the evaluation time arrives as `as_of`). Same inputs + same as_of
always give the same verdict, which is what makes an audit reproducible and
what makes this module easy to unit test.

How one asset is judged (evaluate_asset):

    1. run every check listed for the control in controls.json
       (coverage, freshness, retention, hot_retention)
    2. combine the check statuses: the worst one wins (resolve_status)
    3. look for a risk acceptance (classify_exception)
    4. valid exception + failing asset  ->  final status EXCEPTION,
       but the original status is kept in `underlying_status`

HOW TO ADD A NEW CHECK (e.g. "event volume did not drop by 90%"):
    1. write a function with the same signature as check_freshness below and
       return a CheckOutcome
    2. register it in the CHECKS dictionary
    3. add its id and required parameters to KNOWN_CHECKS in ingest.py
    4. list it under "checks" (and in a mapping's "supported_by") in controls.json
    5. add a unit test for PASS and for the failing case
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Callable

from . import __version__
from .ingest import SIEM_FILE, normalize_hostname
from .models import (
    Asset,
    AssetFinding,
    CheckResult,
    DataQualityIssue,
    Evidence,
    LogSource,
    RiskException,
    RunResult,
    Status,
)

# What every check function returns, as a plain tuple:
#   (status, reason, evidence value, evidence timestamp, rule text, threshold text)
CheckOutcome = tuple[Status, str, str, "datetime | None", str, str]

# Signature every check function must follow:
#   source   -> the SIEM data for this asset, or None if there is no valid row
#   rejected -> data quality issues of this host's SIEM rows (to explain a MISSING)
#   params   -> this check's block from controls.json (e.g. {"min_days": 365})
#   as_of    -> the evaluation time
CheckFn = Callable[[LogSource | None, list[DataQualityIssue], dict[str, Any], datetime], CheckOutcome]

# Statuses that require someone to act; used for the exit code and reports.
ACTION_STATUSES = (Status.MISSING, Status.FAIL, Status.STALE)


def iso_utc(moment: datetime) -> str:
    """Format a UTC datetime the same way everywhere: 2026-10-01T09:00:00Z."""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def merge_sources(sources: list[LogSource]) -> LogSource:
    """Collapse several SIEM rows of the same host into one conservative view.

    A server often feeds the SIEM through several sources (syslog + app log).
    We take the NEWEST event (the host is alive if any source is alive) but the
    LOWEST retention (an auditor can only rely on the weakest source: if one
    index keeps 30 days, some of this host's logs are gone after 30 days).
    """
    return LogSource(
        hostname=sources[0].hostname,
        source_type="+".join(sorted({s.source_type for s in sources})),
        last_event_at=max(s.last_event_at for s in sources),
        retention_days=min(s.retention_days for s in sources),
        hot_retention_days=min(s.hot_retention_days for s in sources),
    )


# ---------------------------------------------------------------------------
# The checks. Each one answers a single yes/no question about one asset.
# ---------------------------------------------------------------------------


def check_coverage(source, rejected, params, as_of) -> CheckOutcome:
    """Is the asset sending logs to the SIEM at all?  (PCI DSS 10.2.1)

    A SIEM row that exists but was rejected as malformed does NOT count:
    untrustworthy evidence proves nothing, so the asset is MISSING and the
    reason explains which value was rejected.
    """
    rule = "asset must appear in SIEM sources with valid evidence"
    if source is not None:
        return Status.PASS, "asset found in SIEM", f"source_type={source.source_type}", None, rule, "present"
    if rejected:
        detail = "; ".join(f"{i.field}={i.value!r} ({i.problem})" for i in rejected)
        return Status.MISSING, f"SIEM row rejected as untrustworthy evidence: {detail}", "rejected row", None, rule, "present"
    return Status.MISSING, "asset not found in SIEM sources", "not found", None, rule, "present"


def check_freshness(source, rejected, params, as_of) -> CheckOutcome:
    """Did the asset log recently?  (PCI DSS 10.7.2: a silent source is a logging failure)

    - no valid SIEM row     -> NOT_EVALUATED (coverage already reports MISSING)
    - event in the future   -> FAIL: clock out of sync or tampered evidence
    - older than the limit  -> STALE
    The limit is inclusive: exactly 24h old still passes "<= 24h".
    """
    max_hours = params["max_age_hours"]
    rule = "as_of - last_event_at <= max_age_hours"
    threshold = f"<= {max_hours}h"
    if source is None:
        return Status.NOT_EVALUATED, "no valid SIEM evidence to evaluate", "n/a", None, rule, threshold
    observed = source.last_event_at
    if observed > as_of:
        return Status.FAIL, "last_event_at is in the future (evidence integrity issue)", iso_utc(observed), observed, rule, threshold
    age = as_of - observed
    hours = age.total_seconds() / 3600
    value = f"age={hours:.1f}h"
    if age > timedelta(hours=max_hours):
        return Status.STALE, f"no events for {hours:.1f}h", value, observed, rule, threshold
    return Status.PASS, "recent events received", value, observed, rule, threshold


def _check_min_days(field: str) -> CheckFn:
    """Build a "LogSource.<field> must be >= min_days" check.  (PCI DSS 10.5.1)

    Retention and hot retention are the same rule on different fields, so one
    factory creates both instead of two copy-pasted functions.
    """

    def check(source, rejected, params, as_of) -> CheckOutcome:
        minimum = params["min_days"]
        rule = f"{field} >= min_days"
        threshold = f">= {minimum}d"
        if source is None:
            return Status.NOT_EVALUATED, "no valid SIEM evidence to evaluate", "n/a", None, rule, threshold
        actual = getattr(source, field)
        value = f"{actual}d"
        if actual < minimum:
            return Status.FAIL, f"{field} is {actual}d, minimum is {minimum}d", value, source.last_event_at, rule, threshold
        return Status.PASS, f"{field} is {actual}d", value, source.last_event_at, rule, threshold

    return check


# Registry: check id used in controls.json -> function that runs it.
CHECKS: dict[str, CheckFn] = {
    "coverage": check_coverage,
    "freshness": check_freshness,
    "retention": _check_min_days("retention_days"),
    "hot_retention": _check_min_days("hot_retention_days"),
}


# ---------------------------------------------------------------------------
# Combining results
# ---------------------------------------------------------------------------


def resolve_status(statuses: list[Status], precedence: list[str]) -> Status:
    """Pick the asset status from its check statuses: the worst one wins.

    "Worst" is defined by `status_precedence` in controls.json
    (MISSING > FAIL > STALE > PASS). NOT_EVALUATED is not in that list on
    purpose: it is a consequence of another failure, not a finding by itself.
    """
    present = {s.value for s in statuses}
    for name in precedence:
        if name in present:
            return Status(name)
    return Status.PASS


def classify_exception(
    exceptions: list[RiskException], asset_id: str, control_id: str, as_of: datetime
) -> tuple[RiskException | None, str]:
    """Find the risk acceptance for this asset + control and say whether it applies.

    Valid means: same control, someone approved it, and as_of falls between
    approval and expiry. Returns (exception, state) where state is one of:
      none              -> no exception exists for this asset/control
      valid             -> it applies
      expired           -> it existed but ran out (reported, does NOT apply)
      not_yet_effective -> approved with a future start date (does NOT apply)
    """
    candidates = [e for e in exceptions if e.asset_id == asset_id and e.control_id == control_id]
    if not candidates:
        return None, "none"
    for exc in candidates:
        if exc.approved_by.strip() and exc.approved_at <= as_of < exc.expires_at:
            return exc, "valid"
    latest = max(candidates, key=lambda e: e.expires_at)
    return latest, "expired" if latest.expires_at <= as_of else "not_yet_effective"


def _requirements_for(control: dict[str, Any], check_id: str) -> tuple[str, ...]:
    """Framework requirements a check supports, read from controls.json mappings."""
    return tuple(
        f"{m['framework']} {m['requirement']}"
        for m in control["mappings"]
        if check_id in m["supported_by"]
    )


def evaluate_asset(
    asset: Asset,
    source: LogSource | None,
    rejected: list[DataQualityIssue],
    exceptions: list[RiskException],
    control: dict[str, Any],
    as_of: datetime,
    siem_file: str = SIEM_FILE,
) -> AssetFinding:
    """Judge one asset against one control (steps 1-4 in the module docstring)."""
    results: list[CheckResult] = []
    for check_id, params in control["checks"].items():
        status, reason, value, observed, rule, threshold = CHECKS[check_id](source, rejected, params, as_of)
        results.append(
            CheckResult(
                check_id=check_id,
                status=status,
                reason=reason,
                evidence=Evidence(siem_file, value, observed, rule, threshold, as_of),
                requirements=_requirements_for(control, check_id),
            )
        )
    underlying = resolve_status([r.status for r in results], control["status_precedence"])
    exception, state = classify_exception(exceptions, asset.asset_id, control["id"], as_of)
    # An exception only changes the verdict of a failing asset; on a passing one it is irrelevant.
    final = Status.EXCEPTION if state == "valid" and underlying is not Status.PASS else underlying
    failed = tuple(r.check_id for r in results if r.status not in (Status.PASS, Status.NOT_EVALUATED))
    return AssetFinding(control["id"], asset, final, underlying, tuple(results), failed, exception, state)


def future_timestamp_issues(sources: list[LogSource], as_of: datetime, siem_file: str = SIEM_FILE) -> list[DataQualityIssue]:
    """Flag events dated after as_of. Usually a broken NTP sync (itself a
    PCI DSS 10.6 problem) or edited evidence; either way an auditor must know."""
    return [
        DataQualityIssue(siem_file, 0, "last_event_at", iso_utc(s.last_event_at), "timestamp is in the future (evidence integrity)", s.hostname)
        for s in sources
        if s.last_event_at > as_of
    ]


def evaluate(
    assets: list[Asset],
    sources: list[LogSource],
    exceptions: list[RiskException],
    data_quality: list[DataQualityIssue],
    controls: dict[str, Any],
    as_of: datetime,
    input_hashes: dict[str, str],
    siem_file: str = SIEM_FILE,
) -> RunResult:
    """Run every control on every in-scope asset; also find untracked hosts.

    `siem_file` is the real name of the SIEM export, so evidence points to the
    file that was actually used and rejected rows can be matched to hosts.
    """
    # Index the SIEM by normalised hostname: host -> all its sources.
    by_host: dict[str, list[LogSource]] = {}
    for src in sources:
        by_host.setdefault(normalize_hostname(src.hostname), []).append(src)

    # Rejected SIEM rows, per host, so coverage can say WHY an asset is MISSING.
    rejected_by_host: dict[str, list[DataQualityIssue]] = {}
    for issue in data_quality:
        if issue.source_file == siem_file and issue.key:
            rejected_by_host.setdefault(normalize_hostname(issue.key), []).append(issue)

    findings: list[AssetFinding] = []
    out_of_scope = 0
    for control in controls["controls"]:
        # Scope comes from controls.json, e.g. {"field": "pci_scope", "equals": true}.
        field, expected = control["scope"]["field"], control["scope"]["equals"]
        for asset in assets:
            if getattr(asset, field) != expected:
                out_of_scope += 1
                continue
            host = normalize_hostname(asset.hostname)
            source = merge_sources(by_host[host]) if host in by_host else None
            findings.append(evaluate_asset(asset, source, rejected_by_host.get(host, []), exceptions, control, as_of, siem_file))

    # The reverse direction: hosts the SIEM knows about but the inventory doesn't.
    inventory_hosts = {normalize_hostname(a.hostname) for a in assets}
    untracked = tuple(
        merge_sources(srcs) for host, srcs in sorted(by_host.items()) if host not in inventory_hosts
    )
    issues = tuple(data_quality) + tuple(future_timestamp_issues(sources, as_of, siem_file))
    return RunResult(as_of, __version__, input_hashes, tuple(findings), untracked, out_of_scope, issues)


def needs_action(result: RunResult) -> bool:
    """True when anything needs human follow-up; drives exit code 1.

    A valid exception does NOT need action (the risk was formally accepted),
    but an expired one does, and so do inventory gaps and untrustworthy data.
    """
    return bool(
        any(f.status in ACTION_STATUSES for f in result.findings)
        or any(f.exception_state == "expired" for f in result.findings)
        or result.untracked
        or result.data_quality
    )
