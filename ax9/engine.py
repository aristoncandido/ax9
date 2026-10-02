"""Control evaluation. Pure functions: no file access, no clock.

Same inputs + same as_of => same result, which is what makes an audit
reproducible.
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

# (status, reason, evidence value, evidence timestamp, rule text, threshold text)
CheckOutcome = tuple[Status, str, str, "datetime | None", str, str]
CheckFn = Callable[[LogSource | None, list[DataQualityIssue], dict[str, Any], datetime], CheckOutcome]


def iso_utc(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def merge_sources(sources: list[LogSource]) -> LogSource:
    """Collapse several SIEM sources of one host into the conservative view:
    newest event, but the LOWEST retention (the weakest source is what an
    auditor can rely on)."""
    return LogSource(
        hostname=sources[0].hostname,
        source_type="+".join(sorted({s.source_type for s in sources})),
        last_event_at=max(s.last_event_at for s in sources),
        retention_days=min(s.retention_days for s in sources),
        hot_retention_days=min(s.hot_retention_days for s in sources),
    )


def check_coverage(source, rejected, params, as_of) -> CheckOutcome:
    rule = "asset must appear in SIEM sources with valid evidence"
    if source is not None:
        return Status.PASS, "asset found in SIEM", f"source_type={source.source_type}", None, rule, "present"
    if rejected:
        detail = "; ".join(f"{i.field}={i.value!r} ({i.problem})" for i in rejected)
        return Status.MISSING, f"SIEM row rejected as untrustworthy evidence: {detail}", "rejected row", None, rule, "present"
    return Status.MISSING, "asset not found in SIEM sources", "not found", None, rule, "present"


def check_freshness(source, rejected, params, as_of) -> CheckOutcome:
    max_hours = params["max_age_hours"]
    rule = "as_of - last_event_at <= max_age_hours"
    threshold = f"<= {max_hours}h"
    if source is None:
        return Status.NOT_EVALUATED, "no valid SIEM evidence to evaluate", "n/a", None, rule, threshold
    observed = source.last_event_at
    if observed > as_of:
        return Status.FAIL, "last_event_at is in the future (evidence integrity issue)", iso_utc(observed), observed, rule, threshold
    age = as_of - observed
    value = f"age={age.total_seconds() / 3600:.1f}h"
    if age > timedelta(hours=max_hours):
        return Status.STALE, f"no events for {age.total_seconds() / 3600:.1f}h", value, observed, rule, threshold
    return Status.PASS, "recent events received", value, observed, rule, threshold


def _check_min_days(field: str):
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


CHECKS: dict[str, CheckFn] = {
    "coverage": check_coverage,
    "freshness": check_freshness,
    "retention": _check_min_days("retention_days"),
    "hot_retention": _check_min_days("hot_retention_days"),
}


def resolve_status(statuses: list[Status], precedence: list[str]) -> Status:
    """Worst status wins, per the precedence list in controls.json.
    NOT_EVALUATED checks are ignored: they are a consequence of another failure."""
    present = {s.value for s in statuses}
    for name in precedence:
        if name in present:
            return Status(name)
    return Status.PASS


def classify_exception(
    exceptions: list[RiskException], asset_id: str, control_id: str, as_of: datetime
) -> tuple[RiskException | None, str]:
    """Find the exception applying to asset+control. A valid one wins; otherwise
    report why the best candidate does not apply."""
    candidates = [e for e in exceptions if e.asset_id == asset_id and e.control_id == control_id]
    if not candidates:
        return None, "none"
    for exc in candidates:
        if exc.approved_by.strip() and exc.approved_at <= as_of < exc.expires_at:
            return exc, "valid"
    latest = max(candidates, key=lambda e: e.expires_at)
    return latest, "expired" if latest.expires_at <= as_of else "not_yet_effective"


def _requirements_for(control: dict[str, Any], check_id: str) -> tuple[str, ...]:
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
    """Run every check of a control on one asset and combine the results."""
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
    final = Status.EXCEPTION if state == "valid" and underlying is not Status.PASS else underlying
    failed = tuple(r.check_id for r in results if r.status not in (Status.PASS, Status.NOT_EVALUATED))
    return AssetFinding(control["id"], asset, final, underlying, tuple(results), failed, exception, state)


def future_timestamp_issues(sources: list[LogSource], as_of: datetime, siem_file: str = SIEM_FILE) -> list[DataQualityIssue]:
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
    """Evaluate every control for every in-scope asset and detect untracked hosts."""
    by_host: dict[str, list[LogSource]] = {}
    for src in sources:
        by_host.setdefault(normalize_hostname(src.hostname), []).append(src)
    rejected_by_host: dict[str, list[DataQualityIssue]] = {}
    for issue in data_quality:
        if issue.source_file == siem_file and issue.key:
            rejected_by_host.setdefault(normalize_hostname(issue.key), []).append(issue)

    findings: list[AssetFinding] = []
    out_of_scope = 0
    for control in controls["controls"]:
        field, expected = control["scope"]["field"], control["scope"]["equals"]
        for asset in assets:
            if getattr(asset, field) != expected:
                out_of_scope += 1
                continue
            host = normalize_hostname(asset.hostname)
            source = merge_sources(by_host[host]) if host in by_host else None
            findings.append(evaluate_asset(asset, source, rejected_by_host.get(host, []), exceptions, control, as_of, siem_file))

    inventory_hosts = {normalize_hostname(a.hostname) for a in assets}
    untracked = tuple(
        merge_sources(srcs) for host, srcs in sorted(by_host.items()) if host not in inventory_hosts
    )
    issues = tuple(data_quality) + tuple(future_timestamp_issues(sources, as_of, siem_file))
    return RunResult(as_of, __version__, input_hashes, tuple(findings), untracked, out_of_scope, issues)


ACTION_STATUSES = (Status.MISSING, Status.FAIL, Status.STALE)


def needs_action(result: RunResult) -> bool:
    """True when anything requires human follow-up. Drives the CI exit code."""
    return bool(
        any(f.status in ACTION_STATUSES for f in result.findings)
        or any(f.exception_state == "expired" for f in result.findings)
        or result.untracked
        or result.data_quality
    )
