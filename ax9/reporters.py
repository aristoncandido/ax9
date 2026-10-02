"""Reporters: turn one RunResult into outputs for four different audiences.

    results.json  -> machines (integrations, dashboards, evidence archive)
    results.csv   -> GRC analysts (Excel / Google Sheets, pivot tables)
    report.md     -> GRC manager (executive summary + what to do next)
    terminal      -> whoever ran the command (colored tables via ui.py)

Reporters never decide anything: every verdict was already made by the
engine. They only choose what to show, in what order and in which format.
To add another format (HTML, a ticketing API...), write one more function
that takes a RunResult.
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .engine import ACTION_STATUSES, iso_utc, needs_action
from .models import AssetFinding, RunResult, Status

# Display order of statuses in summary tables (best to worst).
STATUS_ORDER = [Status.PASS, Status.EXCEPTION, Status.STALE, Status.FAIL, Status.MISSING]
# Used to sort risks: a "critical" card vault comes before a "low" HR portal.
CRITICALITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SEVERITY_RANK = {Status.MISSING: 0, Status.FAIL: 1, Status.STALE: 2}

# Recommended action per failing status, shown in report.md section 7.
ACTIONS = {
    Status.MISSING: "Onboard the asset to the SIEM (or fix the rejected/missing source) and confirm events arrive; open a ticket for the asset owner.",
    Status.FAIL: "Correct retention settings (>= 365d total, >= 90d hot) or investigate the integrity of the reported timestamp.",
    Status.STALE: "Check the log forwarder/agent on the asset; a silent source is a logging failure (PCI 10.7.2) and must be addressed promptly.",
}


def _ts(moment) -> str:
    """Timestamp as text, or empty string when there is none."""
    return iso_utc(moment) if moment else ""


def summarize(result: RunResult) -> dict[str, Any]:
    """Headline numbers shared by every output.

    Two compliance figures on purpose: PASS only, and PASS + valid exceptions.
    An accepted risk is not the same as compliance, and a GRC manager must see
    both numbers side by side.
    """
    counts = Counter(f.status for f in result.findings)
    total = len(result.findings)
    passed, excepted = counts[Status.PASS], counts[Status.EXCEPTION]
    return {
        "in_scope_assets": total,
        "out_of_scope_assets": result.out_of_scope_count,
        "by_status": {s.value: counts[s] for s in STATUS_ORDER},
        "untracked_hosts": len(result.untracked),
        "expired_exceptions": sum(f.exception_state == "expired" for f in result.findings),
        "data_quality_issues": len(result.data_quality),
        "compliance_pct": round(100 * passed / total, 1) if total else 0.0,
        "compliance_pct_with_exceptions": round(100 * (passed + excepted) / total, 1) if total else 0.0,
        "action_required": needs_action(result),
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def _finding_dict(finding: AssetFinding) -> dict[str, Any]:
    """One finding as plain JSON-friendly data, evidence included."""
    exc = finding.exception
    return {
        "control_id": finding.control_id,
        "asset_id": finding.asset.asset_id,
        "hostname": finding.asset.hostname,
        "environment": finding.asset.environment,
        "owner": finding.asset.owner,
        "criticality": finding.asset.criticality,
        "status": finding.status.value,
        "underlying_status": finding.underlying_status.value,
        "failed_checks": list(finding.failed_checks),
        "exception_state": finding.exception_state,
        "exception": None
        if exc is None
        else {
            "reason": exc.reason,
            "approved_by": exc.approved_by,
            "approved_at": _ts(exc.approved_at),
            "expires_at": _ts(exc.expires_at),
        },
        "checks": [
            {
                "check_id": c.check_id,
                "status": c.status.value,
                "reason": c.reason,
                "requirements": list(c.requirements),
                "evidence": {
                    "source_file": c.evidence.source_file,
                    "value": c.evidence.value,
                    "timestamp": _ts(c.evidence.observed_at),
                    "rule": c.evidence.rule,
                    "threshold": c.evidence.threshold,
                    "evaluated_at": _ts(c.evidence.evaluated_at),
                },
            }
            for c in finding.checks
        ],
    }


def write_json(result: RunResult, controls: dict[str, Any], path: Path) -> None:
    """Complete, self-contained record of the run.

    The controls used (thresholds + mappings) are embedded too, so the file
    alone answers "which rules produced this verdict?" months later.
    """
    document = {
        "run": {"as_of": _ts(result.as_of), "tool_version": result.tool_version, "input_sha256": result.input_hashes},
        "summary": summarize(result),
        "controls": controls["controls"],
        "findings": [_finding_dict(f) for f in result.findings],
        "untracked_hosts": [
            {"hostname": u.hostname, "source_type": u.source_type, "last_event_at": _ts(u.last_event_at)} for u in result.untracked
        ],
        "data_quality_issues": [i.__dict__ for i in result.data_quality],
    }
    path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

CSV_COLUMNS = [
    "control_id", "asset_id", "hostname", "environment", "owner", "criticality",
    "check_id", "check_status", "reason", "requirements",
    "evidence_source_file", "evidence_value", "evidence_timestamp", "rule", "threshold", "evaluated_at",
    "asset_status", "asset_underlying_status", "exception_state", "exception_approved_by", "exception_expires_at",
]

# Spreadsheet apps treat a cell starting with one of these as a formula.
FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: object) -> str:
    """Neutralise CSV/formula injection (CWE-1236).

    Hostnames and exception reasons come from input files. A value such as
    =HYPERLINK("http://evil","click") would run as a formula when the GRC
    team opens results.csv in Excel. Prefixing a quote makes it plain text.
    """
    text = str(value)
    return "'" + text if text.startswith(FORMULA_PREFIXES) else text


def write_csv(result: RunResult, path: Path) -> None:
    """Flat table: one row per asset per check, ready for filters and pivots.

    Asset-level columns repeat on each of the asset's rows so every row stands
    alone (filter by check_status=FAIL and you still see owner and criticality).
    """
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_COLUMNS)
        for f in result.findings:
            for c in f.checks:
                row = [
                    f.control_id, f.asset.asset_id, f.asset.hostname, f.asset.environment, f.asset.owner, f.asset.criticality,
                    c.check_id, c.status.value, c.reason, "; ".join(c.requirements),
                    c.evidence.source_file, c.evidence.value, _ts(c.evidence.observed_at), c.evidence.rule,
                    c.evidence.threshold, _ts(c.evidence.evaluated_at),
                    f.status.value, f.underlying_status.value, f.exception_state,
                    f.exception.approved_by if f.exception else "", _ts(f.exception.expires_at) if f.exception else "",
                ]
                writer.writerow([_csv_safe(v) for v in row])


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------


def _cell(text: object) -> str:
    """Escape characters that would break a Markdown table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[object]]) -> list[str]:
    """Markdown table lines, or an explicit "None." (an empty section is information too)."""
    if not rows:
        return ["_None._", ""]
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    lines += ["| " + " | ".join(_cell(v) for v in row) + " |" for row in rows]
    return lines + [""]


def _risk_key(f: AssetFinding) -> tuple[int, int, str]:
    """Sort key for "top risks": most critical asset first, then worst status."""
    return (CRITICALITY_RANK.get(f.asset.criticality, 9), SEVERITY_RANK.get(f.status, 9), f.asset.hostname)


def render_markdown(result: RunResult, controls: dict[str, Any]) -> str:
    """Build report.md, written for a GRC manager.

    Sections go from "how bad is it?" (summary, top risks) to "why?" (by
    requirement, evidence, exceptions) to "what now?" (actions), and end with
    the input hashes that make the report verifiable.
    """
    summary = summarize(result)
    findings = list(result.findings)
    at_risk = sorted((f for f in findings if f.status in ACTION_STATUSES), key=_risk_key)
    verdict = "ACTION REQUIRED" if summary["action_required"] else "COMPLIANT"
    out: list[str] = [
        "# AX9 Audit Report: Audit log compliance",
        "",
        f"- **Evaluated at (as-of):** {_ts(result.as_of)}",
        f"- **Tool version:** {result.tool_version}",
        f"- **Verdict:** {verdict}",
        "",
        "## 1. Executive summary",
        "",
        f"- **Compliance:** {summary['compliance_pct']}% of in-scope assets fully PASS "
        f"({summary['compliance_pct_with_exceptions']}% counting accepted-risk exceptions).",
        f"- **In-scope assets:** {summary['in_scope_assets']} (out of scope and ignored: {summary['out_of_scope_assets']})",
        f"- **Untracked hosts (inventory gap):** {summary['untracked_hosts']}",
        f"- **Expired exceptions:** {summary['expired_exceptions']}",
        f"- **Evidence quality issues:** {summary['data_quality_issues']}",
        "",
    ]
    out += _table(["Status", "Assets"], [[s.value, summary["by_status"][s.value]] for s in STATUS_ORDER])
    out += ["### Top risks (by asset criticality, then severity)", ""]
    out += _table(
        ["Asset", "Criticality", "Status", "Failed checks", "Owner"],
        [[f.asset.hostname, f.asset.criticality, f.status.value, ", ".join(f.failed_checks), f.asset.owner] for f in at_risk[:5]],
    )

    # One subsection per framework requirement, with its rationale AND its
    # limitation: saying what a check does not prove is part of honest reporting.
    out += ["## 2. Failures grouped by framework requirement", ""]
    for control in controls["controls"]:
        for mapping in control["mappings"]:
            rows = [
                [f.asset.hostname, c.check_id, c.status.value, c.reason, f.status.value]
                for f in findings
                for c in f.checks
                if c.check_id in mapping["supported_by"] and c.status not in (Status.PASS, Status.NOT_EVALUATED)
            ]
            out += [f"### {mapping['framework']} {mapping['requirement']}", "", f"_{mapping['summary']}_", ""]
            out += [f"- **Supported by checks:** {', '.join(mapping['supported_by'])}",
                    f"- **Why:** {mapping['rationale']}",
                    f"- **Does NOT prove:** {mapping['limitation']}", ""]
            out += _table(["Asset", "Check", "Check status", "Detail", "Final asset status"], rows)

    out += ["## 3. Missing and stale evidence", ""]
    out += _table(
        ["Asset", "Status", "Detail"],
        [[f.asset.hostname, f.status.value if f.status is not Status.EXCEPTION else "EXCEPTION (" + f.underlying_status.value + ")",
          "; ".join(c.reason for c in f.checks if c.status in (Status.MISSING, Status.STALE))]
         for f in findings if any(c.status in (Status.MISSING, Status.STALE) for c in f.checks)],
    )

    out += ["## 4. Exceptions (risk acceptances)", ""]
    out += _table(
        ["Asset", "State", "Underlying finding", "Approved by", "Expires", "Reason"],
        [[f.asset.hostname, f.exception_state.upper(), f.underlying_status.value, f.exception.approved_by,
          _ts(f.exception.expires_at), f.exception.reason] for f in findings if f.exception],
    )
    out += ["An EXPIRED exception does not apply: the asset is reported with its original finding.", ""]

    out += ["## 5. Untracked hosts (in SIEM, not in inventory)", ""]
    out += _table(
        ["Hostname", "Source type", "Last event"],
        [[u.hostname, u.source_type, _ts(u.last_event_at)] for u in result.untracked],
    )

    out += ["## 6. Evidence quality issues", ""]
    out += _table(
        ["File", "Row", "Record", "Field", "Value", "Problem"],
        [[i.source_file, i.row or "n/a", i.key, i.field, i.value, i.problem] for i in result.data_quality],
    )

    out += ["## 7. Recommended actions", ""]
    statuses = {f.status for f in findings}
    steps = [ACTIONS[s] for s in ACTION_STATUSES if s in statuses]
    if summary["expired_exceptions"]:
        steps.append("Renew or retire expired exceptions; until then the original finding stands.")
    if result.untracked:
        steps.append("Add untracked hosts to the inventory (and scope them) or decommission them.")
    if result.data_quality:
        steps.append("Fix the rejected/suspect rows at the source system and re-run; rejected evidence is never counted as proof.")
    out += [f"{n}. {step}" for n, step in enumerate(steps, 1)] or ["No action required."]

    out += ["", "## 8. Evidence integrity (SHA-256 of inputs)", ""]
    out += _table(["File", "SHA-256"], [[name, f"`{digest}`"] for name, digest in sorted(result.input_hashes.items())])
    return "\n".join(out) + "\n"


def write_markdown(result: RunResult, controls: dict[str, Any], path: Path) -> None:
    path.write_text(render_markdown(result, controls), encoding="utf-8")


# ---------------------------------------------------------------------------
# Terminal tables
# ---------------------------------------------------------------------------

STATUS_COLORS = {
    Status.PASS: "green", Status.EXCEPTION: "cyan", Status.STALE: "yellow",
    Status.FAIL: "red", Status.MISSING: "bold_red",
}
NARROW_TERMINAL = 120  # below this width the ID and OWNER columns are hidden
# Worst first, so the most urgent line is the first one the reader sees.
TABLE_ORDER = {Status.MISSING: 0, Status.FAIL: 1, Status.STALE: 2, Status.EXCEPTION: 3, Status.PASS: 4}


def _console_detail(f: AssetFinding) -> str:
    """One-line explanation for the DETAIL column."""
    if f.status is Status.PASS:
        return "all checks passed"
    reasons = "; ".join(c.reason for c in f.checks if c.check_id in f.failed_checks)
    if f.status is Status.EXCEPTION:
        return f"accepted risk until {_ts(f.exception.expires_at)[:10]} ({reasons})"
    if f.exception_state == "expired":
        return f"{reasons} [exception EXPIRED {_ts(f.exception.expires_at)[:10]}]"
    return reasons


def write_console(result: RunResult, ui: Any) -> None:
    """Kali-style summary on the terminal. `ui` is a ui.UI instance.

    This is a quick view only: long details are truncated to fit the screen,
    while the files above always keep the full text.
    """
    summary = summarize(result)
    findings = sorted(
        result.findings,
        key=lambda f: (TABLE_ORDER[f.status], CRITICALITY_RANK.get(f.asset.criticality, 9), f.asset.hostname),
    )
    headers = ["ASSET", "ID", "CRITICALITY", "STATUS", "FAILED CHECKS", "OWNER", "DETAIL"]
    rows = [
        # A (text, color) tuple tells ui.table to color that single cell.
        [f.asset.hostname, f.asset.asset_id, f.asset.criticality, (f.status.value, STATUS_COLORS[f.status]),
         ", ".join(f.failed_checks) or "-", f.asset.owner, _console_detail(f)]
        for f in findings
    ]
    if ui.width < NARROW_TERMINAL:
        keep = [i for i, h in enumerate(headers) if h not in ("ID", "OWNER")]
        headers = [headers[i] for i in keep]
        rows = [[row[i] for i in keep] for row in rows]
    control_ids = ", ".join(sorted({f.control_id for f in findings}))
    ui.table(f"Findings: {control_ids} (worst first)", headers, rows)
    ui.table(
        "Untracked hosts: in SIEM, not in inventory",
        ["HOSTNAME", "SOURCE TYPE", "LAST EVENT"],
        [[u.hostname, u.source_type, _ts(u.last_event_at)] for u in result.untracked],
    )
    ui.table(
        "Evidence quality issues",
        ["FILE", "ROW", "RECORD", "FIELD", "PROBLEM"],
        [[i.source_file, str(i.row or "-"), i.key, i.field, (i.problem, "yellow")] for i in result.data_quality],
    )
    ui.heading("Compliance")
    ui.bar("PASS only", summary["compliance_pct"])
    ui.bar("PASS + accepted exceptions", summary["compliance_pct_with_exceptions"])
    ui.blank()
