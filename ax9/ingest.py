"""Ingestion: read the input files and turn each row into a trusted model.

Golden rule of this module: a bad ROW never stops the run, a bad FILE does.

- Bad row (invalid date, empty field, "maybe" instead of yes/no): the row is
  rejected and recorded as a DataQualityIssue. The run continues and the
  issue appears in every report.
- Bad file (missing, unreadable, wrong columns, invalid controls.json): an
  IngestError is raised and the CLI exits with code 2 ("the tool could not
  run"), which CI can tell apart from code 1 ("the tool ran and found problems").

Every loader returns `(valid_records, data_quality_issues)`. To read from an
API instead of CSV files (CMDB, Splunk, Elastic...), write a new function that
returns the same pair; nothing else in the project needs to change.
"""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .models import Asset, DataQualityIssue, LogSource, RiskException, Status

# Default file names inside --data-dir (each one can be overridden by a CLI flag).
ASSETS_FILE = "assets.csv"
SIEM_FILE = "siem_sources.csv"
EXCEPTIONS_FILE = "exceptions.csv"

# Required columns per file, in the order they are validated. Every column is
# mandatory: an empty value makes the whole row a data quality issue.
ASSET_FIELDS = ("asset_id", "hostname", "environment", "pci_scope", "owner", "criticality")
SIEM_FIELDS = ("hostname", "source_type", "last_event_at", "retention_days", "hot_retention_days")
EXCEPTION_FIELDS = ("asset_id", "control_id", "reason", "approved_by", "approved_at", "expires_at")


class IngestError(Exception):
    """Fatal input problem: the run cannot produce a trustworthy result."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def normalize_hostname(hostname: str) -> str:
    """Join key between inventory and SIEM.

    "Pay-GW-01 " in the CMDB and "pay-gw-01" in Splunk are the same machine,
    so comparison ignores case and surrounding spaces. FQDN vs short name
    (pay-gw-01.corp.local vs pay-gw-01) is NOT handled: see README limitations.
    """
    return hostname.strip().lower()


def sha256_file(path: Path) -> str:
    """Fingerprint of a file's exact bytes.

    Stored in every report so anyone can later prove which input produced a
    verdict: change one character in the file and the hash changes completely.
    Read in 64 KB chunks so large SIEM exports don't need to fit in memory.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_timestamp(raw: str) -> datetime:
    """Parse ISO 8601 (e.g. 2026-10-01T08:55:00Z) into a UTC datetime.

    A timestamp without timezone ("2026-10-01T08:55:00") is rejected on
    purpose: is it UTC? Brasília? The server's local time? An ambiguous time
    is not acceptable audit evidence. Raises ValueError, which the row loop
    turns into a DataQualityIssue.
    """
    text = raw.strip()
    if text.endswith(("Z", "z")):  # Python < 3.11 does not understand the "Z" suffix
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _parse_yes_no(raw: str) -> bool:
    """Strict yes/no: anything else ("y", "true", "maybe") is a data error, not a guess."""
    value = raw.strip().lower()
    if value not in ("yes", "no"):
        raise ValueError("expected 'yes' or 'no'")
    return value == "yes"


def _parse_days(raw: str) -> int:
    """Whole, non-negative number of days."""
    value = int(raw.strip())
    if value < 0:
        raise ValueError("must not be negative")
    return value


# ---------------------------------------------------------------------------
# Generic CSV loading
# ---------------------------------------------------------------------------


def _read_rows(path: Path, required: tuple[str, ...]) -> list[dict[str, str]]:
    """Read a CSV into dicts, after checking that every required column exists.

    `utf-8-sig` silently drops the invisible BOM that Excel adds when it saves
    "CSV UTF-8"; without it the first column name would not match.
    """
    try:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            missing = [name for name in required if name not in (reader.fieldnames or [])]
            if missing:
                raise IngestError(f"{path.name}: missing columns {missing}")
            return list(reader)
    except FileNotFoundError as exc:
        raise IngestError(f"input file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise IngestError(f"{path.name} is not UTF-8 text (save it as 'CSV UTF-8')") from exc
    except OSError as exc:  # directory instead of file, no permission, ...
        raise IngestError(f"cannot read {path}: {exc.strerror or exc}") from exc


def _load(
    path: Path,
    required: tuple[str, ...],
    key_field: str,
    build: Callable[[dict[str, Any]], Any],
    converters: dict[str, Callable[[str], Any]],
) -> tuple[list[Any], list[DataQualityIssue]]:
    """Row loop shared by every CSV loader.

    For each row and each required column:
      1. empty value                    -> issue "missing value"
      2. converter raises ValueError    -> issue "invalid value: ..."
      3. otherwise store the converted value
    A row with at least one issue is rejected entirely (half a record is not
    evidence); a clean row is turned into a model by `build`.

    `converters` maps column -> function; columns not listed stay plain text.
    `key_field` names the column that identifies the record (hostname or
    asset_id), so issues can be linked back to an asset later.
    """
    records: list[Any] = []
    issues: list[DataQualityIssue] = []
    for row_number, row in enumerate(_read_rows(path, required), start=2):  # line 1 is the header
        key = (row.get(key_field) or "").strip()
        parsed: dict[str, Any] = {}
        problems: list[DataQualityIssue] = []
        for name in required:
            raw = (row.get(name) or "").strip()
            if not raw:
                problems.append(DataQualityIssue(path.name, row_number, name, raw, "missing value", key))
                continue
            try:
                parsed[name] = converters.get(name, str)(raw)
            except ValueError as exc:
                problems.append(DataQualityIssue(path.name, row_number, name, raw, f"invalid value: {exc}", key))
        if problems:
            issues.extend(problems)
        else:
            records.append(build(parsed))
    return records, issues


# ---------------------------------------------------------------------------
# One public loader per input file
# ---------------------------------------------------------------------------


def load_assets(path: Path) -> tuple[list[Asset], list[DataQualityIssue]]:
    """Load the inventory (assets.csv).

    Extra rule: hostnames must be unique, otherwise one SIEM row would be
    matched to two assets. The first occurrence wins; duplicates are issues.
    """
    assets, issues = _load(
        path, ASSET_FIELDS, "asset_id", lambda r: Asset(**r), {"pci_scope": _parse_yes_no}
    )
    seen: set[str] = set()
    unique: list[Asset] = []
    for asset in assets:
        host = normalize_hostname(asset.hostname)
        if host in seen:
            issues.append(DataQualityIssue(path.name, 0, "hostname", asset.hostname, "duplicate hostname in inventory", asset.asset_id))
            continue
        seen.add(host)
        unique.append(asset)
    return unique, issues


def load_siem_sources(path: Path) -> tuple[list[LogSource], list[DataQualityIssue]]:
    """Load the SIEM export (siem_sources.csv). One host may appear on several
    rows (one per source type); the engine merges them."""
    return _load(
        path,
        SIEM_FIELDS,
        "hostname",
        lambda r: LogSource(**r),
        {
            "last_event_at": parse_timestamp,
            "retention_days": _parse_days,
            "hot_retention_days": _parse_days,
        },
    )


def load_exceptions(path: Path) -> tuple[list[RiskException], list[DataQualityIssue]]:
    """Load approved risk acceptances (exceptions.csv). Whether each one is
    still valid is decided by the engine, because that depends on --as-of."""
    return _load(
        path,
        EXCEPTION_FIELDS,
        "asset_id",
        lambda r: RiskException(**r),
        {"approved_at": parse_timestamp, "expires_at": parse_timestamp},
    )


# ---------------------------------------------------------------------------
# controls.json
# ---------------------------------------------------------------------------

# Check ids the engine knows how to run, and the numeric parameter each one
# needs in controls.json. Mirrors engine.CHECKS (kept here to avoid an import
# cycle); a unit test fails if the two ever drift apart.
KNOWN_CHECKS: dict[str, tuple[str, ...]] = {
    "coverage": (),
    "freshness": ("max_age_hours",),
    "retention": ("min_days",),
    "hot_retention": ("min_days",),
}
CONTROL_KEYS = ("id", "scope", "checks", "status_precedence", "mappings")


def load_controls(path: Path) -> dict[str, Any]:
    """Load and validate controls.json (thresholds + framework mappings).

    controls.json is edited by hand, so its structure is checked here, at the
    door, with a clear message. Without this a typo would surface later as a
    confusing KeyError deep inside the engine.
    """
    try:
        with path.open(encoding="utf-8") as handle:
            document = json.load(handle)
    except FileNotFoundError as exc:
        raise IngestError(f"controls file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IngestError(f"{path.name} is not valid JSON: {exc}") from exc
    except (OSError, UnicodeDecodeError) as exc:
        raise IngestError(f"cannot read {path}: {exc}") from exc

    controls = document.get("controls") if isinstance(document, dict) else None
    if not controls or not isinstance(controls, list):
        raise IngestError(f"{path.name}: expected a non-empty \"controls\" list")
    for control in controls:
        _validate_control(path.name, control)
    return document


def _validate_control(file_name: str, control: Any) -> None:
    """Raise IngestError describing the first structural problem found."""
    if not isinstance(control, dict):
        raise IngestError(f"{file_name}: each control must be an object")
    name = control.get("id", "<no id>")
    missing = [key for key in CONTROL_KEYS if key not in control]
    if missing:
        raise IngestError(f"{file_name}: control {name} is missing {missing}")
    unknown = set(control["checks"]) - set(KNOWN_CHECKS)
    if unknown:
        raise IngestError(f"{file_name}: control {name} uses unknown checks {sorted(unknown)}; known: {sorted(KNOWN_CHECKS)}")
    for check_id, params in control["checks"].items():
        for param in KNOWN_CHECKS[check_id]:
            value = params.get(param) if isinstance(params, dict) else None
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
                raise IngestError(f"{file_name}: check {check_id} needs a non-negative number for \"{param}\"")
    bad_status = set(control["status_precedence"]) - {s.value for s in Status}
    if bad_status:
        raise IngestError(f"{file_name}: control {name} has unknown statuses {sorted(bad_status)} in status_precedence")
    for mapping in control["mappings"]:
        unknown_refs = set(mapping.get("supported_by", [])) - set(control["checks"])
        if unknown_refs:
            raise IngestError(f"{file_name}: mapping {mapping.get('requirement')} refers to undefined checks {sorted(unknown_refs)}")
