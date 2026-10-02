"""Load and validate inputs.

Every loader returns (valid_records, data_quality_issues) and never raises on a
bad ROW. Only a missing/unreadable FILE is fatal. To move to API ingestion,
replace these functions with ones returning the same shapes.
"""
from __future__ import annotations

import csv
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .models import Asset, DataQualityIssue, LogSource, RiskException

ASSETS_FILE = "assets.csv"
SIEM_FILE = "siem_sources.csv"
EXCEPTIONS_FILE = "exceptions.csv"

ASSET_FIELDS = ("asset_id", "hostname", "environment", "pci_scope", "owner", "criticality")
SIEM_FIELDS = ("hostname", "source_type", "last_event_at", "retention_days", "hot_retention_days")
EXCEPTION_FIELDS = ("asset_id", "control_id", "reason", "approved_by", "approved_at", "expires_at")


class IngestError(Exception):
    """Fatal input problem (file missing, header wrong, bad controls.json)."""


def normalize_hostname(hostname: str) -> str:
    """Join key between inventory and SIEM: case and whitespace insensitive."""
    return hostname.strip().lower()


def sha256_file(path: Path) -> str:
    """SHA-256 of a file's bytes, for tamper-evident evidence tracking."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_timestamp(raw: str) -> datetime:
    """Parse ISO 8601 into an aware UTC datetime. Naive values are rejected:
    an ambiguous timezone is not acceptable audit evidence."""
    text = raw.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ValueError("timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def _parse_yes_no(raw: str) -> bool:
    value = raw.strip().lower()
    if value not in ("yes", "no"):
        raise ValueError("expected 'yes' or 'no'")
    return value == "yes"


def _parse_days(raw: str) -> int:
    value = int(raw.strip())
    if value < 0:
        raise ValueError("must not be negative")
    return value


def _read_rows(path: Path, required: tuple[str, ...]) -> list[dict[str, str]]:
    try:
        with path.open(newline="", encoding="utf-8-sig") as handle:
            reader = csv.DictReader(handle)
            missing = [name for name in required if name not in (reader.fieldnames or [])]
            if missing:
                raise IngestError(f"{path.name}: missing columns {missing}")
            return list(reader)
    except FileNotFoundError as exc:
        raise IngestError(f"input file not found: {path}") from exc


def _load(
    path: Path,
    required: tuple[str, ...],
    key_field: str,
    build: Callable[[dict[str, str]], Any],
    converters: dict[str, Callable[[str], Any]],
) -> tuple[list[Any], list[DataQualityIssue]]:
    """Shared row loop: blank-field check, per-field conversion, issue capture."""
    records: list[Any] = []
    issues: list[DataQualityIssue] = []
    for row_number, row in enumerate(_read_rows(path, required), start=2):  # header is row 1
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


def load_assets(path: Path) -> tuple[list[Asset], list[DataQualityIssue]]:
    """Load the inventory export (assets.csv)."""
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
    """Load the SIEM export (siem_sources.csv)."""
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
    """Load approved risk acceptances (exceptions.csv)."""
    return _load(
        path,
        EXCEPTION_FIELDS,
        "asset_id",
        lambda r: RiskException(**r),
        {"approved_at": parse_timestamp, "expires_at": parse_timestamp},
    )


def load_controls(path: Path) -> dict[str, Any]:
    """Load controls.json (thresholds + framework mappings)."""
    try:
        with path.open(encoding="utf-8") as handle:
            controls = json.load(handle)
    except FileNotFoundError as exc:
        raise IngestError(f"controls file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise IngestError(f"{path.name} is not valid JSON: {exc}") from exc
    if not controls.get("controls"):
        raise IngestError(f"{path.name}: no controls defined")
    return controls
