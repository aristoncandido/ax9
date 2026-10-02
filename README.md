# AX9 (Audit X9)

> **Audit X9 :: your logs can't hide.** In Brazilian slang an *"X9"* is a snitch: AX9 snitches on payment systems that are not logging the way an auditor expects.

AX9 is an automated auditor for one control: **are all PCI in-scope systems sending audit logs to the SIEM, recently, and retaining them long enough?** It compares the asset inventory with a SIEM export and produces an evidence-backed verdict per asset for GRC reporting.

Python 3.10+, standard library only (no `pip install`, no network).

**Reviewer quick path:** [run](#run) · [control and validation logic](#control-and-validation-logic) · [framework mapping](#framework-mapping) · [assumptions and limitations](#assumptions-and-limitations) · sample input: [`sample_data/`](sample_data/) · sample output: [`sample_output/report.md`](sample_output/report.md)

---

## Run

```bash
git clone https://github.com/aristoncandido/ax9.git
cd ax9
python -m ax9 --as-of 2026-10-01T09:00:00Z      # audit the sample data
python -m unittest discover -s tests -v          # run the tests
```

`--as-of` fixes the evaluation time so the result is reproducible (default: now). Reports are written to `output/`.

To audit your own data:

```bash
python -m ax9 --data-dir path/to/folder                      # folder with the 3 CSVs
python -m ax9 --siem my_splunk_export.csv                    # or replace a single file
```

| Option | Purpose |
|---|---|
| `--data-dir` | Folder with `assets.csv`, `siem_sources.csv`, `exceptions.csv` (default `sample_data`) |
| `--assets` / `--siem` / `--exceptions` | Use a specific file instead |
| `--controls` | Rules file (default `controls.json`) |
| `--as-of` | Evaluation time, ISO 8601 UTC |
| `--out-dir` | Where reports go (default `output`) |
| `--no-banner` / `--no-anim` | Hide the banner / skip the animation |

**Exit codes:** `0` compliant · `1` action required · `2` the run failed (bad file or argument). This lets CI tell "not compliant" from "tool broken".

---

## How it works

```
assets.csv        (what SHOULD log) ─┐
siem_sources.csv  (what IS logging) ─┼─► ingest ─► engine ─► reports
exceptions.csv    (accepted risks)  ─┤   validate   apply     JSON / CSV / Markdown
controls.json     (the rules)       ─┘   each row   the rules + terminal tables
```

1. **Ingest** reads the CSVs. A bad row (invalid date, empty field) is rejected and reported as an *evidence quality issue*; it never crashes the run and never counts as proof.
2. **Engine** matches inventory and SIEM by hostname and runs four checks on every asset with `pci_scope = yes`. The worst result wins, then valid risk exceptions are applied.
3. **Reports** present the verdicts for each audience.

Comparing both lists is the point: a server that stopped logging simply disappears from the SIEM, so only the inventory reveals it is **MISSING**. In the other direction, a host in the SIEM but not in the inventory is **UNTRACKED** (inventory gap).

---

## Control and validation logic

**LOG-01: Audit log coverage, freshness and retention for PCI in-scope assets.** Thresholds live in `controls.json`, so they can be changed without touching code.

| Check | Rule | On failure |
|---|---|---|
| Coverage | asset has a valid row in the SIEM export | `MISSING` |
| Freshness | `as_of - last_event_at <= 24h` | `STALE` (`FAIL` if the timestamp is in the future) |
| Retention | `retention_days >= 365` | `FAIL` |
| Hot retention | `hot_retention_days >= 90` | `FAIL` |

- **Precedence:** `MISSING > FAIL > STALE > PASS`. All failed checks are still listed.
- **Exceptions:** a risk acceptance applies only if it is approved, matches the control and has not expired. The asset becomes `EXCEPTION`, but the original finding stays visible. An expired exception does not apply and is reported.
- **Out of scope** (`pci_scope = no`) assets are ignored and counted.
- **Evidence:** every check records source file, value, timestamp, rule, threshold and evaluation time. Reports include the SHA-256 of every input (including `controls.json`), so any later change to the data or the rules is detectable.

---

## Framework mapping

| Requirement | Check | Does **not** prove |
|---|---|---|
| PCI DSS v4.0.1 **10.2.1**: audit logs enabled and active | Coverage | that every required event type is logged |
| PCI DSS v4.0.1 **10.7.2**: logging failures detected and addressed promptly | Freshness | that an alert was raised or log content is complete |
| PCI DSS v4.0.1 **10.5.1**: 12 months retained, 3 months immediately available | Retention, hot retention | that old logs are actually restorable |
| SOC 2 **CC7.2**: system components monitored for anomalies | Coverage, freshness | that detection rules exist or alerts are reviewed |

The rationale for each mapping is in `controls.json`.

---

## Inputs and outputs

**Inputs** (CSV, timestamps in ISO 8601 with timezone, e.g. `2026-10-01T08:55:00Z`):

| File | Columns |
|---|---|
| `assets.csv` | `asset_id, hostname, environment, pci_scope (yes/no), owner, criticality` |
| `siem_sources.csv` | `hostname, source_type, last_event_at, retention_days, hot_retention_days` |
| `exceptions.csv` | `asset_id, control_id, reason, approved_by, approved_at, expires_at` |

The sample data contains one of each case: PASS, STALE, FAIL (retention), FAIL (hot retention), MISSING, valid and expired exceptions, an out-of-scope asset, an untracked host, a malformed row and a future timestamp. In production these files would come from the CMDB and SIEM APIs; only `ax9/ingest.py` would change.

**Outputs** (in `output/`):

| File | For |
|---|---|
| `report.md` | GRC manager: compliance %, top risks, failures by requirement, exceptions, untracked hosts, recommended actions |
| `results.csv` | Analysts: one row per asset per check, ready for spreadsheets |
| `results.json` | Integrations: full run metadata, input hashes and findings |

The terminal also shows colored tables (worst first) and the compliance gauge.

---

## Assumptions and limitations

**Assumptions:** the inventory is the source of truth for scope; the SIEM export is accurate; hostnames match between both; retention values reflect the effective index policy.

**Limitations:**
- Checks log metadata, not log content.
- Configured retention is not proof that logs can be restored.
- Hostname matching can miss renamed hosts or FQDN vs short-name differences.
- Each run is one point in time.
- New kinds of checks need code: add a function to `CHECKS` in `ax9/engine.py`, then reference it in `controls.json`.

---

Developed by **Ariston Cândido**.
