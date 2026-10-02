# AX9 (Audit X9)

> **Audit X9 :: your logs can't hide.** In Brazilian slang, an "X9" is a snitch: AX9 snitches on every payment system that is not logging the way the auditor expects.

AX9 is a small automated auditor. It compares an **asset inventory** (what *should* be logging) with a **SIEM export** (what *is* logging), applies the rules of one security control, and produces an evidence-backed verdict per asset for GRC reporting.

It answers one question:

> *Can we **prove** that every in-scope payment system is sending audit logs to the SIEM, recently, and retaining them as required?*

---

## Quick start

Requires **Python 3.10+**. Standard library only: no `pip install`, no network, no credentials.

```bash
# Run against the bundled sample data (outputs go to ./output)
python -m ax9 --as-of 2026-10-01T09:00:00Z

# Run the tests
python -m unittest discover -s tests -v
```

### Using your own data

Nothing is hardcoded: every input is read at run time. Point AX9 at a folder, or at individual files:

```bash
# A folder containing assets.csv, siem_sources.csv and exceptions.csv
python -m ax9 --data-dir /path/to/october_audit

# Individual files with any name (e.g. a fresh SIEM export)
python -m ax9 --assets cmdb_export.csv --siem splunk_sources_2026-10.csv --exceptions risk_register.csv
```

| Flag | Default | Purpose |
|---|---|---|
| `--data-dir` | `sample_data` | Folder holding the three input CSVs |
| `--assets` / `--siem` / `--exceptions` | from `--data-dir` | Override a single input file |
| `--controls` | `controls.json` | Thresholds and framework mappings |
| `--as-of` | now (UTC) | Evaluation time. Fix it to make a run reproducible |
| `--out-dir` | `output` | Where the reports are written |
| `--no-banner` | off | Hide the ASCII banner |
| `--no-anim` | off | Skip the banner animation and progress bar |

AX9 is deliberately **non-interactive**: it never prompts. That way the same command runs on a laptop, a cron job or a CI pipeline.

### Exit codes (for CI)

| Code | Meaning |
|---|---|
| `0` | Every in-scope asset is PASS or covered by a valid EXCEPTION |
| `1` | Action required: MISSING, FAIL, STALE, untracked hosts, expired exceptions or evidence quality issues |
| `2` | The run itself failed (missing file, invalid `--as-of`, bad `controls.json`) |

### Terminal output

On an interactive terminal, AX9 opens with an animated banner and a progress bar whose steps are the real stages of the run (load controls, parse inventory, parse SIEM sources, load exceptions, hash evidence, evaluate, write reports). The animation adds about 4 seconds and is skipped automatically when stderr is not a terminal (CI, pipes, cron), or on request with `--no-anim`.

Besides the report files, every run prints a colored summary on the terminal: a findings table sorted worst-first (MISSING → FAIL → STALE → EXCEPTION → PASS, then by asset criticality), untracked hosts, evidence quality issues and a compliance gauge.

```
[*] Findings: LOG-01 (worst first)
    ┌──────────────────┬──────┬─────────────┬───────────┬───────────────┬───────────────────┬──────────────────────────────────────────┐
    │ ASSET            │ ID   │ CRITICALITY │ STATUS    │ FAILED CHECKS │ OWNER             │ DETAIL                                   │
    ├──────────────────┼──────┼─────────────┼───────────┼───────────────┼───────────────────┼──────────────────────────────────────────┤
    │ pay-tokenizer-01 │ A009 │ critical    │ MISSING   │ coverage      │ security-eng      │ SIEM row rejected as untrustworthy evid… │
    │ card-vault-01    │ A004 │ critical    │ FAIL      │ hot_retention │ security-eng      │ hot_retention_days is 30d, minimum is 90d│
    │ ...              │      │             │           │               │                   │                                          │
    └──────────────────┴──────┴─────────────┴───────────┴───────────────┴───────────────────┴──────────────────────────────────────────┘

[*] Compliance
    PASS only                    [███░░░░░░░░░░░░░░░░░░░░░░░░░░░]  11.1%
    PASS + accepted exceptions   [███████░░░░░░░░░░░░░░░░░░░░░░░]  22.2%
```

The table fits the terminal width: long details are truncated, and below 120 columns the ID and OWNER columns are hidden. The full detail is always in `report.md` and `results.csv`.

Banner, progress and tables go to **stderr**, so stdout stays clean for pipes. Colors are disabled automatically when stderr is not a terminal or when `NO_COLOR` is set, and box-drawing characters fall back to plain ASCII on consoles that cannot encode them.

---

## Selected control

**LOG-01: Audit log coverage, freshness and retention for PCI in-scope assets.**

For every asset with `pci_scope = yes`:

| Check | Rule (threshold from `controls.json`) | On failure |
|---|---|---|
| `coverage` | Asset appears in the SIEM export with valid evidence | `MISSING` |
| `freshness` | `as_of - last_event_at <= 24h` | `STALE` (`FAIL` if the timestamp is in the future) |
| `retention` | `retention_days >= 365` | `FAIL` |
| `hot_retention` | `hot_retention_days >= 90` | `FAIL` |

## Framework mapping

The mapping lives in `controls.json`, not in code, so the GRC team can review and version it.

| Requirement | Supported by | Why the check supports it | What it does **not** prove |
|---|---|---|---|
| PCI DSS v4.0.1 **10.2.1**: audit logs enabled and active for all system components | coverage | Presence in the SIEM shows the asset sends audit logs centrally | That every required event type is logged |
| PCI DSS v4.0.1 **10.7.2**: failures of critical security controls (incl. audit logging) detected and addressed promptly | freshness | A silent log source is a logging failure; the 24h window shows it would be detected within a day | That log content is complete, or that an alert/ticket was raised |
| PCI DSS v4.0.1 **10.5.1**: 12 months of audit log history, latest 3 months immediately available | retention, hot_retention | Configured retention is compared with the 12-month and 3-month minimums | That old logs are actually intact and restorable (needs a sampling test) |
| SOC 2 **CC7.2**: monitoring of system components for anomalies | coverage, freshness | Monitoring is only possible for components that send current logs | That detection rules exist or anomalies are reviewed |

## Status definitions

| Status | Meaning |
|---|---|
| `PASS` | All checks passed |
| `STALE` | Asset is logging, but no event within the freshness window |
| `FAIL` | Retention below minimum, or a future timestamp (evidence integrity issue) |
| `MISSING` | No trustworthy evidence the asset logs to the SIEM. Includes rows rejected as malformed |
| `EXCEPTION` | Asset would fail, but a valid, approved, non-expired risk acceptance covers it. **The original finding stays visible** as `underlying_status` |
| `NOT_EVALUATED` | Check-level only: could not run because coverage failed. Not counted as a pass or a failure |
| `UNTRACKED` | Host sends logs to the SIEM but is not in the inventory (inventory gap) |

**Precedence** when several checks fail: `MISSING > FAIL > STALE > PASS`. The final status is the worst one, and **every** failed check is still listed.

**Exceptions** apply only when `control_id` matches, `approved_by` is set and `approved_at <= as_of < expires_at`. An expired exception is ignored and reported as such.

## Evidence handling

- Every check records: evidence source file, value used, evidence timestamp, rule, threshold and `evaluated_at`.
- `--as-of` makes runs reproducible: the same inputs and the same as-of always give the same verdict.
- The **SHA-256** of every input file, including `controls.json`, is recorded in the report. If someone edits the data *or the rules* after the run, the hashes no longer match.
- Bad rows (malformed timestamp, missing field, naive timezone, negative days) are **rejected and reported**, never silently fixed. Rejected evidence never counts in the company's favour: an asset whose only SIEM row was rejected is `MISSING`.
- Timestamps in the future are flagged as an evidence integrity issue (often a broken NTP sync, itself a PCI DSS 10.6 concern).
- When a host has several SIEM sources, AX9 takes the newest event but the **lowest** retention: the weakest source is what an auditor can rely on.

## Outputs

| File | Audience | Content |
|---|---|---|
| `results.json` | Machines / integrations | Run metadata (as-of, input hashes, version), summary counts, per-asset findings with evidence and mapping |
| `results.csv` | GRC analysts (spreadsheets) | One row per asset per check, flat, ready for pivot tables |
| `report.md` | GRC manager | Executive summary, top risks, failures by requirement, missing/stale evidence, exceptions, untracked hosts, evidence quality, recommended actions |

`sample_output/` holds the committed result of `python -m ax9 --as-of 2026-10-01T09:00:00Z --out-dir sample_output`.

## Input formats

**`assets.csv`** (inventory, source of truth for scope)
`asset_id, hostname, environment, pci_scope (yes/no), owner, criticality`

**`siem_sources.csv`** (SIEM export)
`hostname, source_type, last_event_at (ISO 8601 with timezone, e.g. 2026-10-01T08:55:00Z), retention_days, hot_retention_days`

**`exceptions.csv`** (risk acceptances)
`asset_id, control_id, reason, approved_by, approved_at, expires_at`

Inventory and SIEM are joined on `hostname`, ignoring case and surrounding spaces.

The sample data deliberately contains one of each case: PASS, STALE, FAIL (retention), FAIL (hot retention), MISSING, valid exception, expired exception, an out-of-scope asset, an untracked host, a malformed row and a future timestamp.

## Customising

- **Change a threshold or a mapping:** edit `controls.json` (for example `"min_days": 180` for hot retention). No code change needed.
- **Add a new kind of check:** write a function in `ax9/engine.py`, register it in the `CHECKS` dictionary, then reference it in `controls.json`.

## Project layout

```
ax9/
  __main__.py   entrypoint (python -m ax9)
  cli.py        arguments, orchestration, exit codes
  ui.py         banner and [*]/[+]/[!]/[-] progress on stderr
  models.py     dataclasses: Asset, LogSource, RiskException, Finding...
  ingest.py     load + validate inputs, collect data quality issues, hashing
  engine.py     pure control evaluation: checks, precedence, exceptions
  reporters.py  JSON, CSV and Markdown writers
controls.json   thresholds, framework mapping, rationale, limitations
sample_data/    fabricated inputs covering every case
sample_output/  committed output of a fixed --as-of run
tests/          unittest suite
```

## Assumptions

- The **inventory is the source of truth** for what is in PCI scope.
- The **SIEM export is trustworthy** about what it reports (AX9 checks format and plausibility, not the SIEM itself).
- Hostnames are consistent between inventory and SIEM.
- All timestamps are UTC or carry an explicit offset.
- `retention_days` / `hot_retention_days` reflect the effective policy of the index or storage tier holding that source.

## Limitations

- Checks configuration and metadata, **not log content**: a fresh, retained log can still miss required event types (PCI 10.2.1.x).
- Configured retention is not proof that old logs are restorable.
- Joining on hostname can produce false MISSING/UNTRACKED results when naming differs (FQDN vs short name, renamed hosts).
- One snapshot in time: an asset that was silent for a week and recovered yesterday is PASS today.
- Evaluates one control (LOG-01). The engine is generic, but new checks need code.

## Production evolution

1. **API ingestion:** replace the file loaders in `ingest.py` with CMDB and SIEM API clients returning the same models (e.g. Splunk `| tstats latest(_time) by host`, Elastic aggregations, Wazuh agent API).
2. **Scheduling:** run daily via cron or CI; keep each run's JSON as dated evidence for the audit period.
3. **Ticketing:** open a ticket per MISSING/FAIL/STALE finding, assigned to the asset owner, with SLA by criticality; auto-close when a later run passes.
4. **Trend reporting:** compare runs to show compliance over time and mean time to remediate.
5. **Evidence signing:** sign `results.json` and store it in write-once storage so the evidence chain itself is tamper-evident.
6. **Exception workflow:** pull risk acceptances from the GRC platform and alert owners before expiry.
