# AX9 (Audit X9)

> **Audit X9 :: your logs can't hide.**
> In Brazilian slang an *"X9"* is a snitch. AX9 snitches on every payment system that is not logging the way an auditor expects.

AX9 is a small command-line tool that acts as an **automated auditor** for one security control: *are all the systems that handle card data sending audit logs to the SIEM, recently, and keeping them long enough?*

It reads three spreadsheets, applies the rules of the control, and produces an evidence-backed verdict for every system, ready for a GRC (Governance, Risk & Compliance) team.

```
python -m ax9 --as-of 2026-10-01T09:00:00Z
```

- Python 3.10+ and the standard library only: no `pip install`, no network, no credentials.
- 39 unit tests.
- Outputs for machines (JSON), analysts (CSV), managers (Markdown) and humans at a terminal (colored tables).

### Reviewer quick path

| Deliverable | Where |
|---|---|
| Run | `python -m ax9 --as-of 2026-10-01T09:00:00Z` |
| Tests | `python -m unittest discover -s tests -v` |
| Selected control | [§6 The control and its checks](#6-the-control-and-its-checks) |
| Framework mapping | [§8 Framework mapping](#8-framework-mapping) |
| Validation logic | [§6 Checks](#6-the-control-and-its-checks) and [§7 Statuses](#7-statuses) |
| Assumptions and limitations | [§17 Assumptions and limitations](#17-assumptions-and-limitations) |
| Sample input | [`sample_data/`](sample_data/) |
| Sample output | [`sample_output/report.md`](sample_output/report.md) (also `results.csv`, `results.json`) |

---

## Table of contents

1. [The problem, in plain words](#1-the-problem-in-plain-words)
2. [Download and run](#2-download-and-run)
3. [What you will see](#3-what-you-will-see)
4. [How it works](#4-how-it-works)
5. [The input files](#5-the-input-files)
6. [The control and its checks](#6-the-control-and-its-checks)
7. [Statuses](#7-statuses)
8. [Framework mapping](#8-framework-mapping)
9. [Evidence handling](#9-evidence-handling)
10. [The outputs](#10-the-outputs)
11. [Command-line reference](#11-command-line-reference)
12. [Hands-on tutorial](#12-hands-on-tutorial)
13. [Customising](#13-customising)
14. [Code tour](#14-code-tour)
15. [Tests](#15-tests)
16. [Security of the tool itself](#16-security-of-the-tool-itself)
17. [Assumptions and limitations](#17-assumptions-and-limitations)
18. [Taking it to production](#18-taking-it-to-production)

---

## 1. The problem, in plain words

A payments company must follow **PCI DSS**, the security standard for anyone handling card data. One of its rules says, in short: *every system that touches card data must record what happens on it (audit logs), those logs must reach a central place, and they must be kept for at least a year.* Without logs, nobody can investigate a fraud or a breach.

An auditor will ask: **"Prove it."** Saying "I think so" is not an answer. You need evidence.

To prove that *every* system is logging you need **two lists**, and you need to compare them:

| List | Question it answers | Party analogy |
|---|---|---|
| **Asset inventory** (`assets.csv`) | Which systems exist and **should** be sending logs? | The guest list |
| **SIEM export** (`siem_sources.csv`) | Which systems **are** sending logs? | Who actually came through the door |

Looking only at the SIEM, you would see who is logging but **never notice who should be and isn't**. A payment server that stopped logging simply vanishes from the SIEM, and that is the most dangerous case. Only the comparison reveals it:

- In the inventory **and** in the SIEM → check that logs are recent and retained long enough.
- In the inventory but **not** in the SIEM → **MISSING** (an invited guest who never arrived).
- In the SIEM but **not** in the inventory → **UNTRACKED** (a gatecrasher: a system nobody manages).

A third file, `exceptions.csv`, holds **risk acceptances**: cases where someone with authority formally said "we know this system fails, we accept the risk until a given date".

---

## 2. Download and run

### Requirements

- **Python 3.10 or newer.** Check with `python3 --version` (on Windows: `python --version`).
- Nothing else. AX9 uses only the Python standard library.

### Download

With git:

```bash
git clone https://github.com/aristoncandido/ax9.git
cd ax9
```

Without git: on the GitHub page click **Code → Download ZIP**, unzip it, and open a terminal inside the `ax9` folder.

### Run

```bash
python3 -m ax9 --as-of 2026-10-01T09:00:00Z
```

On Windows use `python` instead of `python3`.

What each part means:

| Part | Meaning |
|---|---|
| `python3 -m ax9` | "Python, run the `ax9` package" (the `ax9/` folder) |
| `--as-of 2026-10-01T09:00:00Z` | "Evaluate as if *now* were 1 October 2026, 09:00 UTC" |

**Why fix the date?** The sample data was written for that day. Without `--as-of`, AX9 uses the real current time, and a week later every sample log would look old. A fixed date gives the same result every time, which is exactly what an auditor wants: anyone can re-run the check and get the same verdict.

The reports are written to the `output/` folder.

### Run the tests

```bash
python3 -m unittest discover -s tests -v
```

Expected last line: `OK`.

---

## 3. What you will see

On a terminal, AX9 opens with an animated banner and a progress bar whose steps are the real stages of the run:

```
 █████╗ ██╗  ██╗ █████╗
 ...
  v1.0.0  Audit X9 :: your logs can't hide
  developed by Ariston Cândido

⠴ Parsing SIEM log sources             [██████████░░░░░░░░░░░░░░]  43%
```

Then the run header and the results:

```
[+] compliance scan complete
[*] control: LOG-01
[*] frameworks: PCI DSS v4.0.1, SOC 2
[*] as-of: 2026-10-01T09:00:00Z
[*] loaded 10 assets, 8 SIEM sources, 2 exceptions
[!] 1 input row(s) rejected as evidence quality issues

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
[!] 9 in-scope assets: PASS=1, EXCEPTION=1, STALE=2, FAIL=3, MISSING=2; compliance 11.1%; ...
[*] reports: output/report.md, results.csv, results.json
```

How to read the prefixes (Metasploit style):

| Prefix | Color | Meaning |
|---|---|---|
| `[*]` | blue | information |
| `[+]` | green | success |
| `[!]` | yellow | attention: something needs action |
| `[-]` | red | error: the run could not complete |

The findings table is sorted **worst first**, then by asset criticality, so the most urgent line is the first one you read. Long details are cut to fit the screen; the full text is always in the report files.

The progress bar takes about 1 second (plus the short banner) and only runs on an interactive terminal. In CI, in a pipe or with `--no-anim` it is skipped and the run takes a fraction of a second.

---

## 4. How it works

```
 assets.csv ─────────┐
 siem_sources.csv ───┼─► ingest.py ──► engine.py ──► reporters.py ──► output/results.json
 exceptions.csv ─────┤   read and       apply the      write the              results.csv
 controls.json ──────┘   validate       rules          reports                report.md
                         every row                                    + colored tables on the terminal
```

1. **Ingest** reads every file and validates every row. A bad row (invalid date, empty field) is **not** a crash: it is set aside as a *data quality issue* and reported. A bad file (missing, unreadable) stops the run with a clear error.
2. **Engine** joins inventory and SIEM by hostname, runs the checks on each in-scope asset, picks the worst result, and applies risk exceptions. It never reads files or the clock, so the same input always gives the same output.
3. **Reporters** turn the verdicts into outputs for each audience. They decide nothing; they only present.

---

## 5. The input files

All three are plain CSV files (Excel → *Save as* → *CSV UTF-8* works). The sample files in `sample_data/` are fabricated, and each row was planted to trigger one specific situation (see the tutorial).

### `assets.csv`: the inventory (what *should* log)

```csv
asset_id,hostname,environment,pci_scope,owner,criticality
A001,pay-gw-01,production,yes,payments-platform,critical
```

| Column | Meaning |
|---|---|
| `asset_id` | Unique id of the asset. Exceptions refer to it. |
| `hostname` | Name used to find the asset in the SIEM (case-insensitive). |
| `environment` | e.g. production, staging. Informational. |
| `pci_scope` | `yes` or `no`. Only `yes` assets are audited by LOG-01. |
| `owner` | Team accountable for fixing it. |
| `criticality` | `critical`, `high`, `medium` or `low`. Used to rank risks. |

### `siem_sources.csv`: the SIEM export (what *is* logging)

```csv
hostname,source_type,last_event_at,retention_days,hot_retention_days
pay-gw-01,linux_syslog,2026-10-01T08:55:00Z,400,90
```

| Column | Meaning |
|---|---|
| `hostname` | Host that sends logs. |
| `source_type` | Kind of log (syslog, database audit, firewall...). A host may appear on several rows. |
| `last_event_at` | When the last event arrived. **ISO 8601 with timezone**, e.g. `2026-10-01T08:55:00Z`. |
| `retention_days` | How many days the logs are kept in total. |
| `hot_retention_days` | How many days they stay immediately searchable (not only in archive). |

In a real SIEM this comes from a query such as Splunk `| tstats latest(_time) where index=* by host`, plus the retention settings of each index.

### `exceptions.csv`: risk acceptances

```csv
asset_id,control_id,reason,approved_by,approved_at,expires_at
A006,LOG-01,Legacy host cannot forward logs,ciso@example.com,2026-06-15T10:00:00Z,2027-03-31T23:59:59Z
```

An exception applies only if `control_id` matches, someone approved it, and the evaluation time is between `approved_at` and `expires_at`.

### What makes a row invalid

| Problem | Example | What AX9 does |
|---|---|---|
| Empty required field | `retention_days` blank | Row rejected, reported |
| Date not in ISO 8601 | `01/10/2026 08:30` | Row rejected, reported |
| Date without timezone | `2026-10-01T08:30:00` | Row rejected: an ambiguous time is not evidence |
| Not yes/no | `pci_scope = maybe` | Row rejected, reported |
| Negative or non-numeric days | `-5`, `abc` | Row rejected, reported |
| Duplicate hostname in inventory | two rows `pay-gw-01` | First kept, duplicate reported |
| Date in the future | event at 14:00 when as-of is 09:00 | Kept, check fails, flagged as integrity issue |

A rejected SIEM row **never counts in the company's favour**: if it was the only row for an asset, that asset is `MISSING`, with the reason shown.

---

## 6. The control and its checks

**LOG-01: Audit log coverage, freshness and retention for PCI in-scope assets.**

For every asset with `pci_scope = yes`, four checks run. Thresholds come from `controls.json`.

| Check | Question | Rule | If it fails |
|---|---|---|---|
| `coverage` | Is it in the SIEM at all? | valid SIEM row exists for the hostname | `MISSING` |
| `freshness` | Did it log recently? | `as_of - last_event_at <= 24h` | `STALE` (or `FAIL` if the date is in the future) |
| `retention` | Are logs kept a year? | `retention_days >= 365` | `FAIL` |
| `hot_retention` | Are the last 3 months searchable? | `hot_retention_days >= 90` | `FAIL` |

Why each check matters:

- **Coverage:** a system that doesn't send logs is invisible to the security team.
- **Freshness:** a system that *used to* log but went silent is broken (agent crashed, network rule changed) or someone switched logging off. Both must be noticed quickly.
- **Retention:** breaches are often found months later; without old logs there is nothing to investigate.
- **Hot retention:** archived logs may take days to restore; during an incident you need recent ones immediately.

If `coverage` fails, the other three become `NOT_EVALUATED`: there is no data to judge them, and that is different from passing.

---

## 7. Statuses

| Status | Meaning | Needs action? |
|---|---|---|
| `PASS` | All checks passed | no |
| `STALE` | Logging, but nothing within the freshness window | yes |
| `FAIL` | Retention below the minimum, or a timestamp in the future | yes |
| `MISSING` | No trustworthy evidence the asset logs to the SIEM | yes |
| `EXCEPTION` | Would fail, but a valid risk acceptance covers it | no (until it expires) |
| `UNTRACKED` | In the SIEM but not in the inventory | yes: inventory gap |
| `NOT_EVALUATED` | Check skipped because coverage failed (check-level only) | n/a |

**Precedence.** When several checks fail, the worst status wins: `MISSING > FAIL > STALE > PASS`. Every failed check is still listed, so nothing is hidden behind the top status.

**Exceptions never erase the problem.** An asset covered by a valid exception shows `EXCEPTION` as its status and keeps the real finding in `underlying_status`. An accepted risk is still a risk. An **expired** exception does not apply: the asset gets its original status and the expiry is reported.

---

## 8. Framework mapping

Stored in `controls.json` so the GRC team can review and change it without touching code. Each mapping states **why** the check supports the requirement and, just as important, **what it does not prove**.

| Requirement | Supported by | Why | Does **not** prove |
|---|---|---|---|
| PCI DSS v4.0.1 **10.2.1**: audit logs enabled and active for all system components | coverage | Presence in the SIEM shows the asset sends audit logs centrally | That every required event type is logged |
| PCI DSS v4.0.1 **10.7.2**: failures of critical security controls (incl. audit logging) detected and addressed promptly | freshness | A silent log source is a logging failure; a 24h window would detect it within a day | That log content is complete, or that an alert was raised |
| PCI DSS v4.0.1 **10.5.1**: 12 months of audit log history, latest 3 months immediately available | retention, hot_retention | Configured retention is compared with the 12-month and 3-month minimums | That old logs are intact and restorable |
| SOC 2 **CC7.2**: monitoring of system components for anomalies | coverage, freshness | Monitoring is only possible for components that send current logs | That detection rules exist or alerts are reviewed |

---

## 9. Evidence handling

What turns a script into an audit tool is the ability to answer "how do you know?".

| Feature | Why |
|---|---|
| **Every check records its evidence**: source file, value used, evidence timestamp, rule, threshold, evaluation time | Anyone can re-perform the check by hand and reach the same conclusion |
| **`--as-of`** fixes the evaluation time | The same inputs always give the same verdict: reproducible |
| **SHA-256 of every input**, `controls.json` included, is written in every report | Change one character in a file, or one threshold, and the fingerprint no longer matches the report |
| **Bad rows are rejected and reported**, never silently fixed | Untrustworthy data must not count as proof |
| **Future timestamps are flagged** | Usually a broken clock (NTP, itself a PCI DSS 10.6 issue) or edited evidence |
| **Several SIEM sources per host: newest event, lowest retention** | Conservative: the weakest source is what an auditor can rely on |

---

## 10. The outputs

| File | For | What's inside |
|---|---|---|
| `output/report.md` | GRC manager | Executive summary with compliance %, top risks, failures grouped by requirement, missing/stale evidence, exceptions (valid and expired), untracked hosts, evidence quality issues, recommended actions, input hashes |
| `output/results.csv` | GRC analyst | One row per asset per check, flat, ready for filters and pivot tables in Excel or Google Sheets |
| `output/results.json` | Machines | Run metadata (as-of, input hashes, version), summary counts, controls used, every finding with its evidence and mapping |
| terminal | Whoever ran it | Colored tables and compliance gauges (quick view) |

Two compliance figures are always shown: **PASS only** and **PASS + valid exceptions**. An accepted risk is not the same as compliance, and a manager must see both numbers.

`sample_output/` holds the committed result of
`python -m ax9 --as-of 2026-10-01T09:00:00Z --out-dir sample_output`, so you can read a report without running anything.

---

## 11. Command-line reference

```
python3 -m ax9 [options]
```

| Option | Default | What it does |
|---|---|---|
| `--data-dir DIR` | `sample_data` | Folder holding `assets.csv`, `siem_sources.csv` and `exceptions.csv` |
| `--assets FILE` | from `--data-dir` | Use this inventory file instead |
| `--siem FILE` | from `--data-dir` | Use this SIEM export instead (any file name) |
| `--exceptions FILE` | from `--data-dir` | Use this exceptions file instead |
| `--controls FILE` | `controls.json` | Rules: thresholds and framework mapping |
| `--as-of TIME` | now (UTC) | Evaluation time, ISO 8601, e.g. `2026-10-01T09:00:00Z` |
| `--out-dir DIR` | `output` | Where the three report files are written |
| `--no-banner` | off | Hide the logo |
| `--no-anim` | off | Skip the animation and progress bar |
| `--version` | | Print the version |
| `--help` | | Print this list |

Examples:

```bash
# Your own folder of exports
python3 -m ax9 --data-dir ~/audits/2026-10

# Just a fresh SIEM export, the rest from sample_data
python3 -m ax9 --siem ~/Downloads/splunk_sources_2026-10-01.csv

# In a CI pipeline: fails the job when action is required
python3 -m ax9 --data-dir exports/ --out-dir evidence/$(date +%F)
```

AX9 never asks questions while running. Everything is passed as options, so the same command works on a laptop, in cron or in CI.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Every in-scope asset is PASS or covered by a valid exception |
| `1` | The audit ran and something needs action (MISSING, FAIL, STALE, untracked host, expired exception, evidence quality issue) |
| `2` | The audit could not run (missing/unreadable file, invalid `--as-of`, malformed `controls.json`, output folder not writable) |

Keeping 1 and 2 apart lets a pipeline tell *"not compliant"* from *"the tool is broken"*. Check it with `echo $?` right after a run.

### Where the output goes

Banner, progress and tables are written to **stderr**; stdout stays empty, so the tool never pollutes a pipe. Colors and animation turn off automatically when stderr is not a terminal, and colors also turn off when the `NO_COLOR` environment variable is set. On consoles that cannot draw box characters, tables fall back to plain ASCII (`+---+`).

---

## 12. Hands-on tutorial

### 12.1 Understand the sample data

Each sample row was planted to produce one case:

| Asset | Situation simulated | Result |
|---|---|---|
| `pay-gw-01` | Healthy system | PASS |
| `pay-db-01` | Log agent stopped ~67h ago | STALE |
| `pay-api-01` | Index retention set to 180 days to save disk | FAIL (retention) |
| `card-vault-01` | Logs archived after 30 days | FAIL (hot retention) |
| `pay-batch-01` | New server never onboarded to the SIEM | MISSING |
| `legacy-settle-01` | Legacy host, risk accepted by the CISO until 2027 | EXCEPTION |
| `pay-recon-01` | "Temporary" exception that expired in August | STALE (exception ignored) |
| `hr-portal-01` | HR system, no card data | ignored (out of scope) |
| `shadow-pay-07` | Server running outside the inventory ("shadow IT") | UNTRACKED |
| `pay-tokenizer-01` | Date exported in Brazilian format `01/10/2026 08:30` | row rejected → MISSING |
| `pay-edge-01` | Clock wrong: event dated 5 October | FAIL + integrity issue |

### 12.2 Fix a system and watch the verdict change

Work on a **copy**, so the official sample stays intact:

```bash
cp -r sample_data ~/ax9_lab
```

Open `~/ax9_lab/siem_sources.csv` and change the `pay-db-01` line from
`2026-09-28T14:10:00Z` to `2026-10-01T08:00:00Z` (one hour before the as-of). Then:

```bash
python3 -m ax9 --data-dir ~/ax9_lab --as-of 2026-10-01T09:00:00Z
```

`STALE=2` becomes `STALE=1`, `PASS=1` becomes `PASS=2`, and compliance rises from 11.1% to 22.2%.

### 12.3 Try to cheat

Set the same line to `2026-10-01T14:10:00Z`, five hours **after** the as-of, and run again. `pay-db-01` becomes **FAIL**: *"last_event_at is in the future (evidence integrity issue)"*. Evidence that is "too good to be true" is caught.

### 12.4 Watch the fingerprint change

```bash
sha256sum sample_data/siem_sources.csv ~/ax9_lab/siem_sources.csv
```

One edited line, a completely different hash. That is how the report proves which exact file it used.

### 12.5 Change a rule, not the data

In a copy of `controls.json`, set `"min_days": 365` under `retention` to `180`, then:

```bash
python3 -m ax9 --controls my_controls.json --as-of 2026-10-01T09:00:00Z
```

`pay-api-01` now passes, and the `controls.json` hash in the report is different too: changing a rule is just as visible as changing data.

---

## 13. Customising

### Change a threshold or a mapping: edit `controls.json`

No code needed. For example, to require 180 days of hot retention:

```json
"hot_retention": { "description": "...", "min_days": 180 }
```

AX9 validates the file on load: an unknown check, a missing threshold or a mapping that points to a non-existent check stops the run with a clear message (exit code 2).

### Add a new kind of check: write code

`controls.json` holds the *parameters*; the *logic* of each check is a Python function. To add one (say, "event volume dropped by 90%"):

1. In `ax9/engine.py`, write a function with the same signature as `check_freshness` that returns a `CheckOutcome`.
2. Register it in the `CHECKS` dictionary.
3. Add its id and required parameters to `KNOWN_CHECKS` in `ax9/ingest.py`.
4. Reference it under `checks` and in a mapping's `supported_by` in `controls.json`.
5. Add a test for the passing case and one for the failing case.

### Use real exports

Export the inventory and the SIEM data to CSV with the column names from section 5 and point AX9 at them with `--data-dir` or `--assets/--siem/--exceptions`. File names don't matter when you use the individual flags.

---

## 14. Code tour

Read the files in this order. Each module starts with a docstring explaining its role and how to change it.

### `ax9/models.py`: the data structures

| Class | Represents |
|---|---|
| `Status` | The verdicts: PASS, STALE, FAIL, MISSING, EXCEPTION, NOT_EVALUATED |
| `Asset`, `LogSource`, `RiskException` | One row of each input file, already validated |
| `DataQualityIssue` | A rejected row or suspicious value, with file, line and reason |
| `Evidence` | What was looked at, which value, which rule and threshold, when |
| `CheckResult` | Result of one check on one asset |
| `AssetFinding` | Final verdict for one asset (status, underlying status, all checks, exception) |
| `RunResult` | Everything from one run; the only thing reporters read |

All are frozen dataclasses: once created they cannot be changed, as audit evidence should be.

### `ax9/ingest.py`: reading the files

| Function | What it does |
|---|---|
| `load_assets`, `load_siem_sources`, `load_exceptions` | Read one CSV, return `(valid_records, data_quality_issues)` |
| `load_controls` | Read and validate `controls.json` |
| `parse_timestamp` | ISO 8601 → UTC datetime; rejects dates without a timezone |
| `normalize_hostname` | The join key: lowercase, no surrounding spaces |
| `sha256_file` | Fingerprint of a file for the evidence trail |
| `_load` | Shared row loop: empty-field check, conversion, issue capture |

### `ax9/engine.py`: the rules

| Function | What it does |
|---|---|
| `evaluate` | Entry point: joins inventory and SIEM, evaluates every in-scope asset, finds untracked hosts |
| `evaluate_asset` | Runs every check on one asset, combines them, applies exceptions |
| `check_coverage`, `check_freshness`, `_check_min_days` | The checks themselves |
| `CHECKS` | Registry linking check ids in `controls.json` to these functions |
| `resolve_status` | Worst status wins, following `status_precedence` |
| `classify_exception` | Decides whether an exception is valid, expired or not yet effective |
| `merge_sources` | Combines several SIEM rows of one host conservatively |
| `needs_action` | Decides exit code 1 vs 0 |

### `ax9/reporters.py`: the outputs

| Function | What it does |
|---|---|
| `summarize` | Counts per status and the two compliance percentages |
| `write_json`, `write_csv`, `write_markdown` | The three report files |
| `write_console` | The colored tables on the terminal |
| `_csv_safe` | Protects the CSV against formula injection |

### `ax9/ui.py`: the terminal

| Item | What it does |
|---|---|
| `UI.banner` | Logo, tagline and credit (animated on a terminal) |
| `UI.info / success / warning / error` | The `[*] [+] [!] [-]` lines |
| `UI.table`, `UI.bar` | Bordered tables and compliance gauges |
| `Progress` | The animated step-by-step progress bar |
| `sanitize` | Strips control characters from untrusted text before printing |

### `ax9/cli.py`: putting it together

`build_parser` defines the options; `main` runs the sequence (read → evaluate → write → show) and returns the exit code.

---

## 15. Tests

```bash
python3 -m unittest discover -s tests -v
```

39 tests in `tests/test_engine.py`, grouped by what they protect:

| Group | Guarantees |
|---|---|
| `StatusTests` | Each status appears in the right situation, including the exact 24h boundary |
| `PrecedenceTests` | The worst status wins and every failed check is still listed |
| `ExceptionTests` | Valid, expired, future and wrong-control exceptions behave correctly |
| `ScopeAndInventoryTests` | Out-of-scope assets ignored, untracked hosts found, hostname matching, source merging |
| `EvidenceQualityTests` | Malformed rows rejected without crashing; evidence fields recorded |
| `ExitCodeTests` | End-to-end runs return 0, 1 or 2 as a CI pipeline expects |
| `ConsoleTableTests` | Tables stay aligned with colors, no colors outside a terminal, ASCII fallback |
| `ControlsValidationTests` | Mistakes in `controls.json` produce clear errors |
| `InputRobustnessTests` | Directories, non-UTF-8 files and other bad inputs end in exit 2, not a traceback |
| `TimestampMessageTests` | Bad or timezone-less dates get a clear "expected ISO 8601 with timezone" message |
| `OutputSafetyTests` | CSV formula injection and terminal escape injection are neutralised |

**Testing the tests:** a test that has never failed proves little. Break a rule on purpose (for example change `>` to `>=` in `check_freshness`), run the suite, confirm a test goes red, then undo the change.

---

## 16. Security of the tool itself

A security tool must not become an attack path. Input files are treated as untrusted:

- **CSV formula injection (CWE-1236).** A hostname like `=HYPERLINK("http://evil","x")` would run as a formula when `results.csv` is opened in Excel. Values starting with `= + - @` are prefixed with `'` so they stay text.
- **Terminal escape injection.** Control characters in input values are replaced before printing, so a crafted hostname cannot clear the screen or forge table lines.
- **No network, no credentials, no third-party packages.** Nothing to leak and no supply chain to trust.
- **Read-only on inputs.** AX9 never modifies the files it audits; it only writes to `--out-dir`.

---

## 17. Assumptions and limitations

### Assumptions

- The **inventory is the source of truth** for what is in PCI scope.
- The **SIEM export is trustworthy** about what it reports. AX9 checks format and plausibility, not the SIEM itself.
- Hostnames are written the same way in the inventory and the SIEM.
- Timestamps are UTC or carry an explicit offset.
- `retention_days` and `hot_retention_days` reflect the effective policy of the index that stores each source.

### Limitations

- AX9 checks **configuration and metadata, not log content**. A fresh, retained log can still miss required event types (PCI DSS 10.2.1.x).
- Configured retention is not proof that old logs can actually be restored; that needs a sampling test.
- Joining on hostname can produce false MISSING/UNTRACKED results when names differ (FQDN vs short name, renamed hosts).
- One point in time: an asset that was silent for a week and recovered yesterday is PASS today.
- One control (LOG-01). The engine is generic, but new kinds of checks need code.

---

## 18. Taking it to production

In production the files would be replaced by live sources. The design already allows it: only `ingest.py` would change.

1. **API ingestion:** replace the CSV loaders with CMDB and SIEM API clients (Splunk `tstats`, Elastic aggregations, Wazuh agent API) that return the same models.
2. **Scheduling:** run daily from cron or CI, keeping each run's `results.json` as dated evidence for the audit period.
3. **Ticketing:** open one ticket per MISSING/FAIL/STALE finding for the asset owner, with an SLA by criticality; close it automatically when a later run passes.
4. **Trends:** compare runs to show compliance over time and mean time to remediate.
5. **Signed evidence:** sign `results.json` and store it in write-once storage, so the evidence chain itself is tamper-evident.
6. **Exception workflow:** pull risk acceptances from the GRC platform and warn owners before they expire.

---

Developed by **Ariston Cândido**.
