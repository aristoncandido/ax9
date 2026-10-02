# AX9 Audit Report: Audit log compliance

- **Evaluated at (as-of):** 2026-10-01T09:00:00Z
- **Tool version:** 1.0.0
- **Verdict:** ACTION REQUIRED

## 1. Executive summary

- **Compliance:** 11.1% of in-scope assets fully PASS (22.2% counting accepted-risk exceptions).
- **In-scope assets:** 9 (out of scope and ignored: 1)
- **Untracked hosts (inventory gap):** 1
- **Expired exceptions:** 1
- **Evidence quality issues:** 2

| Status | Assets |
|---|---|
| PASS | 1 |
| EXCEPTION | 1 |
| STALE | 2 |
| FAIL | 3 |
| MISSING | 2 |

### Top risks (by asset criticality, then severity)

| Asset | Criticality | Status | Failed checks | Owner |
|---|---|---|---|---|
| pay-tokenizer-01 | critical | MISSING | coverage | security-eng |
| card-vault-01 | critical | FAIL | hot_retention | security-eng |
| pay-db-01 | critical | STALE | freshness | dba-team |
| pay-batch-01 | high | MISSING | coverage | payments-platform |
| pay-api-01 | high | FAIL | retention | payments-platform |

## 2. Failures grouped by framework requirement

### PCI DSS v4.0.1 10.2.1

_Audit logs are enabled and active for all system components._

- **Supported by checks:** coverage
- **Why:** An asset present in the SIEM proves that it is sending audit logs to the central platform.
- **Does NOT prove:** Presence in the SIEM does not prove that every required event type is being logged.

| Asset | Check | Check status | Detail | Final asset status |
|---|---|---|---|---|
| pay-batch-01 | coverage | MISSING | asset not found in SIEM sources | MISSING |
| legacy-settle-01 | coverage | MISSING | asset not found in SIEM sources | EXCEPTION |
| pay-tokenizer-01 | coverage | MISSING | SIEM row rejected as untrustworthy evidence: last_event_at='01/10/2026 08:30' (invalid value: Invalid isoformat string: '01/10/2026 08:30') | MISSING |

### PCI DSS v4.0.1 10.7.2

_Failures of critical security control systems, including audit logging, are detected and addressed promptly._

- **Supported by checks:** freshness
- **Why:** A log source that has gone silent is a logging failure; the freshness window shows whether it would be detected within a day.
- **Does NOT prove:** A fresh timestamp does not prove log content is complete, and this check does not prove an alert or ticket was raised.

| Asset | Check | Check status | Detail | Final asset status |
|---|---|---|---|---|
| pay-db-01 | freshness | STALE | no events for 66.8h | STALE |
| pay-recon-01 | freshness | STALE | no events for 55.0h | STALE |
| pay-edge-01 | freshness | FAIL | last_event_at is in the future (evidence integrity issue) | FAIL |

### PCI DSS v4.0.1 10.5.1

_Audit log history is retained for at least 12 months, with the most recent 3 months immediately available._

- **Supported by checks:** retention, hot_retention
- **Why:** The SIEM-reported retention values are compared with the 12-month and 3-month minimums.
- **Does NOT prove:** Configured retention is not proof that old logs are actually intact and restorable; that needs a sampling test.

| Asset | Check | Check status | Detail | Final asset status |
|---|---|---|---|---|
| pay-api-01 | retention | FAIL | retention_days is 180d, minimum is 365d | FAIL |
| card-vault-01 | hot_retention | FAIL | hot_retention_days is 30d, minimum is 90d | FAIL |

### SOC 2 CC7.2

_System components are monitored for anomalies indicative of malicious acts or errors._

- **Supported by checks:** coverage, freshness
- **Why:** Monitoring is only possible for components that send logs, and only meaningful if the logs are current.
- **Does NOT prove:** Does not prove that detection rules exist or that anomalies are actually reviewed.

| Asset | Check | Check status | Detail | Final asset status |
|---|---|---|---|---|
| pay-db-01 | freshness | STALE | no events for 66.8h | STALE |
| pay-batch-01 | coverage | MISSING | asset not found in SIEM sources | MISSING |
| legacy-settle-01 | coverage | MISSING | asset not found in SIEM sources | EXCEPTION |
| pay-recon-01 | freshness | STALE | no events for 55.0h | STALE |
| pay-tokenizer-01 | coverage | MISSING | SIEM row rejected as untrustworthy evidence: last_event_at='01/10/2026 08:30' (invalid value: Invalid isoformat string: '01/10/2026 08:30') | MISSING |
| pay-edge-01 | freshness | FAIL | last_event_at is in the future (evidence integrity issue) | FAIL |

## 3. Missing and stale evidence

| Asset | Status | Detail |
|---|---|---|
| pay-db-01 | STALE | no events for 66.8h |
| pay-batch-01 | MISSING | asset not found in SIEM sources |
| legacy-settle-01 | EXCEPTION (MISSING) | asset not found in SIEM sources |
| pay-recon-01 | STALE | no events for 55.0h |
| pay-tokenizer-01 | MISSING | SIEM row rejected as untrustworthy evidence: last_event_at='01/10/2026 08:30' (invalid value: Invalid isoformat string: '01/10/2026 08:30') |

## 4. Exceptions (risk acceptances)

| Asset | State | Underlying finding | Approved by | Expires | Reason |
|---|---|---|---|---|---|
| legacy-settle-01 | VALID | MISSING | ciso@example.com | 2027-03-31T23:59:59Z | Legacy settlement host cannot forward logs until platform migration |
| pay-recon-01 | EXPIRED | STALE | ciso@example.com | 2026-08-31T23:59:59Z | Reconciliation host log forwarder under replacement |

An EXPIRED exception does not apply: the asset is reported with its original finding.

## 5. Untracked hosts (in SIEM, not in inventory)

| Hostname | Source type | Last event |
|---|---|---|
| shadow-pay-07 | linux_syslog | 2026-10-01T08:45:00Z |

## 6. Evidence quality issues

| File | Row | Record | Field | Value | Problem |
|---|---|---|---|---|---|
| siem_sources.csv | 8 | pay-tokenizer-01 | last_event_at | 01/10/2026 08:30 | invalid value: Invalid isoformat string: '01/10/2026 08:30' |
| siem_sources.csv | n/a | pay-edge-01 | last_event_at | 2026-10-05T12:00:00Z | timestamp is in the future (evidence integrity) |

## 7. Recommended actions

1. Onboard the asset to the SIEM (or fix the rejected/missing source) and confirm events arrive; open a ticket for the asset owner.
2. Correct retention settings (>= 365d total, >= 90d hot) or investigate the integrity of the reported timestamp.
3. Check the log forwarder/agent on the asset; a silent source is a logging failure (PCI 10.7.2) and must be addressed promptly.
4. Renew or retire expired exceptions; until then the original finding stands.
5. Add untracked hosts to the inventory (and scope them) or decommission them.
6. Fix the rejected/suspect rows at the source system and re-run; rejected evidence is never counted as proof.

## 8. Evidence integrity (SHA-256 of inputs)

| File | SHA-256 |
|---|---|
| assets.csv | `a7d403e14f1de3953cbf544883ce6aa718ee9f96e7069c8ad28a7c9e79ee1686` |
| controls.json | `8ff5f7936464298e7c696d0a2677b0e5ded9ef543a0d33d7ccf7d4d7899a424d` |
| exceptions.csv | `1d9d3afffb7b815d4603610f5af59341d7886f070ee0f7504e79b8377900fa54` |
| siem_sources.csv | `657295284191d3b03cdd6e4e299fa4beefdf69d40bb047dc467ec3e279c84a93` |

