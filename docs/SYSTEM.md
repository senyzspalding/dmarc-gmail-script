# DMARC Monitor – System Document

| | |
|---|---|
| **System** | DMARC Monitor for `example.org` |
| **Platform** | Google Apps Script (V8 runtime), Google Workspace |
| **Runs as** | `dmarc-bot@example.org` |
| **Owner / alerts to** | `alerts@example.org` |
| **Source** | `src/` in this repository |

For setup steps see `README.md`. This document describes how the system is built,
how it behaves, and how to operate and change it.

---

## 1. Purpose

`example.org` publishes a DMARC record of `p=reject; sp=reject; pct=100`. Receiving
mail systems (Google, Microsoft, Yahoo, …) send daily **aggregate reports** (RFC 7489)
to the `rua=` address, which is the `emailadmin@example.org` Google Group.

With `p=reject`, any legitimate sender that is misconfigured has its mail silently
rejected. Nobody reads the raw XML reports, so this system:

- collects and parses every aggregate report automatically,
- keeps a searchable history in a Google Sheet,
- works out which sending sources are authorized (via SPF) and which are not,
- emails an alert when legitimate mail is failing, when spoofing spikes, when the
  published policy changes, when reports stop arriving, or when a new service starts
  sending as the domain,
- sends a weekly summary.

Out of scope: forensic (`ruf`) reports, changing DNS, and blocking mail. The system only observes.

## 2. Architecture

```
 Receivers (Google, Microsoft, ...)
        │  daily aggregate report (.zip / .gz / .xml)
        ▼
 emailadmin@example.org  (Google Group, rua= target)
        │  delivered "Each email"
        ▼
 dmarc-bot@example.org  Gmail
        │  Gmail filter → label "DMARC", skip inbox, never spam
        ▼
 Apps Script project "DMARC Monitor" (runs as dmarc-bot)
   ├─ processReports  (hourly)   ──► dns.google (TXT/A/AAAA/MX/PTR over HTTPS)
   ├─ checkStale      (daily 7am)
   └─ weeklyDigest    (Mon 8am)
        │                         │
        ▼                         ▼
 Google Sheet                 Gmail send → alertRecipients
 "DMARC Reports - example.org"
```

All data stays inside Google Workspace. The only external calls are DNS queries to
`https://dns.google/resolve`.

### 2.1 Components

| File | Responsibility |
|---|---|
| `src/Config.example.gs` | Template for `src/Config.gs` (git-ignored): all settings and thresholds (`CONFIG`). |
| `src/Main.gs` | Entry points: `setup`, `processReports`, `checkStale`, `weeklyDigest`; record enrichment. |
| `src/Parse.gs` | Extracts XML from zip/gzip/plain attachments; parses reports into plain objects. |
| `src/Dns.gs` | DNS-over-HTTPS, SPF expansion, CIDR matching, reverse DNS, source-org grouping. |
| `src/Store.gs` | Spreadsheet tabs, reading/writing rows, caches, the Sources list. |
| `src/Alerts.gs` | Alert rules (`evaluateRun_`), suppression, email formatting and sending. |
| `src/appsscript.json` | Manifest: time zone `America/New_York`, V8 runtime, Stackdriver logging. |
| `gmail-filter.example.xml` | Template for the Gmail filter imported into dmarc-bot's mailbox. |

Apps Script loads every `.gs` file into one global scope, so files call each other's
functions directly. Functions ending in `_` are private (not runnable from the editor
or as triggers).

### 2.2 Google services and permissions

| Service | Used for |
|---|---|
| `GmailApp` | Search/label threads, read attachments, send alerts |
| `SpreadsheetApp` | Data storage |
| `UrlFetchApp` | DNS-over-HTTPS queries |
| `PropertiesService` (script) | Spreadsheet ID, setup time, last report time, alert suppression |
| `CacheService` (script) | Expanded SPF networks, 6 hours |
| `LockService` | Prevents overlapping `processReports` runs |
| `ScriptApp` | Creating triggers |
| `Utilities`, `XmlService` | Unzip/ungzip, XML parsing |

## 3. Processing flow

### 3.1 `processReports()` — hourly

1. Take the script lock (give up if another run holds it for 5 s).
2. Load state: stored report keys, PTR cache, Sources list, authorized SPF networks.
3. Gmail search: `label:DMARC -label:DMARC-processed -label:DMARC-error -label:DMARC-unparsed`,
   up to `maxThreadsPerRun` (40) threads.
4. For each message, `extractReportXml_` detects the attachment type by magic bytes
   (`PK` = zip, `1F 8B` = gzip, else plain text) and keeps documents containing `<feedback>`.
5. `parseReportXml_` turns each document into a report object (namespaces ignored, so
   DMARCbis-style reports also parse).
6. Duplicate reports (key = `org_name|report_id`) are skipped.
7. `enrichRecord_` adds to every record:
   - `ptr`: reverse-DNS name (cached; at most 150 new lookups per run),
   - `via`: the SPF include that authorizes the IP (or a matching `extraKnownPtrSuffixes` entry),
   - `org`: the grouping key (base domain of the PTR, else the include name, else `/24` or `/48`),
   - `known`: authorized via SPF, or marked `approved` in the Sources sheet.
8. The thread is labeled `DMARC/processed`, `DMARC/error` (exception while parsing) or
   `DMARC/unparsed` (no aggregate report found), and marked read.
9. Rows are written to `Reports`, `Records` and `PtrCache`.
10. `evaluateRun_` produces findings, using the Sources list **as it was before this run**
    (so a new sender is recognized as new).
11. `updateSources_` merges this run's records into Sources, then `saveSources_` writes it.
12. `sendFindings_` drops anything alerted within 24 h and emails the rest.

The loop stops after `maxRunMillis` (4.5 min, below Apps Script's 6 min limit); remaining
threads are picked up next hour.

### 3.2 `checkStale()` — daily 7am

Sends a WARNING if no new report has been stored for `staleDays` (3) days.

### 3.3 `weeklyDigest()` — Monday 8am

Reads the last 7 days of `Records` and emails the overall pass rate, report count,
the number of report emails that failed to parse, and the top 30 sources.

### 3.4 `setup()` — manual

Creates labels, the spreadsheet and tabs, (re)creates the three triggers, and records
`SETUP_AT` / `LAST_REPORT_AT`. Safe to re-run; it never deletes data.

## 4. How authorization is determined

`getAuthorizedNets_` reads the live SPF record for `example.org` and recursively expands
`include:`, `redirect=`, `a`, `mx`, `ip4` and `ip6`, producing a list of CIDRs, each tagged
with the top-level include it came from (e.g. `mailgun.org`, `_spf.google.com`). Limits:

- only `+` (pass) mechanisms count; `-all`, `~all`, `?` are ignored,
- macros, `exists:` and `ptr` are not supported,
- at most 25 DNS lookups per expansion,
- result cached for 6 hours, so SPF changes take up to 6 hours to be picked up.

A source is **known** if its IP is in one of these networks, its PTR ends with an
`extraKnownPtrSuffixes` entry, or its Sources row has `status = approved`.

**DMARC pass** is taken from the reporter's `policy_evaluated`: pass if aligned DKIM or
aligned SPF passed.

## 5. Alert rules

Defined in `evaluateRun_` (`src/Alerts.gs`). Thresholds come from `CONFIG.thresholds`.
Only reports whose period ended in the last 10 days (`alertMaxReportAgeDays`) are evaluated.

| Severity | Key | Condition |
|---|---|---|
| CRITICAL | `knownfail:<org>` | Known source, ≥ `knownFailAlertMin` (3) failed messages |
| WARNING | `unknownfail:<org>` | Unknown source, ≥ `unknownFailAlertMin` (25) failed messages |
| WARNING | `failrate` | Run covers ≥ 100 messages and ≥ 10 % failed |
| WARNING | `policy:<diff>` | A report for `example.org` shows `p`, `sp` or `pct` different from `expectedPolicy` |
| WARNING | `stale` | No new reports for 3 days (`checkStale`) |
| NOTICE | `newsender:<org>` | Org not in Sources and some of its mail passed DMARC; not sent during the first 7 days (`learningDays`) |

Sources with `status = ignore` never produce per-source alerts. Each key is sent at most
once per `suppressHours` (24); the last send time is stored as script property `alert:<key>`.
All findings in one run go out as a single email whose subject carries the highest severity.

## 6. Data model (Google Sheet)

| Tab | One row per | Columns |
|---|---|---|
| `Reports` | aggregate report | report_key, org_name, report_id, begin, end, domain, p, sp, pct, adkim, aspf, records, messages, failed, processed_at |
| `Records` | report record (source IP + result) | report_key, reporter, begin, end, source_ip, ptr, source_org, authorized_via, count, disposition, dmarc, dkim_aligned, spf_aligned, header_from, envelope_from, dkim_auth, spf_auth, reasons |
| `Sources` | sending organization | source_org, first_seen, last_seen, messages, failed, authorized_via, last_ip, **status**, **notes** |
| `PtrCache` | IP looked up | ip, ptr, looked_up |
| `Alerts` | alert sent | sent_at, severity, key, title |

In `Sources`, the script writes only columns A–G. `status` (`approved` / `ignore` / blank)
and `notes` are for people and are never overwritten.

### Script properties

| Property | Meaning |
|---|---|
| `SPREADSHEET_ID` | Spreadsheet created by `setup()` |
| `SETUP_AT` | First setup time (ms); starts the learning period |
| `LAST_REPORT_AT` | Last time a new report was stored (ms); used by `checkStale` |
| `alert:<key>` | Last time that alert was sent (ms) |

## 7. Configuration

All in `src/Config.gs` (copied from `src/Config.example.gs`, not committed):

| Setting | Default | Notes |
|---|---|---|
| `domain` | `example.org` | Domain monitored and whose SPF is expanded |
| `rootLabel` etc. | `DMARC`, `DMARC/processed`, `DMARC/error`, `DMARC/unparsed` | Must match the Gmail filter |
| `spreadsheetId` | `''` | Leave blank; `setup()` stores the ID |
| `alertRecipients` | `['alerts@example.org']` | `setup()` refuses a `CHANGE_ME` value |
| `expectedPolicy` | `p=reject, sp=reject, pct=100` | |
| `extraKnownPtrSuffixes` | `[]` | Extra senders treated as authorized by PTR suffix |
| `thresholds.*` | see §5 | |
| `resolvePtr` / `maxPtrLookupsPerRun` | `true` / `150` | |
| `maxThreadsPerRun` / `maxRunMillis` | `40` / 4.5 min | |

## 8. Operations

### Routine
- Read alert emails and the Monday summary.
- After new senders appear, set `status` in the `Sources` tab: `approved` for real
  services, `ignore` for forwarders/mailing lists that always break DKIM.

### Health checks
| Check | Where |
|---|---|
| Reports arriving | dmarc-bot Gmail: `list:emailadmin.example.org` |
| Filter working | `label:DMARC` |
| Processing | `label:DMARC/processed`; `Reports`/`Records` tabs growing |
| Parse failures | `label:DMARC/error` + Apps Script → Executions |
| Triggers present | Apps Script → Triggers: `processReports` hourly, `checkStale` daily 7am, `weeklyDigest` Mon 8am |

### Troubleshooting
| Symptom | Likely cause / action |
|---|---|
| "No DMARC reports received" alert | dmarc-bot removed from group, subscription not *Each email*, filter missing, or `rua=` changed |
| Threads under `DMARC/error` | Malformed report. See the failed execution's log. Remove the label to retry after a fix |
| CRITICAL for Google/Microsoft | May be another tenant spoofing you on shared infrastructure. Check `header_from` and auth results |
| CRITICAL for Mailgun or similar | DKIM not signing `d=example.org`; `aspf=s` means SPF on a different bounce domain does not align |
| Run timed out | Backlog; runs resume automatically. Lower `maxThreadsPerRun` if it recurs |

### Changing the code
1. Edit files in `src/` and commit.
2. Paste into the Apps Script editor, or `clasp push` (with `--rootDir src`).
3. Re-run `setup()` only if labels, sheets or triggers changed. It is safe to re-run.

## 9. Security and privacy

- dmarc-bot is a dedicated account with 2-step verification and only Gmail, Sheets and
  Apps Script in use.
- Report data (source IPs, sending domains) is stored only in the spreadsheet, shared
  with nobody by default.
- Outbound calls: DNS names and IPs to `dns.google`; nothing else.
- Alert email content is HTML-escaped (`esc_`).
- No secrets are stored in the code. The spreadsheet ID lives in script properties.

## 10. Limits and known constraints

- History starts when dmarc-bot joined the group.
- Apps Script quotas: 6 min per execution, URL fetch and Gmail daily limits. 150 PTR
  lookups per run keeps well inside them.
- Sheets limit is 10 M cells; at ~18 cells per record this is years of data. Archive
  old `Records` rows if needed.
- SPF expansion does not support macros, `exists:` or `ptr`; such senders show as unknown
  unless approved in Sources.
- `sourceOrg_` uses a small built-in list of two-part TLDs, not the full public suffix list.
- Weekly digest and the Sources list are only as complete as the reports received.

## 11. Function reference

| Function | File | Purpose |
|---|---|---|
| `setup()` | Main | One-time / idempotent install |
| `processReports()` | Main | Hourly pipeline |
| `checkStale()` | Main | Daily no-reports check |
| `weeklyDigest()` | Main | Monday summary |
| `enrichRecord_` | Main | Adds ptr / via / org / known |
| `labelQuery_` | Main | Label name → Gmail search form |
| `extractReportXml_` | Parse | Attachments → XML strings |
| `parseReportXml_` | Parse | XML → report object |
| `reportKey_` | Parse | De-duplication key |
| `dohQuery_` | Dns | DNS-over-HTTPS query |
| `getAuthorizedNets_` / `expandSpf_` | Dns | SPF → list of CIDRs |
| `findAuthorizedVia_` / `ipInCidr_` / `ipToBytes_` | Dns | IP matching (IPv4 + IPv6) |
| `lookupPtr_` / `reverseName_` | Dns | Reverse DNS |
| `sourceOrg_` | Dns | Groups IPs into organizations |
| `evaluateRun_` | Alerts | Alert rules (pure, testable) |
| `updateSources_` | Alerts | Merges run into Sources |
| `sendFindings_` | Alerts | Suppression + email |
| `getSpreadsheet_` / `initSheets_` | Store | Spreadsheet setup |
| `loadSources_` / `saveSources_` | Store | Sources tab |
| `loadPtrCache_` / `savePtrCache_` | Store | PTR cache |
| `reportRow_` / `recordRow_` | Store | Row builders |
