/**
 * Google Sheet storage. Tabs:
 *   Reports  - one row per aggregate report
 *   Records  - one row per report record (source IP + result)
 *   Sources  - one row per sending organization; `status` is yours to edit
 *   PtrCache - reverse-DNS lookups
 *   Alerts   - every alert sent
 */

// Header row of each tab. Row builders below must produce columns in this order.
const SHEETS_ = {
  Reports: ['report_key', 'org_name', 'report_id', 'begin', 'end', 'domain', 'p', 'sp', 'pct', 'adkim', 'aspf',
    'records', 'messages', 'failed', 'processed_at'],
  Records: ['report_key', 'reporter', 'begin', 'end', 'source_ip', 'ptr', 'source_org', 'authorized_via', 'count',
    'disposition', 'dmarc', 'dkim_aligned', 'spf_aligned', 'header_from', 'envelope_from', 'dkim_auth', 'spf_auth', 'reasons'],
  Sources: ['source_org', 'first_seen', 'last_seen', 'messages', 'failed', 'authorized_via', 'last_ip', 'status', 'notes'],
  PtrCache: ['ip', 'ptr', 'looked_up'],
  Alerts: ['sent_at', 'severity', 'key', 'title'],
};

// Columns of Sources the script writes; `status` and `notes` belong to people.
const SOURCES_SCRIPT_COLS_ = 7;

/**
 * Opens the results spreadsheet: CONFIG.spreadsheetId if set, else the ID saved in
 * Script Properties, else creates a new one and saves its ID.
 */
function getSpreadsheet_() {
  const props = PropertiesService.getScriptProperties();
  const id = CONFIG.spreadsheetId || props.getProperty('SPREADSHEET_ID');
  if (id) return SpreadsheetApp.openById(id);
  const ss = SpreadsheetApp.create('DMARC Reports - ' + CONFIG.domain);
  props.setProperty('SPREADSHEET_ID', ss.getId());
  return ss;
}

/** Creates any missing tabs with bold, frozen header rows and removes the empty default Sheet1. */
function initSheets_(ss) {
  Object.keys(SHEETS_).forEach(function (name) {
    let sh = ss.getSheetByName(name);
    if (!sh) sh = ss.insertSheet(name);
    if (sh.getLastRow() === 0) {
      sh.appendRow(SHEETS_[name]);
      sh.setFrozenRows(1);
      sh.getRange(1, 1, 1, SHEETS_[name].length).setFontWeight('bold');
    }
  });
  const blank = ss.getSheetByName('Sheet1');
  if (blank && ss.getSheets().length > 1 && blank.getLastRow() === 0) ss.deleteSheet(blank);
}

/** Tab by name; throws if missing so a half-set-up project fails loudly. */
function sheet_(ss, name) {
  const sh = ss.getSheetByName(name);
  if (!sh) throw new Error('Missing sheet "' + name + '" - run setup()');
  return sh;
}

/** All data rows (no header) of a sheet. */
function readRows_(ss, name) {
  const sh = sheet_(ss, name);
  const last = sh.getLastRow();
  if (last < 2) return [];
  return sh.getRange(2, 1, last - 1, sh.getLastColumn()).getValues();
}

/** Appends rows below the last used row in one write. No-op for an empty list. */
function appendRows_(ss, name, rows) {
  if (!rows.length) return;
  const sh = sheet_(ss, name);
  sh.getRange(sh.getLastRow() + 1, 1, rows.length, rows[0].length).setValues(rows);
}

/** Set of report_key values already stored, for de-duplication. */
function loadReportKeys_(ss) {
  const keys = new Set();
  readRows_(ss, 'Reports').forEach(function (r) { keys.add(String(r[0])); });
  return keys;
}

/** PtrCache tab -> {ip: {ptr, isNew: false}}. Empty ptr means "looked up, none found". */
function loadPtrCache_(ss) {
  const cache = {};
  readRows_(ss, 'PtrCache').forEach(function (r) { cache[String(r[0])] = { ptr: String(r[1]), isNew: false }; });
  return cache;
}

/** Appends only the lookups made this run (isNew). */
function savePtrCache_(ss, cache) {
  const now = new Date();
  const rows = Object.keys(cache).filter(function (ip) { return cache[ip].isNew; })
    .map(function (ip) { return [ip, cache[ip].ptr, now]; });
  appendRows_(ss, 'PtrCache', rows);
}

/** Map of source_org -> {row, firstSeen, lastSeen, messages, failed, via, lastIp, status}. */
function loadSources_(ss) {
  const sources = new Map();
  readRows_(ss, 'Sources').forEach(function (r, i) {
    sources.set(String(r[0]), {
      row: i + 2, firstSeen: r[1], lastSeen: r[2], messages: Number(r[3]) || 0, failed: Number(r[4]) || 0,
      via: String(r[5]), lastIp: String(r[6]), status: String(r[7] || '').trim().toLowerCase(),
    });
  });
  return sources;
}

/**
 * Writes the script-owned columns (A-G) of Sources: existing orgs in place, new orgs
 * appended. Columns `status` and `notes` are never touched, so edits there survive.
 */
function saveSources_(ss, sources) {
  const sh = sheet_(ss, 'Sources');
  let nextRow = Math.max(sh.getLastRow(), 1) + 1;
  const rows = [];
  sources.forEach(function (s, org) {
    if (!s.row) s.row = nextRow++;
    rows[s.row - 2] = [org, s.firstSeen, s.lastSeen, s.messages, s.failed, s.via, s.lastIp];
  });
  if (!rows.length) return;
  for (let i = 0; i < rows.length; i++) if (!rows[i]) rows[i] = new Array(SOURCES_SCRIPT_COLS_).fill('');
  sh.getRange(2, 1, rows.length, SOURCES_SCRIPT_COLS_).setValues(rows);
}

/** Reports-tab row for a parsed report (columns as SHEETS_.Reports). */
function reportRow_(report, key) {
  const messages = report.records.reduce(function (n, r) { return n + r.count; }, 0);
  const failed = report.records.reduce(function (n, r) { return n + (r.dmarcPass ? 0 : r.count); }, 0);
  const p = report.policy;
  return [key, report.orgName, report.reportId, report.begin, report.end, p.domain, p.p, p.sp, p.pct, p.adkim, p.aspf,
    report.records.length, messages, failed, new Date()];
}

/** Records-tab row for one enriched record (columns as SHEETS_.Records). */
function recordRow_(report, key, r) {
  return [key, report.orgName, report.begin, report.end, r.sourceIp, r.ptr, r.org, r.via, r.count,
    r.disposition, r.dmarcPass ? 'pass' : 'fail', r.dkim, r.spf, r.headerFrom, r.envelopeFrom,
    r.dkimAuth.map(function (d) { return d.domain + (d.selector ? '/' + d.selector : '') + '=' + d.result; }).join('; '),
    r.spfAuth.map(function (s) { return s.domain + (s.scope ? '/' + s.scope : '') + '=' + s.result; }).join('; '),
    r.reasons.join('; ')];
}
