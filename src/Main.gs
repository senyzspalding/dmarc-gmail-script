/**
 * Entry points. Run setup() once by hand; triggers run the rest.
 */

// Functions run by time-based triggers. setup() deletes and recreates their triggers.
const TRIGGER_HANDLERS_ = ['processReports', 'checkStale', 'weeklyDigest'];

/** Creates labels, the spreadsheet and the triggers. Safe to run again. */
function setup() {
  if (CONFIG.alertRecipients.some(function (a) { return /CHANGE_ME/i.test(a); })) {
    throw new Error('Set CONFIG.alertRecipients in Config.gs before running setup().');
  }
  [CONFIG.rootLabel, CONFIG.processedLabel, CONFIG.errorLabel, CONFIG.unparsedLabel].forEach(function (name) {
    if (!GmailApp.getUserLabelByName(name)) GmailApp.createLabel(name);
  });

  const ss = getSpreadsheet_();
  initSheets_(ss);

  ScriptApp.getProjectTriggers().forEach(function (t) {
    if (TRIGGER_HANDLERS_.indexOf(t.getHandlerFunction()) >= 0) ScriptApp.deleteTrigger(t);
  });
  ScriptApp.newTrigger('processReports').timeBased().everyHours(1).create();
  ScriptApp.newTrigger('checkStale').timeBased().everyDays(1).atHour(7).create();
  ScriptApp.newTrigger('weeklyDigest').timeBased().onWeekDay(ScriptApp.WeekDay.MONDAY).atHour(8).create();

  const props = PropertiesService.getScriptProperties();
  if (!props.getProperty('SETUP_AT')) props.setProperty('SETUP_AT', String(Date.now()));
  if (!props.getProperty('LAST_REPORT_AT')) props.setProperty('LAST_REPORT_AT', String(Date.now()));

  Logger.log('Setup complete. Spreadsheet: ' + ss.getUrl());
}

/**
 * Hourly: parse new report emails, store them, alert on problems.
 *
 * Flow: search Gmail for threads labeled DMARC but not yet processed/error/unparsed ->
 * extract and parse every report -> skip ones already stored -> enrich each record
 * (PTR, SPF match, org) -> write Reports/Records/PtrCache -> evaluate alerts against
 * the Sources list as it was before this run -> update Sources -> email findings.
 * A script lock prevents overlapping runs; the loop stops early near the time limit
 * and the next run picks up the remaining threads.
 */
function processReports() {
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(5000)) return;
  try {
    const started = Date.now();
    const ss = getSpreadsheet_();
    const props = PropertiesService.getScriptProperties();
    const seenKeys = loadReportKeys_(ss);
    const ptrCache = loadPtrCache_(ss);
    const sources = loadSources_(ss);
    const nets = getAuthorizedNets_();
    const budget = { remaining: CONFIG.maxPtrLookupsPerRun };
    const labels = {
      processed: GmailApp.getUserLabelByName(CONFIG.processedLabel),
      error: GmailApp.getUserLabelByName(CONFIG.errorLabel),
      unparsed: GmailApp.getUserLabelByName(CONFIG.unparsedLabel),
    };
    const query = 'label:' + labelQuery_(CONFIG.rootLabel) + ' -label:' + labelQuery_(CONFIG.processedLabel) +
      ' -label:' + labelQuery_(CONFIG.errorLabel) + ' -label:' + labelQuery_(CONFIG.unparsedLabel);

    const threads = GmailApp.search(query, 0, CONFIG.maxThreadsPerRun);
    const newReports = [];
    const reportRows = [];
    const recordRows = [];

    for (let i = 0; i < threads.length; i++) {
      if (Date.now() - started > CONFIG.maxRunMillis) break;
      const thread = threads[i];
      let found = 0, failed = false;
      thread.getMessages().forEach(function (message) {
        try {
          extractReportXml_(message).forEach(function (xml) {
            const report = parseReportXml_(xml);
            found++;
            const key = reportKey_(report);
            if (seenKeys.has(key)) return;
            seenKeys.add(key);
            report.records.forEach(function (r) { enrichRecord_(r, nets, ptrCache, budget, sources); });
            newReports.push(report);
            reportRows.push(reportRow_(report, key));
            report.records.forEach(function (r) { recordRows.push(recordRow_(report, key, r)); });
          });
        } catch (e) {
          failed = true;
          console.error('Failed to process message "' + message.getSubject() + '": ' + e.stack);
        }
      });
      thread.addLabel(failed ? labels.error : found ? labels.processed : labels.unparsed);
      thread.markRead();
    }

    appendRows_(ss, 'Reports', reportRows);
    appendRows_(ss, 'Records', recordRows);
    savePtrCache_(ss, ptrCache);

    const setupAt = Number(props.getProperty('SETUP_AT') || 0);
    const learning = Date.now() - setupAt < CONFIG.thresholds.learningDays * 86400000;
    const findings = evaluateRun_(newReports, sources, CONFIG, new Date(), learning);
    updateSources_(sources, newReports);
    saveSources_(ss, sources);
    if (newReports.length) props.setProperty('LAST_REPORT_AT', String(Date.now()));

    sendFindings_(ss, findings);
    console.log('Processed ' + threads.length + ' threads, ' + newReports.length + ' new reports, ' +
      findings.length + ' findings');
  } finally {
    lock.releaseLock();
  }
}

/** Adds ptr, org, via (SPF include that authorizes the IP) and known to a record. */
function enrichRecord_(r, nets, ptrCache, budget, sources) {
  r.ptr = lookupPtr_(r.sourceIp, ptrCache, budget);
  r.via = findAuthorizedVia_(r.sourceIp, nets);
  if (!r.via && r.ptr) {
    const suffix = CONFIG.extraKnownPtrSuffixes.filter(function (s) {
      return r.ptr === s || r.ptr.slice(-(s.length + 1)) === '.' + s;
    })[0];
    if (suffix) r.via = suffix;
  }
  r.org = r.ptr ? sourceOrg_(r.sourceIp, r.ptr) : (r.via || sourceOrg_(r.sourceIp, ''));
  const src = sources.get(r.org);
  r.known = !!r.via || (!!src && src.status === 'approved');
}

/** Gmail search syntax wants "/" and spaces in label names written as "-". */
function labelQuery_(name) {
  return name.replace(/[\/ ]/g, '-');
}

/** Daily: alert if reports have stopped arriving. */
function checkStale() {
  const last = Number(PropertiesService.getScriptProperties().getProperty('LAST_REPORT_AT') || 0);
  const days = (Date.now() - last) / 86400000;
  if (days < CONFIG.thresholds.staleDays) return;
  sendFindings_(getSpreadsheet_(), [{
    severity: 'WARNING', key: 'stale',
    title: 'No DMARC reports received for ' + Math.floor(days) + ' days',
    body: ['Receivers normally send aggregate reports daily. Check that the rua= address in the _dmarc DNS record ' +
      'still points at the group, that this account is still a group member receiving every email, ' +
      'and that the Gmail filter is still labeling reports "' + CONFIG.rootLabel + '".'],
  }]);
}

/** Weekly (Monday 8am): emails pass rate and top 30 sources for the last 7 days, read from the sheet. */
function weeklyDigest() {
  const ss = getSpreadsheet_();
  const since = Date.now() - 7 * 86400000;
  const header = SHEETS_.Records;
  const col = function (name) { return header.indexOf(name); };
  const byOrg = new Map();
  let total = 0, failed = 0;

  readRows_(ss, 'Records').forEach(function (r) {
    const end = r[col('end')];
    if (!(end instanceof Date) || end.getTime() < since) return;
    const n = Number(r[col('count')]) || 0;
    const fail = r[col('dmarc')] === 'fail' ? n : 0;
    const org = String(r[col('source_org')]);
    const agg = byOrg.get(org) || { messages: 0, failed: 0, via: '' };
    agg.messages += n;
    agg.failed += fail;
    agg.via = agg.via || String(r[col('authorized_via')]);
    byOrg.set(org, agg);
    total += n;
    failed += fail;
  });

  const reports = readRows_(ss, 'Reports').filter(function (r) {
    return r[4] instanceof Date && r[4].getTime() >= since;
  }).length;
  const problems = GmailApp.search('label:' + labelQuery_(CONFIG.errorLabel) + ' newer_than:7d').length;

  const rows = Array.from(byOrg.entries())
    .sort(function (a, b) { return b[1].messages - a[1].messages; })
    .slice(0, 30)
    .map(function (e) {
      const a = e[1];
      return [e[0], a.via || 'not in SPF', a.messages, a.failed, (a.messages ? a.failed / a.messages * 100 : 0).toFixed(1) + '%'];
    });
  const passPct = total ? ((total - failed) / total * 100).toFixed(1) : 'n/a';

  let html = '<div style="font-family:Arial,sans-serif;font-size:14px">' +
    '<h2 style="margin:0 0 8px">DMARC weekly summary for ' + esc_(CONFIG.domain) + '</h2>' +
    '<p>' + reports + ' reports covering ' + total + ' messages. DMARC pass rate: <b>' + passPct + '%</b> ' +
    '(' + failed + ' failed).</p>';
  if (problems) html += '<p style="color:#b00">' + problems + ' report emails could not be parsed (label ' +
    esc_(CONFIG.errorLabel) + ').</p>';
  if (rows.length) html += htmlTable_(['Source', 'Authorized via', 'Messages', 'Failed', 'Fail %'], rows);
  html += '<p style="color:#666;margin-top:20px">Spreadsheet: <a href="' + ss.getUrl() + '">' + esc_(ss.getName()) +
    '</a></p></div>';
  const text = 'DMARC weekly summary for ' + CONFIG.domain + ': ' + reports + ' reports, ' + total +
    ' messages, ' + passPct + '% pass. Details: ' + ss.getUrl();

  GmailApp.sendEmail(CONFIG.alertRecipients.join(','), '[DMARC] Weekly summary for ' + CONFIG.domain +
    ': ' + passPct + '% pass', text, { htmlBody: html, name: 'DMARC Monitor' });
}
