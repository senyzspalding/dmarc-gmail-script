/**
 * Deciding what is worth an alert, and sending it.
 */

// Sort order for findings: most severe first. Also decides the email subject tag.
const SEVERITY_ORDER_ = { CRITICAL: 0, WARNING: 1, NOTICE: 2 };

/**
 * Looks at the reports processed in this run and returns findings:
 * {severity, key, title, body: [lines], rows: [[...]], headers: [...]}.
 * `sources` is the Sources map *before* this run's reports were added.
 * While `learning` is true (the first days after setup) new-sender notices are
 * skipped, since every sender is new.
 * Pure function: no Apps Script services, so it can be tested locally.
 */
function evaluateRun_(reports, sources, cfg, now, learning) {
  const t = cfg.thresholds;
  const cutoff = now.getTime() - t.alertMaxReportAgeDays * 86400000;
  const recent = reports.filter(function (rep) { return !rep.end || rep.end.getTime() >= cutoff; });
  const findings = [];

  // 1. Published policy differs from what we expect.
  const exp = cfg.expectedPolicy;
  recent.forEach(function (rep) {
    const p = rep.policy;
    if (p.domain !== cfg.domain) return;
    const changed = Object.keys(exp).filter(function (k) { return p[k] && String(p[k]) !== String(exp[k]); });
    if (!changed.length) return;
    const desc = changed.map(function (k) { return k + '=' + p[k] + ' (expected ' + exp[k] + ')'; }).join(', ');
    findings.push({
      severity: 'WARNING', key: 'policy:' + desc, title: 'DMARC policy for ' + cfg.domain + ' changed: ' + desc,
      body: ['A report from ' + rep.orgName + ' saw a published policy that differs from the expected one. ' +
        'If nobody changed the _dmarc DNS record on purpose, check it now.'],
    });
  });

  // 2. Per-source-org failures and new senders.
  const byOrg = new Map();
  let total = 0, failedTotal = 0;
  recent.forEach(function (rep) {
    rep.records.forEach(function (r) {
      total += r.count;
      if (!r.dmarcPass) failedTotal += r.count;
      let agg = byOrg.get(r.org);
      if (!agg) {
        agg = { org: r.org, known: false, via: '', messages: 0, failed: 0, ips: new Set(), failures: [] };
        byOrg.set(r.org, agg);
      }
      agg.known = agg.known || r.known;
      agg.via = agg.via || r.via;
      agg.messages += r.count;
      agg.ips.add(r.sourceIp);
      if (!r.dmarcPass) {
        agg.failed += r.count;
        agg.failures.push([rep.orgName, r.sourceIp, r.ptr || '-', r.count, r.headerFrom,
          'DKIM ' + r.dkim + ' / SPF ' + r.spf, authSummary_(r), r.disposition]);
      }
    });
  });

  const failHeaders = ['Reporter', 'Source IP', 'PTR', 'Msgs', 'From', 'Aligned', 'Auth results', 'Disposition'];
  byOrg.forEach(function (agg) {
    const src = sources.get(agg.org);
    const status = src ? src.status : '';
    if (status === 'ignore') return;

    if (agg.known && agg.failed >= t.knownFailAlertMin) {
      findings.push({
        severity: 'CRITICAL', key: 'knownfail:' + agg.org,
        title: agg.failed + ' messages from authorized sender ' + agg.org + ' failed DMARC',
        body: ['This source is authorized (' + (agg.via || 'approved in Sources sheet') + ') but its mail is not ' +
          'passing DMARC, and with p=reject receivers are likely rejecting it.',
        'Usual causes: DKIM not signing with d=' + cfg.domain + ', or SPF passing for a different envelope domain ' +
          '(aspf=s requires an exact match). Shared platforms such as Google and Microsoft can also show failures ' +
          'from other tenants spoofing you; check the "From" and auth results below.'],
        headers: failHeaders, rows: agg.failures.slice(0, 25),
      });
    } else if (!agg.known && agg.failed >= t.unknownFailAlertMin) {
      findings.push({
        severity: 'WARNING', key: 'unknownfail:' + agg.org,
        title: agg.failed + ' failing messages from unrecognized source ' + agg.org,
        body: ['Mail claiming to be from ' + cfg.domain + ' came from servers not in your SPF record and failed DMARC. ' +
          'This is either spoofing (blocked by p=reject) or a service someone set up without DKIM/SPF.',
        'If it is a legitimate service, add it to SPF/DKIM. If it is a forwarder or expected noise, ' +
          'set its status to "ignore" in the Sources sheet.'],
        headers: failHeaders, rows: agg.failures.slice(0, 25),
      });
    }

    if (!learning && !src && agg.messages > agg.failed) {
      findings.push({
        severity: 'NOTICE', key: 'newsender:' + agg.org,
        title: 'New sender passing DMARC as ' + cfg.domain + ': ' + agg.org,
        body: ['First time this source has been seen, and ' + (agg.messages - agg.failed) + ' of its ' + agg.messages +
          ' messages passed DMARC, so it holds valid DKIM keys or SPF authorization for your domain.',
        'If this is expected, set its status to "approved" in the Sources sheet. If not, find out who set it up.',
        'IPs: ' + Array.from(agg.ips).slice(0, 10).join(', ')],
      });
    }
  });

  // 3. Overall fail rate.
  if (total >= t.failRateMinVolume && (failedTotal / total) * 100 >= t.failRatePct) {
    findings.push({
      severity: 'WARNING', key: 'failrate',
      title: 'High DMARC failure rate: ' + (failedTotal / total * 100).toFixed(1) + '% of ' + total + ' messages',
      body: ['Across the reports processed in this run, ' + failedTotal + ' of ' + total + ' messages failed DMARC.'],
    });
  }

  const seenKeys = new Set();
  return findings
    .filter(function (f) { return !seenKeys.has(f.key) && seenKeys.add(f.key); })
    .sort(function (a, b) { return SEVERITY_ORDER_[a.severity] - SEVERITY_ORDER_[b.severity]; });
}

/** Adds this run's records to the Sources map. Call after evaluateRun_. */
function updateSources_(sources, reports) {
  reports.forEach(function (rep) {
    const seen = rep.end || new Date();
    rep.records.forEach(function (r) {
      let s = sources.get(r.org);
      if (!s) {
        s = { row: 0, firstSeen: seen, lastSeen: seen, messages: 0, failed: 0, via: '', lastIp: '', status: '' };
        sources.set(r.org, s);
      }
      if (seen < s.firstSeen) s.firstSeen = seen;
      if (seen >= s.lastSeen) { s.lastSeen = seen; s.lastIp = r.sourceIp; }
      s.messages += r.count;
      if (!r.dmarcPass) s.failed += r.count;
      if (r.via) s.via = r.via;
    });
  });
}

/** Compact raw auth results for an alert row, e.g. "dkim:mailgun.org=pass, spf:bounce.x.org=pass". */
function authSummary_(r) {
  const dkim = r.dkimAuth.map(function (d) { return 'dkim:' + d.domain + '=' + d.result; });
  const spf = r.spfAuth.map(function (s) { return 'spf:' + s.domain + '=' + s.result; });
  return dkim.concat(spf).join(', ') || '-';
}

/**
 * Drops findings sent within the suppression window, then emails the rest as one
 * message (HTML + plain text) to CONFIG.alertRecipients. Each sent finding is logged
 * to the Alerts tab and its send time stored in Script Properties as "alert:<key>".
 */
function sendFindings_(ss, findings) {
  const props = PropertiesService.getScriptProperties();
  const now = Date.now();
  const windowMs = CONFIG.thresholds.suppressHours * 3600000;
  const fresh = findings.filter(function (f) {
    const last = Number(props.getProperty('alert:' + f.key) || 0);
    return now - last >= windowMs;
  });
  if (!fresh.length) return;

  const top = fresh[0].severity;
  const subject = '[DMARC ' + top + '] ' + (fresh.length === 1 ? fresh[0].title : fresh.length + ' issues for ' + CONFIG.domain);
  let html = '<div style="font-family:Arial,sans-serif;font-size:14px">';
  let text = '';
  fresh.forEach(function (f) {
    html += '<h3 style="margin:18px 0 6px">' + esc_(f.severity) + ': ' + esc_(f.title) + '</h3>';
    html += f.body.map(function (b) { return '<p style="margin:4px 0">' + esc_(b) + '</p>'; }).join('');
    if (f.rows && f.rows.length) html += htmlTable_(f.headers, f.rows);
    text += f.severity + ': ' + f.title + '\n' + f.body.join('\n') + '\n\n';
  });
  html += '<p style="color:#666;margin-top:20px">Spreadsheet: <a href="' + ss.getUrl() + '">' + esc_(ss.getName()) + '</a></p></div>';
  text += 'Spreadsheet: ' + ss.getUrl();

  GmailApp.sendEmail(CONFIG.alertRecipients.join(','), subject, text, { htmlBody: html, name: 'DMARC Monitor' });
  appendRows_(ss, 'Alerts', fresh.map(function (f) { return [new Date(), f.severity, f.key, f.title]; }));
  fresh.forEach(function (f) { props.setProperty('alert:' + f.key, String(now)); });
}

/** Inline-styled HTML table (email clients ignore <style> blocks). Cells are escaped. */
function htmlTable_(headers, rows) {
  const td = 'style="border:1px solid #ccc;padding:3px 6px;vertical-align:top"';
  return '<table style="border-collapse:collapse;font-size:12px;margin:6px 0">' +
    '<tr>' + headers.map(function (h) { return '<th ' + td + '>' + esc_(h) + '</th>'; }).join('') + '</tr>' +
    rows.map(function (r) {
      return '<tr>' + r.map(function (c) { return '<td ' + td + '>' + esc_(c) + '</td>'; }).join('') + '</tr>';
    }).join('') + '</table>';
}

/** HTML-escapes a value for email bodies. */
function esc_(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
