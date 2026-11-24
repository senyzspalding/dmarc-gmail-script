/**
 * Turning report emails into plain report objects.
 */

/** Returns the XML text of every aggregate report attached to a Gmail message. */
function extractReportXml_(message) {
  const docs = [];
  const attachments = message.getAttachments({ includeInlineImages: false, includeAttachments: true });
  attachments.forEach(function (att) {
    const bytes = att.getBytes();
    if (bytes.length < 2) return;
    const b0 = bytes[0] & 0xff;
    const b1 = bytes[1] & 0xff;
    if (b0 === 0x50 && b1 === 0x4b) { // "PK" - zip
      Utilities.unzip(att.copyBlob().setContentType('application/zip')).forEach(function (b) {
        const text = b.getDataAsString();
        if (looksLikeReport_(text)) docs.push(text);
      });
    } else if (b0 === 0x1f && b1 === 0x8b) { // gzip
      const text = Utilities.ungzip(att.copyBlob().setContentType('application/x-gzip')).getDataAsString();
      if (looksLikeReport_(text)) docs.push(text);
    } else {
      const text = att.getDataAsString();
      if (looksLikeReport_(text)) docs.push(text);
    }
  });
  return docs;
}

/** Cheap check that a decoded attachment is an aggregate report (has a <feedback> element). */
function looksLikeReport_(text) {
  return /<feedback[\s>]/.test(text);
}

/**
 * Parses aggregate report XML (RFC 7489, and the DMARCbis namespaced variant)
 * into a plain object. Element names are matched ignoring XML namespaces.
 */
function parseReportXml_(xml) {
  const clean = String(xml).replace(/^﻿/, '').trim();
  const root = XmlService.parse(clean).getRootElement();
  if (root.getName() !== 'feedback') throw new Error('Root element is not <feedback>');

  const meta = child_(root, 'report_metadata');
  const policy = child_(root, 'policy_published');
  const report = {
    orgName: text_(meta, 'org_name'),
    email: text_(meta, 'email'),
    reportId: text_(meta, 'report_id'),
    begin: epochToDate_(text_(meta, 'date_range/begin')),
    end: epochToDate_(text_(meta, 'date_range/end')),
    policy: {
      domain: text_(policy, 'domain').toLowerCase(),
      adkim: text_(policy, 'adkim'),
      aspf: text_(policy, 'aspf'),
      p: text_(policy, 'p'),
      sp: text_(policy, 'sp'),
      pct: text_(policy, 'pct'),
    },
    records: [],
  };
  if (!report.reportId) throw new Error('Report has no report_id');

  children_(root, 'record').forEach(function (rec) {
    const row = child_(rec, 'row');
    const evaluated = child_(row, 'policy_evaluated');
    const ids = child_(rec, 'identifiers');
    const auth = child_(rec, 'auth_results');
    const r = {
      sourceIp: text_(row, 'source_ip'),
      count: parseInt(text_(row, 'count'), 10) || 0,
      disposition: text_(evaluated, 'disposition'),
      dkim: text_(evaluated, 'dkim'),
      spf: text_(evaluated, 'spf'),
      reasons: children_(evaluated, 'reason').map(function (rs) {
        const comment = text_(rs, 'comment');
        return text_(rs, 'type') + (comment ? ' (' + comment + ')' : '');
      }),
      headerFrom: text_(ids, 'header_from').toLowerCase(),
      envelopeFrom: text_(ids, 'envelope_from').toLowerCase(),
      dkimAuth: children_(auth, 'dkim').map(function (d) {
        return { domain: text_(d, 'domain'), selector: text_(d, 'selector'), result: text_(d, 'result') };
      }),
      spfAuth: children_(auth, 'spf').map(function (s) {
        return { domain: text_(s, 'domain'), scope: text_(s, 'scope'), result: text_(s, 'result') };
      }),
    };
    r.dmarcPass = r.dkim === 'pass' || r.spf === 'pass';
    report.records.push(r);
  });
  return report;
}

/**
 * Unique key for a report, used to skip duplicates (the same report can arrive twice
 * via the group). report_id is only unique per reporting organization.
 */
function reportKey_(report) {
  return report.orgName + '|' + report.reportId;
}

/** Unix seconds (as text) -> Date, or null if not a number. */
function epochToDate_(s) {
  const n = parseInt(s, 10);
  return isNaN(n) ? null : new Date(n * 1000);
}

/** Direct children of `el` with local name `name` (namespace ignored). Null-safe. */
function children_(el, name) {
  if (!el) return [];
  return el.getChildren().filter(function (c) { return c.getName() === name; });
}

/** First direct child with local name `name`, or null. */
function child_(el, name) {
  return children_(el, name)[0] || null;
}

/** Text of a descendant given a slash-separated path, or '' if missing. */
function text_(el, path) {
  const parts = path.split('/');
  for (let i = 0; i < parts.length && el; i++) el = child_(el, parts[i]);
  return el ? el.getText().trim() : '';
}
