/**
 * DMARC monitor configuration.
 * Copy this file to Config.gs (git-ignored), fill in your values, then run setup() once.
 */
const CONFIG = {
  // Domain whose DMARC reports we are monitoring.
  domain: 'example.org',

  // Gmail labels. The Gmail filter (see README) applies `rootLabel` to incoming reports.
  rootLabel: 'DMARC',
  processedLabel: 'DMARC/processed',
  errorLabel: 'DMARC/error',       // attachment found but could not be parsed
  unparsedLabel: 'DMARC/unparsed', // no aggregate report found (e.g. forensic/ruf reports)

  // Leave blank: setup() creates the spreadsheet and remembers its ID.
  spreadsheetId: '',

  // Who receives alerts and the weekly digest. setup() refuses to run until this is set.
  alertRecipients: ['alerts@example.org'],

  // What the published DMARC record should look like. Reports showing anything
  // else raise a "policy changed" alert.
  expectedPolicy: { p: 'reject', sp: 'reject', pct: '100' },

  // Sending infrastructure treated as "ours" in addition to everything the
  // domain's SPF record authorizes (resolved automatically). Matched against
  // the end of the source IP's reverse-DNS name.
  extraKnownPtrSuffixes: [],

  thresholds: {
    knownFailAlertMin: 3,      // failed messages from an authorized sender before alerting
    unknownFailAlertMin: 25,   // failed messages from one unknown source org before alerting
    failRatePct: 10,           // overall fail rate (per run) that triggers an alert...
    failRateMinVolume: 100,    // ...but only when the run covers at least this many messages
    staleDays: 3,              // alert if no new reports for this many days
    suppressHours: 24,         // don't repeat the same alert within this window
    alertMaxReportAgeDays: 10, // reports older than this are recorded but never alert
    learningDays: 7,           // after setup, don't send "new sender" notices while the Sources list fills
  },

  // Look up reverse DNS (PTR) names for source IPs via dns.google.
  resolvePtr: true,
  maxPtrLookupsPerRun: 150,

  maxThreadsPerRun: 40,
  maxRunMillis: 4.5 * 60 * 1000, // Apps Script hard limit is 6 minutes
};
