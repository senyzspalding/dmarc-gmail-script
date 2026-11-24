/**
 * DNS lookups (via Google's DNS-over-HTTPS JSON API), SPF expansion and IP matching.
 */

// DNS record type names -> numeric codes, as returned in dns.google answers.
const DNS_TYPES_ = { A: 1, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };

/**
 * One DNS-over-HTTPS query against dns.google.
 * @param {string} name  Name to look up (e.g. "example.org", "4.3.2.1.in-addr.arpa").
 * @param {string} type  Record type, a key of DNS_TYPES_ ("A", "TXT", ...).
 * @return {string[]} The `data` field of each answer of that type; [] on any HTTP error.
 */
function dohQuery_(name, type) {
  const url = 'https://dns.google/resolve?name=' + encodeURIComponent(name) + '&type=' + type;
  const resp = UrlFetchApp.fetch(url, { muteHttpExceptions: true });
  if (resp.getResponseCode() !== 200) return [];
  const data = JSON.parse(resp.getContentText());
  return (data.Answer || [])
    .filter(function (a) { return a.type === DNS_TYPES_[type]; })
    .map(function (a) { return a.data; });
}

/** TXT answers may come back quoted and split into several strings. */
function cleanTxt_(s) {
  return String(s).replace(/"\s*"/g, '').replace(/^"|"$/g, '');
}

/**
 * Every network the domain's SPF record authorizes, as [{cidr, via}], where `via`
 * names the include it came from (e.g. "mailgun.org"). Cached for 6 hours.
 */
function getAuthorizedNets_() {
  const cache = CacheService.getScriptCache();
  const cached = cache.get('spfNets');
  if (cached) return JSON.parse(cached);
  const nets = [];
  expandSpf_(CONFIG.domain, '', nets, { lookups: 0 });
  const json = JSON.stringify(nets);
  if (nets.length && json.length < 90000) cache.put('spfNets', json, 21600);
  return nets;
}

/**
 * Recursively walks an SPF record and pushes every authorized network onto `out`.
 * Handles ip4, ip6, include, a, mx and redirect=. Only "+" (pass) mechanisms count;
 * -, ~ and ? are skipped, as are macros (%{...}) and exists:/ptr.
 * @param {string} domain  Domain whose SPF TXT record is read.
 * @param {string} via     Top-level include this branch came from ('' at the root).
 * @param {Array<{cidr: string, via: string}>} out  Collected networks (mutated).
 * @param {{lookups: number}} state  Shared counter; stops after 25 lookups to avoid loops.
 */
function expandSpf_(domain, via, out, state) {
  if (++state.lookups > 25) return;
  const record = dohQuery_(domain, 'TXT').map(cleanTxt_).filter(function (t) { return /^v=spf1(\s|$)/i.test(t); })[0];
  if (!record) return;
  record.split(/\s+/).slice(1).forEach(function (tok) {
    let qualifier = '+';
    if (/^[+\-~?]/.test(tok)) { qualifier = tok[0]; tok = tok.slice(1); }
    if (tok.indexOf('%') >= 0) return; // SPF macros aren't supported
    const lower = tok.toLowerCase();
    if (lower.indexOf('redirect=') === 0) {
      const target = tok.slice(9);
      expandSpf_(target, via || target, out, state);
      return;
    }
    if (qualifier !== '+') return;
    const m = /^(ip4|ip6|include|a|mx)(?::([^/]+))?(?:\/(\d+))?(?:\/\/(\d+))?$/i.exec(tok);
    if (!m) return;
    const mech = m[1].toLowerCase();
    const arg = m[2];
    if (mech === 'ip4' || mech === 'ip6') {
      out.push({ cidr: arg + (m[3] ? '/' + m[3] : ''), via: via || domain });
    } else if (mech === 'include') {
      expandSpf_(arg, via || arg, out, state);
    } else {
      const target = arg || domain;
      const hosts = mech === 'a' ? [target] : dohQuery_(target, 'MX').map(function (mx) {
        return mx.split(/\s+/).pop().replace(/\.$/, '');
      });
      state.lookups++;
      hosts.forEach(function (h) {
        dohQuery_(h, 'A').forEach(function (ip) { out.push({ cidr: ip + '/' + (m[3] || 32), via: via || domain }); });
        dohQuery_(h, 'AAAA').forEach(function (ip) { out.push({ cidr: ip + '/' + (m[4] || 128), via: via || domain }); });
      });
    }
  });
}

/** Returns the `via` of the first authorized network containing ip, or ''. */
function findAuthorizedVia_(ip, nets) {
  for (let i = 0; i < nets.length; i++) {
    if (ipInCidr_(ip, nets[i].cidr)) return nets[i].via;
  }
  return '';
}

/**
 * True if `ip` is inside `cidr` ("1.2.3.0/24", "2001:db8::/32", or a bare address).
 * IPv4 and IPv6 never match each other.
 */
function ipInCidr_(ip, cidr) {
  const parts = cidr.split('/');
  const a = ipToBytes_(ip);
  const b = ipToBytes_(parts[0]);
  if (!a || !b || a.length !== b.length) return false;
  const bits = parts.length > 1 ? parseInt(parts[1], 10) : a.length * 8;
  for (let i = 0; i < a.length; i++) {
    const remaining = bits - i * 8;
    if (remaining <= 0) return true;
    const mask = remaining >= 8 ? 0xff : (0xff << (8 - remaining)) & 0xff;
    if ((a[i] & mask) !== (b[i] & mask)) return false;
  }
  return true;
}

/** IPv4 -> 4 bytes, IPv6 -> 16 bytes, anything else -> null. */
function ipToBytes_(ip) {
  ip = String(ip).trim();
  if (ip.indexOf(':') < 0) {
    const p = ip.split('.');
    if (p.length !== 4) return null;
    const bytes = p.map(function (x) { return /^\d{1,3}$/.test(x) ? parseInt(x, 10) : NaN; });
    return bytes.every(function (x) { return x >= 0 && x <= 255; }) ? bytes : null;
  }
  let tail = [];
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
  if (v4) {
    tail = ipToBytes_(v4[1]);
    if (!tail) return null;
    ip = ip.slice(0, -v4[1].length) + '0:0';
  }
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = 8 - head.length - rest.length;
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return null;
  const groups = head.concat(new Array(fill).fill('0'), rest);
  const bytes = [];
  for (let i = 0; i < groups.length; i++) {
    if (!/^[0-9a-f]{1,4}$/i.test(groups[i])) return null;
    const n = parseInt(groups[i], 16);
    bytes.push(n >> 8, n & 0xff);
  }
  if (tail.length) bytes.splice(12, 4, tail[0], tail[1], tail[2], tail[3]);
  return bytes;
}

/** PTR query name for an IP: "d.c.b.a.in-addr.arpa" or the nibble-reversed ".ip6.arpa" form. */
function reverseName_(ip) {
  const bytes = ipToBytes_(ip);
  if (!bytes) return null;
  if (bytes.length === 4) return bytes.slice().reverse().join('.') + '.in-addr.arpa';
  const nibbles = [];
  bytes.forEach(function (b) { nibbles.push((b >> 4).toString(16), (b & 0xf).toString(16)); });
  return nibbles.reverse().join('.') + '.ip6.arpa';
}

/**
 * Reverse-DNS name for ip, using and filling `cache`.
 * @param {string} ip
 * @param {Object} cache   {ip: {ptr, isNew}}; new lookups are flagged isNew so savePtrCache_ writes them.
 * @param {{remaining: number}} budget  Lookups left this run; returns '' once exhausted.
 * @return {string} Lower-case PTR name without the trailing dot, or ''.
 */
function lookupPtr_(ip, cache, budget) {
  if (cache[ip]) return cache[ip].ptr;
  if (!CONFIG.resolvePtr || budget.remaining <= 0) return '';
  budget.remaining--;
  const name = reverseName_(ip);
  const ptr = name ? (dohQuery_(name, 'PTR')[0] || '').replace(/\.$/, '').toLowerCase() : '';
  cache[ip] = { ptr: ptr, isNew: true };
  return ptr;
}

// Public suffixes with two labels, so sourceOrg_ keeps three labels (e.g. "example.co.uk").
const TWO_PART_TLDS_ = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.za', 'com.br', 'com.cn', 'co.in', 'com.mx'];

/**
 * Groups a source IP into an "organization": the base domain of its PTR name,
 * or its /24 (IPv4) or /48 (IPv6) network when it has no PTR.
 */
function sourceOrg_(ip, ptr) {
  if (ptr) {
    const labels = ptr.split('.');
    const n = TWO_PART_TLDS_.indexOf(labels.slice(-2).join('.')) >= 0 ? 3 : 2;
    return labels.slice(-n).join('.');
  }
  const bytes = ipToBytes_(ip);
  if (!bytes) return 'unknown';
  if (bytes.length === 4) return 'no-ptr ' + bytes.slice(0, 3).join('.') + '.0/24';
  const g = [];
  for (let i = 0; i < 6; i += 2) g.push(((bytes[i] << 8) | bytes[i + 1]).toString(16));
  return 'no-ptr ' + g.join(':') + '::/48';
}
