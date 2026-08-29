'use strict';
/**
 * Hostname normalization for the threat-feed pipeline.
 *
 * Per the research digest (Pipeline spec, NORMALIZE stage):
 *   lowercase; strip scheme/port/path/query; punycode via url.domainToASCII;
 *   strip leading www.; drop IPs/bare TLDs/len>253; KEEP FULL HOSTNAME
 *   — never collapse to eTLD+1 (shared hosting like *.pages.dev/*.vercel.app
 *   must keep the exact abusive hostname, not the whole platform).
 */
const { domainToASCII } = require('node:url');
const net = require('node:net');

const MAX_HOST_LEN = 253;
// Conservative hostname grammar: LDH labels (a-z0-9-, no leading/trailing
// hyphen) joined by dots. Punycode labels ("xn--...") already satisfy this.
const HOST_RE = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/;

/**
 * Pulls a bare hostname out of a URL, "host:port", "host/path", or already-
 * bare host string. Returns null if nothing host-shaped can be extracted.
 */
function stripScheme(raw) {
  const s = String(raw == null ? '' : raw).trim();
  if (!s) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) {
    try {
      return new URL(s).hostname || null;
    } catch (_) {
      return null;
    }
  }
  let h = s.split(/[/?#\s]/)[0];
  if (!h) return null;
  const at = h.lastIndexOf('@');
  if (at > -1) h = h.slice(at + 1);
  if (h.startsWith('[')) {
    // IPv6 literal in bracket form, e.g. "[::1]:8080".
    const end = h.indexOf(']');
    h = end > -1 ? h.slice(1, end) : h.slice(1);
  } else {
    const colon = h.indexOf(':');
    if (colon > -1) h = h.slice(0, colon);
  }
  return h || null;
}

/**
 * Normalizes a raw feed entry (URL, "host:port", or bare hostname) into a
 * canonical full hostname, or null if it should be dropped.
 */
function normalizeHost(raw) {
  let h = stripScheme(raw);
  if (!h) return null;
  h = h.toLowerCase().replace(/\.+$/, '');
  if (!h) return null;
  if (h.startsWith('www.')) h = h.slice(4);
  if (!h) return null;
  try {
    const ascii = domainToASCII(h);
    if (ascii) h = ascii.toLowerCase();
  } catch (_) {
    /* fall through; HOST_RE below will reject anything still non-ASCII */
  }
  if (net.isIP(h)) return null; // IPv4/IPv6 literal
  if (h.length > MAX_HOST_LEN) return null;
  const labels = h.split('.').filter(Boolean);
  if (labels.length < 2) return null; // bare TLD / single label
  if (!HOST_RE.test(h)) return null;
  return h;
}

// ---------------------------------------------------------------------------
// Registrable-domain helper, preserved from pipeline v1 per Task B1 brief
// ("Preserve what's good: registrable-domain helpers"). NOT used on the main
// v2 emit path — the digest explicitly forbids eTLD+1 collapsing for
// set40.bin/warn40.bin/exact shards, since it would merge unrelated tenants
// on shared hosting into one rule. Kept here (tested) for any future
// grouping/reporting use and because collapsing full-hostname records down
// to a registrable domain is still useful when deciding how many *distinct
// organizations* a source touches.
// ---------------------------------------------------------------------------
const MULTI_LABEL_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'me.uk', 'net.uk', 'ltd.uk', 'plc.uk', 'ac.uk', 'gov.uk', 'sch.uk', 'nhs.uk',
  'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp',
  'com.sg', 'edu.sg', 'gov.sg', 'net.sg', 'org.sg',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'id.au',
  'com.my', 'net.my', 'org.my', 'edu.my', 'gov.my',
  'co.in', 'net.in', 'org.in', 'ac.in', 'edu.in', 'gov.in', 'res.in',
  'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br',
  'com.mx', 'org.mx', 'gob.mx', 'edu.mx',
  'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz',
  'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr',
  'com.hk', 'net.hk', 'org.hk', 'edu.hk', 'gov.hk',
  'co.kr', 'ne.kr', 'or.kr', 'go.kr', 'ac.kr',
  'com.tw', 'net.tw', 'org.tw', 'edu.tw', 'gov.tw',
  'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za',
  'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'edu.ar',
  'com.sa', 'net.sa', 'org.sa', 'gov.sa', 'edu.sa',
  'com.eg', 'net.eg', 'org.eg', 'gov.eg', 'edu.eg',
  'co.th', 'in.th', 'or.th', 'ac.th', 'go.th',
  'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
  'com.vn', 'net.vn', 'org.vn', 'gov.vn', 'edu.vn',
  'co.id', 'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn',
  'com.pk', 'com.bd', 'com.ng', 'co.ke',
  'co.il', 'org.il', 'ac.il', 'gov.il',
  'com.ua', 'com.co', 'com.pe', 'com.cl', 'com.ec', 'com.uy',
  'com.ve', 'co.ve', 'com.do', 'com.gt', 'co.cr', 'com.pa', 'com.py', 'com.bo',
  'com.kw', 'com.qa', 'com.bh', 'com.om', 'com.jo', 'com.lb',
  'com.lk', 'com.np', 'com.kh', 'com.mm'
]);
const GENERIC_SECOND_LEVELS = new Set([
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'co', 'ac', 'go', 'ne', 'or',
  'gob', 'govt', 'sch', 'id', 'me', 'ltd', 'plc', 'nhs', 'res', 'in', 'web'
]);
const IP4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

function registrableDomain(host) {
  const h = String(host || '').toLowerCase().replace(/\.+$/, '');
  const labels = h.split('.').filter(Boolean);
  if (IP4_RE.test(h) || labels.length <= 1) return h;
  const lastTwo = labels.slice(-2).join('.');
  if (labels.length >= 3 && (
    MULTI_LABEL_SUFFIXES.has(lastTwo) ||
    (labels[labels.length - 1].length === 2 && GENERIC_SECOND_LEVELS.has(labels[labels.length - 2]))
  )) return labels.slice(-3).join('.');
  return lastTwo;
}

/**
 * True if `host` is exactly `allowedSuffix` or a subdomain of it. Used by
 * the allowlist gate — Tranco/whitelist/brand entries are already
 * registrable domains, so a simple label-boundary suffix check is enough
 * without any public-suffix-list awareness.
 */
function isSubdomainOrSelf(host, allowedSuffix) {
  return host === allowedSuffix || host.endsWith('.' + allowedSuffix);
}

module.exports = {
  normalizeHost,
  stripScheme,
  registrableDomain,
  isSubdomainOrSelf,
  MULTI_LABEL_SUFFIXES,
  GENERIC_SECOND_LEVELS,
};
