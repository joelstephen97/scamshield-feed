'use strict';
/**
 * Legacy root blocklist.json — SAME format/path as pipeline v1
 * ({ version, rules: ["||domain^"] }, cap 5000, highest-confidence slice).
 * Pre-0.9 installs poll this file forever, so its shape is sacred.
 */
const CAP = 5000;
const DAY_MS = 86400000;

function buildLegacyBlocklist(scored, { cap = CAP, now = Date.now() } = {}) {
  const blockHosts = [];
  for (const [host, entry] of scored) {
    if (entry.tier === 'block') blockHosts.push([host, entry.sources.size]);
  }
  // Highest-confidence (most corroborating sources) first, then alpha for
  // determinism among ties.
  blockHosts.sort((a, b) => {
    if (b[1] !== a[1]) return b[1] - a[1];
    return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
  });
  const rules = blockHosts.slice(0, cap).map(([host]) => `||${host}^`);
  const version = Math.floor(now / DAY_MS); // days-since-epoch, matches v1
  return { version, rules };
}

module.exports = { buildLegacyBlocklist, CAP };
