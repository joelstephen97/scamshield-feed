'use strict';
/**
 * Allowlist gate: subtract Tranco top-100k union MetaMask whitelist union a
 * hand-curated brand list. Every entry in the union is already a
 * registrable domain, so testing "is host equal to, or a subdomain of, one
 * of these" needs no public-suffix-list awareness — just a label-boundary
 * suffix walk.
 */

function buildAllowlist({ tranco, metamaskWhitelist, handBrandList }) {
  const allow = new Set();
  for (const d of tranco || []) allow.add(String(d).toLowerCase());
  for (const d of metamaskWhitelist || []) allow.add(String(d).toLowerCase());
  for (const d of handBrandList || []) allow.add(String(d).toLowerCase());
  return allow;
}

function isAllowed(host, allowlistSet) {
  const labels = host.split('.');
  // i=0 checks the full host itself; increasing i walks up to parent
  // domains ("evil.mail.google.com" -> "mail.google.com" -> "google.com").
  // Stops one short of the bare TLD, which can never be an allowlist entry.
  for (let i = 0; i < labels.length - 1; i++) {
    if (allowlistSet.has(labels.slice(i).join('.'))) return true;
  }
  return false;
}

module.exports = { buildAllowlist, isAllowed };
