'use strict';
/**
 * Allowlist gate: subtract Tranco top-100k union MetaMask whitelist union a
 * hand-curated brand list. Every entry in the union is already a
 * registrable domain, so testing "is host equal to, or a subdomain of, one
 * of these" needs no public-suffix-list awareness — just a label-boundary
 * suffix walk.
 *
 * Exception: shared-hosting / tenant platforms. `vercel.app`,
 * `pages.dev`, `blogspot.com` and friends are themselves Tranco top-100k,
 * so a plain suffix walk allowlists EVERY tenant under them — which is
 * exactly where a large share of live phishing kits are hosted. Those
 * apexes are listed in SHARED_HOST_APEXES: the apex itself stays
 * allowlisted (the platform's own marketing site is not a scam), but a
 * tenant beneath it is never allowlisted by its platform. A tenant host
 * that is explicitly listed in the allowlist in its own right still wins.
 */

// Shared-hosting / tenant-platform apexes. A host BELOW one of these is
// never allowlisted purely because its platform apex is popular.
const SHARED_HOST_APEXES = new Set([
  'vercel.app',
  'netlify.app',
  'pages.dev',
  'workers.dev',
  'github.io',
  'gitlab.io',
  'web.app',
  'firebaseapp.com',
  'azurewebsites.net',
  'web.core.windows.net',
  'blob.core.windows.net',
  'backblazeb2.com',
  'r2.dev',
  'surge.sh',
  'glitch.me',
  'repl.co',
  'replit.app',
  'weebly.com',
  'wixsite.com',
  'blogspot.com',
  'wordpress.com',
  'godaddysites.com',
  'square.site',
  'systeme.io',
  'carrd.co',
  'strikingly.com',
  'duckdns.org',
  'zya.me',
  'eu.cc',
  'hstn.me',
  'fwh.is',
  '000webhostapp.com',
  'ngrok-free.app',
  'ngrok.io',
  'ngrok.app',
  'trycloudflare.com',
  'onrender.com',
  'fly.dev',
  'herokuapp.com',
  'koyeb.app',
  'railway.app',
  'webflow.io',
  'gitbook.io',
  'amplifyapp.com',
  'filesusr.com',
  'contentstack.com',
  'mystrikingly.com',
  'my.canva.site',
  'notion.site',
  'pantheonsite.io',
  'wpengine.com',
  'kinsta.cloud',
  'cloudfront.net',
  's3.amazonaws.com',
  'amazonaws.com',
  'googleusercontent.com',
  'appspot.com',
  'ipfs.io',
  'ipfs.dweb.link',
]);

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
    const candidate = labels.slice(i).join('.');
    if (!allowlistSet.has(candidate)) continue;
    // First allowlist hit decides. At i === 0 the host itself is listed, so
    // it is allowed no matter what. Above that, a hit on a shared-hosting
    // apex means "this is a tenant of a popular platform", which is not a
    // reason to trust the tenant — refuse.
    if (i === 0) return true;
    return !SHARED_HOST_APEXES.has(candidate);
  }
  return false;
}

// Publish tripwire filter (0.15.0): split hosts into kept vs. Tranco-popular.
// Pure and non-throwing on purpose: the hot/daily builds run unattended, and
// one bad upstream entry must be dropped and counted, never fail the build.
// Uses the gate's own rule, so a tenant of a shared-hosting apex is kept.
function dropPopular(hosts, tranco) {
  const kept = [];
  const dropped = [];
  for (const h of hosts) (isAllowed(String(h).toLowerCase(), tranco) ? dropped : kept).push(h);
  return { kept, dropped };
}

// Explicit exclusions (data/exclusions.txt): EXACT host match only (www. is
// folded), deliberately not the subdomain walk of isAllowed. A legitimate
// domain can still have a genuinely compromised subdomain serving phish, and
// that must keep being listed. Returns { kept, dropped }.
function dropExcluded(hosts, exclusions) {
  const kept = [];
  const dropped = [];
  for (const h of hosts) {
    const s = String(h).toLowerCase();
    (exclusions.has(s) || exclusions.has(s.replace(/^www./, '')) ? dropped : kept).push(h);
  }
  return { kept, dropped };
}

// Wide-band corroboration rule: a Tranco top-1M domain whose ONLY upstream
// listing comes from a distrusted single source (Phishing.Database: an
// automated crawler feed, 2026-10-23 audit found ~20% of its top-1M hits were
// legitimate, e.g. lifeatspotify.com) is not published unless a second source
// corroborates it. Exact-host match only, so a tenant of a ranked apex (a
// subdomain, or a path on a shared host) is never touched. Mutates `scored`
// (Map host -> { sources:Set, tier }) and returns the dropped hosts.
const UNCORROBORATED_DISTRUSTED = new Set(['phishing-database']);
function dropUncorroborated(scored, wideTranco, distrusted = UNCORROBORATED_DISTRUSTED) {
  const dropped = [];
  for (const [host, entry] of scored) {
    if (entry.sources.size !== 1) continue;
    const only = entry.sources.values().next().value;
    if (!distrusted.has(only)) continue;
    const bare = host.startsWith('www.') ? host.slice(4) : host;
    if (wideTranco.has(host) || wideTranco.has(bare)) dropped.push(host);
  }
  for (const h of dropped) scored.delete(h);
  return dropped;
}

module.exports = { buildAllowlist, isAllowed, dropPopular, dropExcluded, dropUncorroborated, UNCORROBORATED_DISTRUSTED, SHARED_HOST_APEXES };
