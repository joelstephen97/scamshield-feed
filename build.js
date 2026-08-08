#!/usr/bin/env node
/**
 * ScamShield threat-feed builder.
 *
 * Pulls live phishing/malware-distribution URLs from OpenPhish (community
 * feed) and URLhaus (abuse.ch), reduces them to registrable-domain block
 * rules, drops anything in the Tranco top-10k (false-positive guard for
 * compromised-but-legitimate big sites), dedupes, caps, and emits
 * blocklist.json in the format ScamShield's OTA updater consumes:
 *
 *   { "version": <days-since-epoch>, "rules": ["||evil.example^", ...] }
 *
 * Only public, redistribution-friendly sources are used. Nothing about any
 * user ever touches this pipeline — it is a build-time artifact.
 *
 * Usage:
 *   node build.js                     # writes ./blocklist.json (cap 5000)
 *   node build.js --snapshot out.json # writes a static DNR ruleset (cap 500)
 *                                     # for bundling inside the extension
 */
'use strict';
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

const OPENPHISH_URL = 'https://openphish.com/feed.txt';
const URLHAUS_URL = 'https://urlhaus.abuse.ch/downloads/csv_online/';
const TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip';
const FEED_CAP = 5000;
const SNAPSHOT_CAP = 500;

// Two-label public suffixes — mirror of the extension's MULTI_LABEL_SUFFIXES.
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
const IP4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;

// Shared/free hosting where one bad tenant must not block the whole platform.
// Rules for these registrable domains keep the full hostname instead.
const SHARED_HOSTS = new Set([
  'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'netlify.app',
  'vercel.app', 'github.io', 'gitlab.io', 'blogspot.com', 'wordpress.com',
  'weebly.com', 'wixsite.com', 'glitch.me', 'repl.co', 'onrender.com',
  'herokuapp.com', 'surge.sh', 'neocities.org', 'webflow.io', 'square.site',
  'godaddysites.com', 'hstn.me', 'rf.gd', '000webhostapp.com', 'duckdns.org',
  'ngrok-free.app', 'trycloudflare.com', 'r2.dev', 'amplifyapp.com',
  'azurewebsites.net', 'cloudfront.net', 'amazonaws.com', 'windows.net',
  'googleusercontent.com', 'appspot.com', 'cprapid.com'
]);

// Gateways where abusive content lives in the PATH, not the hostname
// (ipfs.io/ipfs/<cid>). Hostname-level blocking would kill the whole legit
// gateway and URL-level rules go stale in hours — skip these entirely.
const PATH_SHARED = new Set([
  'ipfs.io', 'cf-ipfs.com', 'cloudflare-ipfs.com', 'dweb.link', 'w3s.link',
  'nftstorage.link', 'pinata.cloud', '4everland.io', 'fleek.co',
  'archive.org', 'drive.google.com', 'docs.google.com', 'dropbox.com'
]);

// Generic second-level labels: if an unlisted ccTLD uses one of these as its
// second level (roblox.com.bn), fall back to a three-label registrable rather
// than emitting a rule for the whole "com.bn" suffix.
const GENERIC_SECOND_LEVELS = new Set([
  'com', 'net', 'org', 'edu', 'gov', 'mil', 'co', 'ac', 'go', 'ne', 'or',
  'gob', 'govt', 'sch', 'id', 'me', 'ltd', 'plc', 'nhs', 'res', 'in', 'web'
]);

function registrableDomain(host) {
  const h = String(host || '').toLowerCase().replace(/\.+$/, '');
  const labels = h.split('.').filter(Boolean);
  if (IP4_RE.test(h) || labels.length <= 1) return h;
  const lastTwo = labels.slice(-2).join('.');
  if (labels.length >= 3 && (
    MULTI_LABEL_SUFFIXES.has(lastTwo) ||
    // Unlisted ccTLD with a generic second level ("com.bn"): assume suffix.
    (labels[labels.length - 1].length === 2 && GENERIC_SECOND_LEVELS.has(labels[labels.length - 2]))
  )) return labels.slice(-3).join('.');
  return lastTwo;
}

function hostOf(url) {
  try { return new URL(url.trim()).hostname.toLowerCase(); } catch (_) { return null; }
}

async function fetchText(url) {
  const res = await fetch(url, { headers: { 'user-agent': 'scamshield-feed-builder' } });
  if (!res.ok) throw new Error(`${url} -> HTTP ${res.status}`);
  return res.text();
}

async function fetchTrancoTop(n) {
  const res = await fetch(TRANCO_URL, { redirect: 'follow' });
  if (!res.ok) throw new Error(`tranco -> HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  // The zip contains a single top-1m.csv (rank,domain). Minimal zip parse:
  // find the deflated entry via the local file header and inflate it.
  const nameLen = buf.readUInt16LE(26);
  const extraLen = buf.readUInt16LE(28);
  const method = buf.readUInt16LE(8);
  const dataStart = 30 + nameLen + extraLen;
  const raw = buf.subarray(dataStart);
  const csv = method === 0 ? raw.toString('utf8') : zlib.inflateRawSync(raw).toString('utf8');
  const top = new Set();
  for (const line of csv.split('\n')) {
    const [, domain] = line.trim().split(',');
    if (domain) top.add(domain.toLowerCase());
    if (top.size >= n) break;
  }
  return top;
}

function parseUrlhausCsv(csv) {
  // columns: id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter
  const urls = [];
  for (const line of csv.split('\n')) {
    if (!line || line.startsWith('#')) continue;
    const m = line.match(/^"?\d+"?,"?[^",]+"?,"([^"]+)"/);
    if (m) urls.push(m[1]);
  }
  return urls;
}

async function main() {
  const snapshotIdx = process.argv.indexOf('--snapshot');
  const snapshotOut = snapshotIdx > -1 ? process.argv[snapshotIdx + 1] : null;

  console.log('Downloading sources…');
  const [openphish, urlhausCsv, tranco] = await Promise.all([
    fetchText(OPENPHISH_URL),
    fetchText(URLHAUS_URL),
    fetchTrancoTop(10000)
  ]);

  const sources = [
    // OpenPhish first: live phishing beats older malware URLs when capping.
    ...openphish.split('\n'),
    ...parseUrlhausCsv(urlhausCsv)
  ];

  const rules = [];
  const seen = new Set();
  let droppedTranco = 0;
  for (const raw of sources) {
    const host = hostOf(raw);
    if (!host || host === 'localhost') continue;
    const reg = registrableDomain(host);
    if (PATH_SHARED.has(reg) || PATH_SHARED.has(host)) continue; // path-scoped gateways: unblockable by host
    if (tranco.has(reg)) { droppedTranco++; continue; } // FP guard: never block top sites
    // On shared hosting block only the exact hostname; otherwise the domain.
    const target = SHARED_HOSTS.has(reg) ? host : reg;
    if (tranco.has(target)) { droppedTranco++; continue; }
    if (seen.has(target)) continue;
    seen.add(target);
    rules.push('||' + target + '^');
    if (rules.length >= FEED_CAP) break;
  }

  const version = Math.floor(Date.now() / 86400000); // days since epoch: bumps daily
  console.log(`Kept ${rules.length} rules (dropped ${droppedTranco} Tranco-top-10k hits).`);

  if (snapshotOut) {
    // Static DNR ruleset bundled inside the extension. Rule id 1 stays the
    // manual smoke-test domain; real rules follow.
    const dnr = [{
      id: 1, priority: 1, action: { type: 'block' },
      condition: { urlFilter: '||scamshield-test-blocked.example^', resourceTypes: ['main_frame', 'sub_frame'] }
    }];
    rules.slice(0, SNAPSHOT_CAP).forEach((r, i) => dnr.push({
      id: i + 2, priority: 1, action: { type: 'block' },
      condition: { urlFilter: r, resourceTypes: ['main_frame', 'sub_frame'] }
    }));
    fs.writeFileSync(snapshotOut, JSON.stringify(dnr, null, 2) + '\n');
    console.log(`Wrote static snapshot (${dnr.length} rules) to ${snapshotOut}`);
    return;
  }

  const out = { version, generated: new Date().toISOString(), rules };
  const dest = path.join(__dirname, 'blocklist.json');
  fs.writeFileSync(dest, JSON.stringify(out, null, 1) + '\n');
  console.log(`Wrote ${dest} (version ${version}, ${rules.length} rules).`);
}

main().catch((e) => { console.error(e); process.exit(1); });
