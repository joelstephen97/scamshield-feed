#!/usr/bin/env node
'use strict';
// scripts/build-hot.js — hourly "hot list": hosts first seen in the last 48 h
// across the FAST licence-vetted sources only. Output hot.json (+ hot-state.json)
// on the orphan branch `hot`. See README "Hot list".
const fs = require('fs'); const path = require('path');
const { sources, handBrandList } = require('../sources');
const { normalizeHost } = require('../lib/normalize');
const { buildAllowlist, isAllowed } = require('../lib/gate');
const { fetchTrancoTop, DEFAULT_TOP_N } = require('../lib/tranco');

// Exact `key` values from sources.js — confirmed 2026-09-07 against the
// registry (metamask + malware-filter + hagezi-tif keys differ from their
// short names: 'metamask-eth-phishing', 'malware-filter-phishing',
// 'hagezi-tif-medium').
const HOT_SOURCE_KEYS = ['phishdestroy', 'metamask-eth-phishing', 'phishing-database', 'malware-filter-phishing', 'hagezi-tif-medium'];
const TAG = { phishdestroy: 'pd', 'metamask-eth-phishing': 'mm', 'phishing-database': 'pdb', 'malware-filter-phishing': 'mf', 'hagezi-tif-medium': 'hz' };
const HOT_CAP = 4000; const PATH_CAP = 300; const WINDOW_MIN = 48 * 60; const GROWTH_GUARD = 0.25; const TTL_MINUTES = 360;
const PDB_LINKS = 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-NEW-today.txt';
// Hosts where badness is path-scoped: the host is Tranco-allowlisted, the path is not.
const SHARED_PATH_HOSTS = new Set(['sites.google.com', 'docs.google.com', 'drive.google.com', 'forms.office.com', 'rb.gy', 'beacons.ai', 'linktr.ee', 'scan.page', 'scanned.page', 'shorten.is', 'ln.run', 'notion.site']);

function buildHot({ sources: srcSets, paths, allow, prevState, now }) {
  const nowMin = Math.floor(now / 60000);
  // `tags` persists the last known source tag per host across runs (not
  // part of the documented seen/absent/counts contract, purely additive)
  // so a total source outage (see below) can still label previously-known
  // hosts in the emitted domains[] instead of inventing a fake tag.
  const state = { seen: Object.assign({}, prevState.seen || {}), absent: Object.assign({}, prevState.absent || {}), counts: {}, tags: Object.assign({}, prevState.tags || {}) };
  const rejected = [];
  const present = new Map(); // host -> first source tag
  for (const key of Object.keys(srcSets)) {
    const set = srcSets[key]; state.counts[key] = set.size;
    const prevCount = prevState.counts && prevState.counts[key];
    if (prevCount && set.size > prevCount * (1 + GROWTH_GUARD)) { rejected.push(key); continue; }
    for (const h of set) {
      // Reuse lib/gate.js's isAllowed() — a full suffix walk — instead of a
      // single registrable-domain check, so an allowlist entry that is
      // itself an intermediate sub-domain (e.g. only "mail.google.com" is
      // listed) still protects a deeper sub-domain like
      // "evil.mail.google.com" the way build.js's own gate does.
      if (isAllowed(h, allow)) continue;
      if (!present.has(h)) present.set(h, TAG[key] || key);
    }
  }
  // A total outage — every source failed to fetch, or every source that DID
  // fetch was rejected by the growth guard above — means `present` carries
  // no signal at all this run. Treat that as "no information", not "every
  // host disappeared": skip the absent/removed bookkeeping entirely so two
  // consecutive bad hours don't evict the whole list into `removed`, and
  // fall back to re-emitting the previously-known, still-in-window hosts
  // from `state.seen` so `domains` doesn't go blank for one bad run.
  const contributed = Object.keys(srcSets).length - rejected.length;
  const outage = contributed === 0;
  for (const h of present.keys()) {
    if (state.seen[h] == null) state.seen[h] = nowMin;
    state.tags[h] = present.get(h);
    delete state.absent[h];
  }
  const removed = [];
  if (!outage) {
    for (const h of Object.keys(state.seen)) {
      if (present.has(h)) continue;
      state.absent[h] = (state.absent[h] || 0) + 1;
      if (state.absent[h] >= 2) { removed.push(h); delete state.seen[h]; delete state.absent[h]; delete state.tags[h]; }
    }
  }
  const domainHosts = outage ? Object.keys(state.seen) : [...present.keys()];
  const domains = domainHosts.map((h) => ({ h, s: present.get(h) || state.tags[h], t: state.seen[h] }))
    .filter((d) => d.t >= nowMin - WINDOW_MIN).sort((a, b) => b.t - a.t).slice(0, HOT_CAP);
  const outPaths = (paths || [])
    .filter((p) => SHARED_PATH_HOSTS.has(p.h) || !isAllowed(p.h, allow))
    .map((p) => ({ h: p.h, p: p.p, s: p.s, t: nowMin })).slice(0, PATH_CAP);
  const hot = { v: 1, generatedAt: now, ttlMinutes: TTL_MINUTES, domains, paths: outPaths, removed: removed.sort() };
  return { hot, state, rejected };
}

async function fetchText(url) { const r = await fetch(url, { headers: { 'user-agent': 'scamshield-feed hot builder' } }); if (!r.ok) throw new Error(url + ' -> ' + r.status); return r.text(); }
function hostsFromList(text) { const out = new Set(); for (const raw of text.split('\n')) { const l = raw.trim(); if (!l || l.startsWith('#') || l.startsWith('!')) continue; const h = normalizeHost(l.replace(/^\|\|/, '').replace(/\^.*$/, '')); if (h) out.add(h); } return out; }
function pathsFromLinks(text) {
  const out = [];
  for (const raw of text.split('\n')) { let u; try { u = new URL(raw.trim()); } catch (_) { continue; } const h = normalizeHost(u.hostname); if (!h || !SHARED_PATH_HOSTS.has(h)) continue; const p = u.pathname.replace(/\/+$/, ''); if (p.length > 1 && p.length <= 200) out.push({ h, p, s: 'pdb' }); }
  return out;
}

async function main() {
  const now = Date.now();
  const registry = Object.fromEntries(sources.map((s) => [s.key, s]));
  const srcSets = {};
  for (const key of HOT_SOURCE_KEYS) {
    const s = registry[key]; if (!s || s.enabled === false) continue;
    try {
      const text = await fetchText(s.hotUrl || s.url);
      srcSets[key] = key === 'metamask-eth-phishing' ? new Set((JSON.parse(text).blacklist || []).map(normalizeHost).filter(Boolean)) : hostsFromList(text);
    } catch (e) { console.error(`[hot] ${key} failed: ${e.message} — skipped`); }
  }
  let paths = []; try { paths = pathsFromLinks(await fetchText(PDB_LINKS)); } catch (e) { console.error('[hot] links failed: ' + e.message); }
  const tranco = await fetchTrancoTop(DEFAULT_TOP_N);
  const allow = buildAllowlist({ tranco, metamaskWhitelist: [], handBrandList });
  const statePath = path.resolve('hot-state.json');
  const prevState = fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, 'utf8')) : { seen: {}, absent: {}, counts: {} };
  const { hot, state, rejected } = buildHot({ sources: srcSets, paths, allow, prevState, now });
  fs.writeFileSync('hot.json', JSON.stringify(hot));
  fs.writeFileSync(statePath, JSON.stringify(state));
  console.log(`[hot] domains=${hot.domains.length} paths=${hot.paths.length} removed=${hot.removed.length} rejected=${rejected.join(',') || '-'} bytes=${fs.statSync('hot.json').size}`);
}
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { buildHot, HOT_CAP, PATH_CAP, WINDOW_MIN, HOT_SOURCE_KEYS };
