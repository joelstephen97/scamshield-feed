#!/usr/bin/env node
'use strict';
// scripts/build-hot.js — hourly "hot list": hosts first seen in the last 48 h
// across the FAST licence-vetted sources only. Output hot.json (+ hot-state.json
// + hot-baseline.bloom) on the orphan branch `hot`. See README "Hot list".
const fs = require('fs'); const path = require('path');
const { sources, handBrandList } = require('../sources');
const { normalizeHost } = require('../lib/normalize');
const { buildAllowlist, isAllowed } = require('../lib/gate');
const { fetchTrancoTop, DEFAULT_TOP_N } = require('../lib/tranco');
const bloomLib = require('../lib/bloom');

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

// Baseline Bloom filter (hot-baseline.bloom): every host that has EVER
// graduated out of the 48 h `seen` window (Task 5 fix round 2) — sized once
// for a generous fixed capacity so the file never needs resizing across its
// append-only lifetime. See lib/bloom.js for the file format / index math
// (shared with nrd.bloom); we reuse it rather than inventing a second Bloom
// implementation.
const BLOOM_CAPACITY = 2000000;
const BLOOM_P = 0.001;

function newBloomState() {
  const { mBits, k } = bloomLib.optimalParams(BLOOM_CAPACITY, BLOOM_P);
  return { mBits, k, bits: bloomLib.createBitArray(mBits), n: 0 };
}
function bloomHas(b, host) { return bloomLib.testHost(b.bits, b.mBits, b.k, host); }
function bloomAdd(b, host) { bloomLib.addHost(b.bits, b.mBits, b.k, host); b.n += 1; }

function buildHot({ sources: srcSets, paths, allow, prevState, prevBloom, now }) {
  const nowMin = Math.floor(now / 60000);
  // `tags` persists the last known source tag per host across runs (not
  // part of the documented seen/absent/counts contract, purely additive)
  // so a total source outage (see below) can still label previously-known
  // hosts in the emitted domains[] instead of inventing a fake tag.
  const state = { seen: Object.assign({}, prevState.seen || {}), absent: Object.assign({}, prevState.absent || {}), counts: {}, tags: Object.assign({}, prevState.tags || {}) };
  // The bloom is append-only: reuse the previous file's own bits/params if
  // one loaded successfully, otherwise start a fresh empty bit array sized
  // for BLOOM_CAPACITY @ BLOOM_P. A missing/corrupt bloom (no `prevBloom`)
  // means there is no baseline to compare against — see the bootstrap
  // branch below.
  const bloomState = prevBloom
    ? { mBits: prevBloom.mBits, k: prevBloom.k, bits: Buffer.from(prevBloom.bits), n: prevBloom.n || 0 }
    : newBloomState();
  const bootstrap = !prevBloom;

  const rejected = [];
  const present = new Map(); // host -> first source tag, this run's union
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

  const outPaths = (paths || [])
    .filter((p) => SHARED_PATH_HOSTS.has(p.h) || !isAllowed(p.h, allow))
    .map((p) => ({ h: p.h, p: p.p, s: p.s, t: nowMin })).slice(0, PATH_CAP);

  if (bootstrap) {
    // No baseline bloom exists — either a genuine first-ever run, or we are
    // migrating a deployment whose `seen` grew unbounded before this fix
    // (see README "Hot list" migration note). Either way there is nothing
    // safe to diff against: fold everything we currently know about —
    // whatever was already in `seen` UNION everything present this run —
    // straight into the baseline bloom, reset seen/absent/tags to empty,
    // and emit no domains this run. From the next run on, only hosts
    // absent from both `seen` and this baseline count as genuinely new.
    for (const h of Object.keys(state.seen)) bloomAdd(bloomState, h);
    for (const h of present.keys()) bloomAdd(bloomState, h);
    console.error('[hot] bootstrap: baseline recorded, no domains emitted');
    const hot = { v: 1, generatedAt: now, ttlMinutes: TTL_MINUTES, domains: [], paths: outPaths, removed: [] };
    return { hot, state: { seen: {}, absent: {}, counts: state.counts, tags: {} }, rejected, bloom: bloomState };
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

  // Membership test order for each host present this run: already in
  // `seen` -> keep its original first-seen t; else already graduated into
  // the baseline bloom -> old, skip (a Bloom cannot forget, so a host that
  // disappears and later reappears is treated as old — accepted); else ->
  // genuinely new, t = now.
  for (const h of present.keys()) {
    if (state.seen[h] != null) { delete state.absent[h]; continue; }
    if (bloomHas(bloomState, h)) continue;
    state.seen[h] = nowMin;
    state.tags[h] = present.get(h);
  }

  const removed = [];
  if (!outage) {
    for (const h of Object.keys(state.seen)) {
      if (present.has(h)) continue;
      state.absent[h] = (state.absent[h] || 0) + 1;
      if (state.absent[h] >= 2) { removed.push(h); delete state.seen[h]; delete state.absent[h]; delete state.tags[h]; }
    }
  }

  // Graduation: any host that has aged out of the 48 h window — whether
  // still present this run or not — moves out of `seen` (and its
  // absent/tags bookkeeping) into the append-only baseline bloom, so `seen`
  // stays bounded (a few thousand in-window hosts) instead of growing
  // forever with every host any source has ever mentioned.
  for (const h of Object.keys(state.seen)) {
    if (state.seen[h] < nowMin - WINDOW_MIN) {
      bloomAdd(bloomState, h);
      delete state.seen[h]; delete state.absent[h]; delete state.tags[h];
    }
  }

  // `seen` now only holds in-window hosts (graduation above already pruned
  // anything older), so no extra window filter is needed here.
  const domainHosts = outage ? Object.keys(state.seen) : [...present.keys()].filter((h) => state.seen[h] != null);
  const domains = domainHosts.map((h) => ({ h, s: present.get(h) || state.tags[h] || 'unk', t: state.seen[h] }))
    .sort((a, b) => b.t - a.t).slice(0, HOT_CAP);

  const hot = { v: 1, generatedAt: now, ttlMinutes: TTL_MINUTES, domains, paths: outPaths, removed: removed.sort() };
  return { hot, state, rejected, bloom: bloomState };
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
  const bloomPath = path.resolve('hot-baseline.bloom');
  const prevState = fs.existsSync(statePath) ? JSON.parse(fs.readFileSync(statePath, 'utf8')) : { seen: {}, absent: {}, counts: {}, tags: {} };
  let prevBloom = null;
  if (fs.existsSync(bloomPath)) {
    try { prevBloom = bloomLib.parseBloomFile(fs.readFileSync(bloomPath)); }
    catch (e) { console.error(`[hot] baseline bloom unreadable (${e.message}) — rebuilding as bootstrap`); prevBloom = null; }
  }
  const { hot, state, rejected, bloom } = buildHot({ sources: srcSets, paths, allow, prevState, prevBloom, now });
  fs.writeFileSync('hot.json', JSON.stringify(hot));
  fs.writeFileSync(statePath, JSON.stringify(state));
  fs.writeFileSync(bloomPath, bloomLib.serializeBloomFile({ n: bloom.n, mBits: bloom.mBits, k: bloom.k, bits: bloom.bits }));
  console.log(`[hot] domains=${hot.domains.length} paths=${hot.paths.length} removed=${hot.removed.length} rejected=${rejected.join(',') || '-'} bytes=${fs.statSync('hot.json').size}`);
}
if (require.main === module) main().catch((e) => { console.error(e); process.exit(1); });
module.exports = { buildHot, HOT_CAP, PATH_CAP, WINDOW_MIN, HOT_SOURCE_KEYS, BLOOM_CAPACITY, BLOOM_P };
