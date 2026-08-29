#!/usr/bin/env node
/**
 * parry-feed pipeline v2 (Task B1).
 *
 * Aggregates ~11 license-vetted phishing/scam-domain feeds (see sources.js),
 * normalizes to full hostnames (no eTLD+1 collapsing — shared hosting must
 * keep the exact abusive hostname), gates against an allowlist, scores each
 * domain into block/warn tiers by source corroboration, and emits the v0.9
 * output contract: meta.json, set40.bin, warn40.bin, delta-<prev>.bin,
 * exact-NN.jsonl.gz shards, risk.json, and the legacy root blocklist.json.
 *
 * Usage:
 *   node build.js                       # real build: fetches live sources,
 *                                        # writes v/current/* + blocklist.json
 *   node build.js --dry-run             # fetches live sources, builds to a
 *                                        # temp dir, prints stats, touches
 *                                        # nothing under version control
 *   node build.js --offline <fixturesDir>  # builds from local fixture files
 *                                        # (used by test/*.js)
 *
 * Node >=20, zero npm dependencies (uses only node: builtins + global fetch).
 */
'use strict';
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');

const { sources, riskTableSources, nrdSources, NRD_WINDOW_DAYS, handBrandList } = require('./sources');
const { normalizeHost } = require('./lib/normalize');
const {
  parseList, parseHosts, parseAdblock, parseJsonArray,
  parseMetamaskConfig, parsePolkadotAllDeny,
} = require('./lib/parsers');
const { fetchTrancoTop, parseTrancoCsv, DEFAULT_TOP_N } = require('./lib/tranco');
const { buildAllowlist, isAllowed } = require('./lib/gate');
const { scoreDomains } = require('./lib/score');
const { buildLegacyBlocklist } = require('./lib/legacy');
const {
  recordFor, shardIndexFor, sortRecords, dedupeSortedRecords,
  concatRecords, bufferToRecords,
} = require('./lib/hash');
const { diffSortedRecords, applyDelta, serializeDelta, deserializeDelta } = require('./lib/delta');
const { buildRiskTable } = require('./lib/riskTables');
const { buildBloom, serializeBloomFile } = require('./lib/bloom');

const SHRINK_GUARD_RATIO = 0.30; // reject a source whose count drops >30%
const LEGACY_CAP = 5000;
const NRD_TARGET_P = 0.005; // target ~0.5% false-positive rate for nrd.bloom

// ---------------------------------------------------------------------------
// Parsing dispatch
// ---------------------------------------------------------------------------
function parseByFormat(format, text) {
  switch (format) {
    case 'list': return { entries: parseList(text) };
    case 'hosts': return { entries: parseHosts(text) };
    case 'adblock': return { entries: parseAdblock(text) };
    case 'json-array': return { entries: parseJsonArray(text) };
    case 'metamask-config': {
      const cfg = parseMetamaskConfig(text);
      return { entries: cfg.blacklist, whitelist: cfg.whitelist };
    }
    case 'polkadot-all-deny': {
      const d = parsePolkadotAllDeny(text);
      return { entries: d.deny };
    }
    default:
      throw new Error(`unknown source format: ${format}`);
  }
}

// ---------------------------------------------------------------------------
// Per-source disk cache (last-good reuse + poisoning-guard baseline)
// ---------------------------------------------------------------------------
function cachePaths(cacheDir, key) {
  return {
    meta: path.join(cacheDir, `${key}.json`),
    data: path.join(cacheDir, `${key}.txt.gz`),
  };
}

function loadSourceCache(cacheDir, key) {
  const { meta, data } = cachePaths(cacheDir, key);
  if (!fs.existsSync(meta) || !fs.existsSync(data)) return null;
  try {
    const metaJson = JSON.parse(fs.readFileSync(meta, 'utf8'));
    const text = zlib.gunzipSync(fs.readFileSync(data)).toString('utf8');
    const domains = new Set(text.split('\n').filter(Boolean));
    return { count: metaJson.count, domains };
  } catch (_) {
    return null;
  }
}

function saveSourceCache(cacheDir, key, domainSet) {
  fs.mkdirSync(cacheDir, { recursive: true });
  const { meta, data } = cachePaths(cacheDir, key);
  const body = Array.from(domainSet).sort().join('\n');
  fs.writeFileSync(data, zlib.gzipSync(Buffer.from(body, 'utf8')));
  fs.writeFileSync(meta, JSON.stringify({ count: domainSet.size, savedAt: new Date().toISOString() }, null, 1) + '\n');
}

// ---------------------------------------------------------------------------
// FETCH + NORMALIZE (+ shrink-poisoning guard + last-good reuse) per source
// ---------------------------------------------------------------------------
async function fetchAndNormalizeSource(source, { offlineDir, cacheDir }) {
  let rawText = null;
  let entries = [];
  let whitelist = [];
  let errorMessage = null;

  try {
    if (offlineDir) {
      rawText = fs.readFileSync(path.join(offlineDir, source.offlineFile), 'utf8');
    } else {
      const res = await fetch(source.url, { headers: { 'user-agent': 'parry-feed-builder' } });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      rawText = await res.text();
    }
    const parsed = parseByFormat(source.format, rawText);
    entries = parsed.entries;
    whitelist = parsed.whitelist || [];
  } catch (e) {
    errorMessage = e.message;
    rawText = null;
  }

  let normalizedSet = null;
  if (rawText != null) {
    normalizedSet = new Set();
    for (const raw of entries) {
      const h = normalizeHost(raw);
      if (h) normalizedSet.add(h);
    }
  }

  const cache = loadSourceCache(cacheDir, source.key);

  let shrinkRejected = false;
  if (normalizedSet && cache && cache.count > 0) {
    const shrinkRatio = 1 - normalizedSet.size / cache.count;
    if (shrinkRatio > SHRINK_GUARD_RATIO) shrinkRejected = true;
  }

  let finalSet;
  let status;
  if (!normalizedSet) {
    if (cache) {
      finalSet = cache.domains;
      status = `fetch/parse failed (${errorMessage}) -> reused last-good cache (${cache.count})`;
    } else {
      finalSet = new Set();
      status = `fetch/parse failed (${errorMessage}), no cache available -> 0 domains`;
    }
  } else if (shrinkRejected) {
    finalSet = cache.domains;
    status = `REJECTED: shrank ${cache.count} -> ${normalizedSet.size} (>30%), poisoning guard -> reused last-good cache`;
  } else {
    finalSet = normalizedSet;
    status = cache ? 'ok' : 'ok (first successful fetch, cache seeded)';
    saveSourceCache(cacheDir, source.key, finalSet);
  }

  return {
    key: source.key,
    name: source.name,
    rawCount: entries.length,
    normalizedCount: normalizedSet ? normalizedSet.size : 0,
    finalSet,
    status,
    whitelist,
  };
}

// ---------------------------------------------------------------------------
// EMIT helpers
// ---------------------------------------------------------------------------
function recordsForTier(scored, tier) {
  const recs = [];
  for (const [host, entry] of scored) {
    if (entry.tier === tier) recs.push(recordFor(host));
  }
  return dedupeSortedRecords(sortRecords(recs));
}

function removeCollisions(warnRecords, blockRecords) {
  const blockKeys = new Set(blockRecords.map((b) => b.toString('hex')));
  return warnRecords.filter((r) => !blockKeys.has(r.toString('hex')));
}

function buildExactShards(scored, sourceMetaByKey) {
  const shards = new Map(); // shardIndex(hex2) -> array of {d,s}
  for (const [host, entry] of scored) {
    const idx = shardIndexFor(host);
    if (!shards.has(idx)) shards.set(idx, []);
    const sourceNames = Array.from(entry.sources)
      .map((key) => (sourceMetaByKey.get(key) || {}).name || key)
      .sort();
    shards.get(idx).push({ d: host, s: sourceNames });
  }
  for (const arr of shards.values()) arr.sort((a, b) => (a.d < b.d ? -1 : a.d > b.d ? 1 : 0));
  return shards;
}

function formatVersion(date) {
  const y = date.getUTCFullYear();
  const m = String(date.getUTCMonth() + 1).padStart(2, '0');
  const d = String(date.getUTCDate()).padStart(2, '0');
  const h = String(date.getUTCHours()).padStart(2, '0');
  return `${y}${m}${d}${h}`;
}

function readPrevState(prevOutDir) {
  const metaPath = path.join(prevOutDir, 'meta.json');
  const setPath = path.join(prevOutDir, 'set40.bin');
  if (!fs.existsSync(metaPath) || !fs.existsSync(setPath)) {
    return { prevVersion: null, prevBlockRecords: [] };
  }
  try {
    const meta = JSON.parse(fs.readFileSync(metaPath, 'utf8'));
    const prevBlockRecords = bufferToRecords(fs.readFileSync(setPath));
    return { prevVersion: meta.version || null, prevBlockRecords };
  } catch (_) {
    return { prevVersion: null, prevBlockRecords: [] };
  }
}

// ---------------------------------------------------------------------------
// Main pipeline (testable — no CLI side effects)
// ---------------------------------------------------------------------------
async function runBuild(opts = {}) {
  const repoRoot = opts.repoRoot || __dirname;
  const offlineDir = opts.offlineDir || null;
  const cacheDir = opts.cacheDir || path.join(repoRoot, 'cache');
  const prevDir = opts.prevDir || repoRoot;
  const writeDir = opts.writeDir || repoRoot;
  const now = opts.now || new Date();
  const trancoTopN = opts.trancoTopN || DEFAULT_TOP_N;

  const stats = { sources: [], riskSources: [], nrdSources: [], gateRemovals: 0, tierSplit: {}, unionSize: 0 };

  // --- Tranco (allowlist gate input) ---
  let tranco;
  if (offlineDir) {
    const csv = fs.readFileSync(path.join(offlineDir, 'tranco.csv'), 'utf8');
    tranco = parseTrancoCsv(csv, trancoTopN);
  } else {
    tranco = await fetchTrancoTop(trancoTopN);
  }

  // --- FETCH + NORMALIZE each enabled blocklist source ---
  const enabledSources = sources.filter((s) => s.enabled !== false);
  const perSourceSets = new Map();
  const sourceMetaByKey = new Map();
  let metamaskWhitelist = [];
  for (const source of enabledSources) {
    const result = await fetchAndNormalizeSource(source, { offlineDir, cacheDir });
    perSourceSets.set(source.key, result.finalSet);
    sourceMetaByKey.set(source.key, source);
    if (source.contributesAllowlist) metamaskWhitelist = result.whitelist;
    stats.sources.push({
      key: source.key, name: source.name, licenseTier: source.licenseTier,
      scoreWeight: source.scoreWeight, rawCount: result.rawCount,
      normalizedCount: result.normalizedCount, keptCount: result.finalSet.size,
      status: result.status,
    });
  }

  // --- ALLOWLIST GATE ---
  const allowlist = buildAllowlist({ tranco, metamaskWhitelist, handBrandList });
  const gatedPerSourceSets = new Map();
  let gateRemovals = 0;
  for (const [key, domainSet] of perSourceSets) {
    const kept = new Set();
    for (const host of domainSet) {
      if (isAllowed(host, allowlist)) gateRemovals++;
      else kept.add(host);
    }
    gatedPerSourceSets.set(key, kept);
  }
  stats.gateRemovals = gateRemovals;
  stats.trancoSize = tranco.size;
  stats.allowlistSize = allowlist.size;

  // --- SCORE ---
  const scored = scoreDomains(gatedPerSourceSets, sourceMetaByKey);
  let blockCount = 0;
  let warnCount = 0;
  for (const entry of scored.values()) {
    if (entry.tier === 'block') blockCount++;
    else warnCount++;
  }
  stats.tierSplit = { block: blockCount, warn: warnCount, total: scored.size };
  stats.unionSize = scored.size;

  // --- RISK TABLES (HaGeZi dyndns/hoster; NOT part of the blocklist union) ---
  const enabledRiskSources = riskTableSources.filter((s) => s.enabled !== false);
  let dyndnsHosts = [];
  let hosterHosts = [];
  for (const rt of enabledRiskSources) {
    const result = await fetchAndNormalizeSource(rt, { offlineDir, cacheDir });
    if (rt.riskKey === 'dyndns') dyndnsHosts = Array.from(result.finalSet);
    else if (rt.riskKey === 'hosters') hosterHosts = Array.from(result.finalSet);
    stats.riskSources.push({
      key: rt.key, name: rt.name, rawCount: result.rawCount,
      normalizedCount: result.normalizedCount, keptCount: result.finalSet.size,
      status: result.status,
    });
  }
  const risk = buildRiskTable(dyndnsHosts, hosterHosts);

  // --- NRD BLOOM FILTER (Task C3): union of HaGeZi's 7-day + 8-14-day
  // windows = a 14-day "newly-registered-domains" signal. MILLIONS of
  // domains, so this never touches the block/warn union or risk.json — it
  // is emitted as its own compact Bloom filter (see lib/bloom.js for the
  // file format and the exact index-derivation spec, mirrored byte-for-byte
  // in the extension's engine/bloom.js). Uses the same
  // fetchAndNormalizeSource() poisoning-guard/cache/continue-on-error
  // machinery as every other source array.
  const enabledNrdSources = nrdSources.filter((s) => s.enabled !== false);
  const nrdHostSet = new Set();
  for (const nsrc of enabledNrdSources) {
    const result = await fetchAndNormalizeSource(nsrc, { offlineDir, cacheDir });
    for (const h of result.finalSet) nrdHostSet.add(h);
    stats.nrdSources.push({
      key: nsrc.key, name: nsrc.name, rawCount: result.rawCount,
      normalizedCount: result.normalizedCount, keptCount: result.finalSet.size,
      status: result.status,
    });
  }
  const nrdBuilt = buildBloom(nrdHostSet, { p: NRD_TARGET_P });
  const nrdBloomBuf = serializeBloomFile(nrdBuilt);
  const sha256Nrd = crypto.createHash('sha256').update(nrdBloomBuf).digest('hex');
  stats.nrdBloom = { n: nrdBuilt.n, mBits: nrdBuilt.mBits, k: nrdBuilt.k, bytes: nrdBloomBuf.length };

  // --- EMIT ---
  const blockRecords = recordsForTier(scored, 'block');
  let warnRecords = recordsForTier(scored, 'warn');
  warnRecords = removeCollisions(warnRecords, blockRecords);

  const prevOutDir = path.join(prevDir, 'v', 'current');
  const { prevVersion, prevBlockRecords } = readPrevState(prevOutDir);
  const delta = diffSortedRecords(prevBlockRecords, blockRecords);
  const deltaBuf = serializeDelta(delta);

  const version = formatVersion(now);
  const set40Buf = concatRecords(blockRecords);
  const warn40Buf = concatRecords(warnRecords);
  const sha256Set40 = crypto.createHash('sha256').update(set40Buf).digest('hex');
  const sha256Warn40 = crypto.createHash('sha256').update(warn40Buf).digest('hex');
  const sha256Delta = prevVersion ? crypto.createHash('sha256').update(deltaBuf).digest('hex') : null;

  const meta = {
    version,
    generatedAt: now.toISOString(),
    counts: { block: blockRecords.length, warn: warnRecords.length, total: scored.size },
    sha256: { set40: sha256Set40, warn40: sha256Warn40, deltaFromPrev: sha256Delta },
    prev: prevVersion,
    urls: {
      cdn: `https://cdn.jsdelivr.net/gh/joelstephen97/scamshield-feed@v${version}/v/current/`,
      fallback: 'https://raw.githubusercontent.com/joelstephen97/scamshield-feed/main/v/current/',
    },
    ttlHours: 6,
    nrd: {
      file: 'nrd.bloom',
      sha256: sha256Nrd,
      n: nrdBuilt.n,
      mBits: nrdBuilt.mBits,
      k: nrdBuilt.k,
      windowDays: NRD_WINDOW_DAYS,
    },
  };

  const legacy = buildLegacyBlocklist(scored, { cap: LEGACY_CAP, now: now.getTime() });
  const shards = buildExactShards(scored, sourceMetaByKey);

  const outDir = path.join(writeDir, 'v', 'current');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'set40.bin'), set40Buf);
  fs.writeFileSync(path.join(outDir, 'warn40.bin'), warn40Buf);
  if (prevVersion) {
    fs.writeFileSync(path.join(outDir, `delta-${prevVersion}.bin`), deltaBuf);
  }
  fs.writeFileSync(path.join(outDir, 'risk.json'), JSON.stringify(risk, null, 1) + '\n');
  fs.writeFileSync(path.join(outDir, 'nrd.bloom'), nrdBloomBuf);
  fs.writeFileSync(path.join(outDir, 'meta.json'), JSON.stringify(meta, null, 1) + '\n');
  for (const [idx, lines] of shards) {
    const jsonl = lines.map((l) => JSON.stringify(l)).join('\n') + '\n';
    fs.writeFileSync(path.join(outDir, `exact-${idx}.jsonl.gz`), zlib.gzipSync(Buffer.from(jsonl, 'utf8')));
  }
  fs.writeFileSync(path.join(writeDir, 'blocklist.json'), JSON.stringify(legacy, null, 1) + '\n');

  return { stats, scored, risk, meta, legacy, outDir, shardCount: shards.size };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------
function printStats(stats) {
  console.log('\nPer-source counts:');
  for (const s of stats.sources) {
    console.log(`  [${s.licenseTier}/${s.scoreWeight}] ${s.name}: raw=${s.rawCount} normalized=${s.normalizedCount} kept=${s.keptCount} (${s.status})`);
  }
  console.log('\nRisk-table sources:');
  for (const s of stats.riskSources) {
    console.log(`  ${s.name}: raw=${s.rawCount} normalized=${s.normalizedCount} kept=${s.keptCount} (${s.status})`);
  }
  console.log('\nNRD (newly-registered-domains) sources:');
  for (const s of stats.nrdSources) {
    console.log(`  ${s.name}: raw=${s.rawCount} normalized=${s.normalizedCount} kept=${s.keptCount} (${s.status})`);
  }
  if (stats.nrdBloom) {
    console.log(`  nrd.bloom: n=${stats.nrdBloom.n} mBits=${stats.nrdBloom.mBits} k=${stats.nrdBloom.k} bytes=${stats.nrdBloom.bytes}`);
  }
  console.log(`\nTranco allowlist size: ${stats.trancoSize} (+ MetaMask whitelist + hand brand list = ${stats.allowlistSize} total)`);
  console.log(`Allowlist gate removals: ${stats.gateRemovals}`);
  console.log(`Union size (post-gate, pre-dedupe-by-hash): ${stats.unionSize}`);
  console.log(`Tier split: block=${stats.tierSplit.block} warn=${stats.tierSplit.warn} total=${stats.tierSplit.total}`);
}

async function main() {
  const args = process.argv.slice(2);
  const dryRun = args.includes('--dry-run');
  const offlineIdx = args.indexOf('--offline');
  const offlineDir = offlineIdx > -1 ? args[offlineIdx + 1] : null;

  const opts = { repoRoot: __dirname };
  if (offlineDir) opts.offlineDir = path.resolve(offlineDir);
  if (dryRun) {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'parry-feed-dryrun-'));
    opts.writeDir = tmp;
    opts.prevDir = __dirname; // compare against real committed state, if any
    console.log(`[dry-run] writing to temp dir: ${tmp} (repo outputs untouched)`);
  }

  const result = await runBuild(opts);
  printStats(result.stats);
  if (dryRun) {
    console.log(`\n[dry-run] complete. Outputs left at ${result.outDir} for inspection; nothing committed.`);
  } else {
    console.log(`\nWrote outputs to ${result.outDir} and ${path.join(opts.writeDir || __dirname, 'blocklist.json')}`);
    console.log(`Version: ${result.meta.version} (prev: ${result.meta.prev || 'none'})`);
  }
}

if (require.main === module) {
  main().catch((e) => {
    console.error(e);
    process.exit(1);
  });
}

module.exports = {
  runBuild,
  parseByFormat,
  fetchAndNormalizeSource,
  loadSourceCache,
  saveSourceCache,
  recordsForTier,
  removeCollisions,
  buildExactShards,
  formatVersion,
  readPrevState,
};
