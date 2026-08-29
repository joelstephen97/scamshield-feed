'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const { runBuild } = require('../build.js');
const { bufferToRecords, recordFor } = require('../lib/hash');

const FIXTURES_BASE = path.join(__dirname, 'fixtures', 'base');
const FIXTURES_SHRUNK = path.join(__dirname, 'fixtures', 'shrunk');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('offline build: scoring, gate, and full-hostname retention are correct end-to-end', async () => {
  const writeDir = tmpDir('parry-feed-it-');
  const cacheDir = tmpDir('parry-feed-cache-');
  const result = await runBuild({
    repoRoot: writeDir,
    offlineDir: FIXTURES_BASE,
    cacheDir,
    prevDir: writeDir,
    writeDir,
    now: new Date('2026-08-29T10:00:00Z'),
  });

  const { scored, stats } = result;

  // Block tier: every tier-1(A) single-source hit, plus the 2-source
  // tier-2(B)+tier-2(B) corroboration case.
  const expectedBlock = [
    'a1-tier1.com', 'wwwstrip-test.com', 'evil.pages.dev',
    'a2-tier1.com', 'a3-tier1.com', 'a4-tier1.com', 'a5-tier1.com', 'a6-tier1.com',
    'shared-warn-promote.com',
  ];
  for (const h of expectedBlock) {
    assert.ok(scored.has(h), `expected ${h} in scored map`);
    assert.equal(scored.get(h).tier, 'block', `expected ${h} to be block-tier`);
  }

  // Warn tier: single tier-2(B) source only.
  const expectedWarn = ['b1-tier2weight.com', 'b2-tier2.com', 'b3-tier2.com', 'b4-tier2.com', 'solo-warn.com'];
  for (const h of expectedWarn) {
    assert.equal(scored.get(h).tier, 'warn', `expected ${h} to be warn-tier`);
  }

  // Gated out entirely (Tranco / MetaMask whitelist) — never in the union.
  assert.equal(scored.has('gate-me.com'), false);
  assert.equal(scored.has('allowed-brand.example'), false);

  // Dropped by NORMALIZE (IP / bare TLD), not by the gate.
  assert.equal(scored.has('192.168.1.1'), false);
  assert.equal(scored.has('justatld'), false);

  // Shared-hosting full hostname is retained; the platform root never appears.
  assert.equal(scored.has('pages.dev'), false);

  assert.equal(stats.tierSplit.block, expectedBlock.length);
  assert.equal(stats.tierSplit.warn, expectedWarn.length);
  assert.equal(stats.tierSplit.total, expectedBlock.length + expectedWarn.length);
  assert.ok(stats.gateRemovals >= 2, 'expected at least gate-me.com and allowed-brand.example removed');
});

test('offline build emits the full output contract with correct shapes', async () => {
  const writeDir = tmpDir('parry-feed-it-');
  const cacheDir = tmpDir('parry-feed-cache-');
  const result = await runBuild({
    repoRoot: writeDir, offlineDir: FIXTURES_BASE, cacheDir, prevDir: writeDir, writeDir,
    now: new Date('2026-08-29T10:00:00Z'),
  });
  const outDir = result.outDir;

  for (const f of ['meta.json', 'set40.bin', 'warn40.bin', 'risk.json']) {
    assert.ok(fs.existsSync(path.join(outDir, f)), `missing ${f}`);
  }
  assert.ok(fs.existsSync(path.join(writeDir, 'blocklist.json')), 'missing legacy blocklist.json at repo root');

  const set40 = fs.readFileSync(path.join(outDir, 'set40.bin'));
  const warn40 = fs.readFileSync(path.join(outDir, 'warn40.bin'));
  assert.equal(set40.length % 5, 0);
  assert.equal(warn40.length % 5, 0);
  assert.equal(set40.length / 5, result.stats.tierSplit.block);
  assert.equal(warn40.length / 5, result.stats.tierSplit.warn);

  // set40.bin must be sorted by the 40-bit value.
  const setRecords = bufferToRecords(set40);
  for (let i = 1; i < setRecords.length; i++) {
    assert.ok(Buffer.compare(setRecords[i - 1], setRecords[i]) < 0, 'set40.bin must be strictly sorted (deduped)');
  }

  // No record appears in both tiers (block wins on hash collisions).
  const setKeys = new Set(setRecords.map((b) => b.toString('hex')));
  for (const r of bufferToRecords(warn40)) assert.equal(setKeys.has(r.toString('hex')), false);

  const meta = JSON.parse(fs.readFileSync(path.join(outDir, 'meta.json'), 'utf8'));
  assert.equal(meta.counts.block, result.stats.tierSplit.block);
  assert.equal(meta.counts.warn, result.stats.tierSplit.warn);
  assert.equal(meta.counts.total, result.stats.tierSplit.total);
  assert.equal(meta.ttlHours, 6);
  assert.ok(meta.urls.cdn.includes('cdn.jsdelivr.net'));
  assert.equal(meta.prev, null); // first run, no prior version

  const risk = JSON.parse(fs.readFileSync(path.join(outDir, 'risk.json'), 'utf8'));
  assert.equal(risk.dyndns.length, 1);
  assert.equal(risk.hosters.length, 1);
  assert.ok(risk.tlds['.top'] >= 1);

  const legacy = JSON.parse(fs.readFileSync(path.join(writeDir, 'blocklist.json'), 'utf8'));
  assert.deepEqual(Object.keys(legacy).sort(), ['rules', 'version']);
  assert.ok(legacy.rules.includes('||a1-tier1.com^'));
  assert.equal(legacy.rules.includes('||b1-tier2weight.com^'), false); // warn-tier excluded

  // Exact shards: every scored domain appears exactly once, in the shard
  // matching the first byte of its hash.
  const shardFiles = fs.readdirSync(outDir).filter((f) => f.startsWith('exact-'));
  assert.equal(shardFiles.length, result.shardCount);
  let totalShardLines = 0;
  for (const f of shardFiles) {
    const idx = f.slice('exact-'.length, f.length - '.jsonl.gz'.length);
    const jsonl = zlib.gunzipSync(fs.readFileSync(path.join(outDir, f))).toString('utf8').trim();
    for (const line of jsonl.split('\n')) {
      const rec = JSON.parse(line);
      totalShardLines++;
      assert.equal(recordFor(rec.d)[0].toString(16).padStart(2, '0'), idx);
      assert.ok(Array.isArray(rec.s) && rec.s.length > 0);
    }
  }
  assert.equal(totalShardLines, result.stats.tierSplit.total);
});

test('identical inputs produce byte-identical set40.bin/warn40.bin/risk.json (deterministic reruns)', async () => {
  const now = new Date('2026-08-29T10:00:00Z');
  const dirA = tmpDir('parry-feed-it-a-');
  const dirB = tmpDir('parry-feed-it-b-');
  const [rA, rB] = await Promise.all([
    runBuild({ repoRoot: dirA, offlineDir: FIXTURES_BASE, cacheDir: tmpDir('cache-a-'), prevDir: dirA, writeDir: dirA, now }),
    runBuild({ repoRoot: dirB, offlineDir: FIXTURES_BASE, cacheDir: tmpDir('cache-b-'), prevDir: dirB, writeDir: dirB, now }),
  ]);
  for (const f of ['set40.bin', 'warn40.bin', 'risk.json', 'meta.json']) {
    const a = fs.readFileSync(path.join(rA.outDir, f));
    const b = fs.readFileSync(path.join(rB.outDir, f));
    assert.equal(Buffer.compare(a, b), 0, `${f} differs between identical reruns`);
  }
});

test('poisoning guard: a source shrinking >30% is rejected and last-good cache is reused', async () => {
  const cacheDir = tmpDir('parry-feed-cache-shrink-');
  const dir1 = tmpDir('parry-feed-it-run1-');
  const dir2 = tmpDir('parry-feed-it-run2-');

  const run1 = await runBuild({
    repoRoot: dir1, offlineDir: FIXTURES_BASE, cacheDir, prevDir: dir1, writeDir: dir1,
    now: new Date('2026-08-29T10:00:00Z'),
  });
  const src1 = run1.stats.sources.find((s) => s.key === 'phishing-database');
  assert.equal(src1.normalizedCount, 3); // a1-tier1.com, wwwstrip-test.com, evil.pages.dev
  assert.equal(src1.keptCount, 3);
  assert.ok(src1.status.startsWith('ok'));

  const run2 = await runBuild({
    repoRoot: dir2, offlineDir: FIXTURES_SHRUNK, cacheDir, prevDir: dir1, writeDir: dir2,
    now: new Date('2026-08-29T16:00:00Z'),
  });
  const src2 = run2.stats.sources.find((s) => s.key === 'phishing-database');
  assert.equal(src2.normalizedCount, 1); // shrunk fixture only has a1-tier1.com
  assert.ok(src2.status.startsWith('REJECTED'), `expected shrink rejection, got: ${src2.status}`);
  assert.equal(src2.keptCount, 3, 'should have fallen back to the cached last-good set, not the shrunk fetch');

  // The rest of the union should still reflect the reused cache, e.g.
  // evil.pages.dev (only ever supplied by phishing-database) survives.
  assert.equal(run2.scored.has('evil.pages.dev'), true);
});

test('delta-<prevVersion>.bin correctly reflects a new domain appearing between runs', async () => {
  const cacheDir = tmpDir('parry-feed-cache-delta-');
  const dirA = tmpDir('parry-feed-it-deltaA-');
  const dirB = tmpDir('parry-feed-it-deltaB-');

  const run1 = await runBuild({
    repoRoot: dirA, offlineDir: FIXTURES_BASE, cacheDir, prevDir: dirA, writeDir: dirA,
    now: new Date('2026-08-29T10:00:00Z'),
  });

  // Second fixture set: base + one brand-new tier-1 domain.
  const fixturesDelta = tmpDir('parry-feed-fixtures-delta-');
  for (const f of fs.readdirSync(FIXTURES_BASE)) {
    fs.copyFileSync(path.join(FIXTURES_BASE, f), path.join(fixturesDelta, f));
  }
  fs.appendFileSync(path.join(fixturesDelta, 'phishdestroy.txt'), 'brand-new-domain.example\n');

  const run2 = await runBuild({
    repoRoot: dirB, offlineDir: fixturesDelta, cacheDir, prevDir: dirA, writeDir: dirB,
    now: new Date('2026-08-29T16:00:00Z'),
  });

  assert.equal(run2.meta.prev, run1.meta.version);
  const deltaPath = path.join(run2.outDir, `delta-${run1.meta.version}.bin`);
  assert.ok(fs.existsSync(deltaPath), 'expected a delta file named after the previous version');
  const { deserializeDelta, applyDelta } = require('../lib/delta');
  const { bufferToRecords: toRecords } = require('../lib/hash');
  const deltaBuf = fs.readFileSync(deltaPath);
  const delta = deserializeDelta(deltaBuf);
  assert.equal(delta.added.length, 1);
  assert.equal(delta.removed.length, 0);

  const oldSet = toRecords(fs.readFileSync(path.join(run1.outDir, 'set40.bin')));
  const newSet = toRecords(fs.readFileSync(path.join(run2.outDir, 'set40.bin')));
  const applied = applyDelta(oldSet, delta);
  assert.equal(applied.length, newSet.length);
  for (let i = 0; i < applied.length; i++) assert.equal(Buffer.compare(applied[i], newSet[i]), 0);
});
