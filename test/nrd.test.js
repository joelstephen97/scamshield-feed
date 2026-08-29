'use strict';
// test/nrd.test.js — Task C3: the NRD bloom build stage wired into build.js.
// lib/bloom.js's own math (known-in/known-out FP rate, header round-trip,
// determinism) is covered by test/bloom.test.js; this file covers the
// pipeline integration — fetch/normalize/union of the two HaGeZi windows,
// meta.json's `nrd` block, the poisoning guard, and end-to-end determinism.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { runBuild } = require('../build.js');
const Bloom = require('../lib/bloom');

const FIXTURES_BASE = path.join(__dirname, 'fixtures', 'base');
const FIXTURES_SHRUNK = path.join(__dirname, 'fixtures', 'shrunk');

function tmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

test('offline build emits nrd.bloom + meta.nrd, and every fixture NRD host tests positive', async () => {
  const writeDir = tmpDir('parry-feed-nrd-');
  const cacheDir = tmpDir('parry-feed-nrd-cache-');
  const result = await runBuild({
    repoRoot: writeDir, offlineDir: FIXTURES_BASE, cacheDir, prevDir: writeDir, writeDir,
    now: new Date('2026-08-29T10:00:00Z'),
  });

  const bloomPath = path.join(result.outDir, 'nrd.bloom');
  assert.ok(fs.existsSync(bloomPath), 'expected v/current/nrd.bloom to be written');
  const buf = fs.readFileSync(bloomPath);
  const parsed = Bloom.parseBloomFile(buf);

  // Union of the two fixture files, deduped (nrd-shared-window.example
  // appears in both): 6 + 4 - 1 shared = 9.
  const expectedHosts = [
    'nrd-fresh-one.example', 'nrd-fresh-two.example', 'nrd-shared-window.example',
    'nrd-only-in-seven.example', '0-fake-brand-support.icu', 'paypa1-verify-account.top',
    'nrd-fresh-three.example', 'nrd-only-in-fourteen.example', 'secure-login-verify-8271.xyz',
  ];
  assert.equal(parsed.n, expectedHosts.length);
  for (const h of expectedHosts) assert.equal(Bloom.testHostInFile(parsed, h), true, `expected ${h} to test positive`);
  assert.equal(Bloom.testHostInFile(parsed, 'clean-not-in-any-fixture.example'), false);

  const crypto = require('node:crypto');
  assert.equal(crypto.createHash('sha256').update(buf).digest('hex'), result.meta.nrd.sha256);

  const meta = JSON.parse(fs.readFileSync(path.join(result.outDir, 'meta.json'), 'utf8'));
  assert.deepEqual(Object.keys(meta.nrd).sort(), ['file', 'k', 'mBits', 'n', 'sha256', 'windowDays'].sort());
  assert.equal(meta.nrd.file, 'nrd.bloom');
  assert.equal(meta.nrd.n, expectedHosts.length);
  assert.equal(meta.nrd.windowDays, 14);
  assert.ok(meta.nrd.k >= 1 && meta.nrd.k <= 7);

  // NRD hosts must NOT leak into the block/warn union or risk.json (Part A.1:
  // "do NOT put them in risk.json or a sorted set").
  for (const h of expectedHosts) assert.equal(result.scored.has(h), false, `${h} must not be in the block/warn union`);
  const risk = JSON.parse(fs.readFileSync(path.join(result.outDir, 'risk.json'), 'utf8'));
  assert.equal(JSON.stringify(risk).includes('nrd-'), false);
});

test('poisoning guard: an NRD source shrinking >30% is rejected and last-good cache is reused', async () => {
  const cacheDir = tmpDir('parry-feed-nrd-cache-shrink-');
  const dir1 = tmpDir('parry-feed-nrd-run1-');
  const dir2 = tmpDir('parry-feed-nrd-run2-');

  const run1 = await runBuild({
    repoRoot: dir1, offlineDir: FIXTURES_BASE, cacheDir, prevDir: dir1, writeDir: dir1,
    now: new Date('2026-08-29T10:00:00Z'),
  });
  const src1 = run1.stats.nrdSources.find((s) => s.key === 'hagezi-nrd7');
  assert.equal(src1.normalizedCount, 6);
  assert.ok(src1.status.startsWith('ok'));

  const run2 = await runBuild({
    repoRoot: dir2, offlineDir: FIXTURES_SHRUNK, cacheDir, prevDir: dir1, writeDir: dir2,
    now: new Date('2026-08-29T16:00:00Z'),
  });
  const src2 = run2.stats.nrdSources.find((s) => s.key === 'hagezi-nrd7');
  assert.equal(src2.normalizedCount, 1); // shrunk fixture only has nrd-fresh-one.example
  assert.ok(src2.status.startsWith('REJECTED'), `expected shrink rejection, got: ${src2.status}`);
  assert.equal(src2.keptCount, 6, 'should have fallen back to the cached last-good set, not the shrunk fetch');

  // A host only ever supplied by the (rejected-shrink) hagezi-nrd7 fixture
  // still tests positive, proving the cache fallback actually fed the union.
  const bloomPath = path.join(run2.outDir, 'nrd.bloom');
  const parsed = Bloom.parseBloomFile(fs.readFileSync(bloomPath));
  assert.equal(Bloom.testHostInFile(parsed, 'nrd-only-in-seven.example'), true);
});

test('a source fetch/parse failure with no cache continues on error (0 domains, never throws)', async () => {
  const writeDir = tmpDir('parry-feed-nrd-nofixture-');
  const cacheDir = tmpDir('parry-feed-nrd-nofixture-cache-');
  const emptyOffline = tmpDir('parry-feed-nrd-empty-offline-');
  // Copy every base fixture EXCEPT the two NRD files, so nrd7/nrd14-8 fail to
  // read (ENOENT) with no prior cache to fall back to.
  for (const f of fs.readdirSync(FIXTURES_BASE)) {
    if (f.startsWith('hagezi-nrd')) continue;
    fs.copyFileSync(path.join(FIXTURES_BASE, f), path.join(emptyOffline, f));
  }
  const result = await runBuild({
    repoRoot: writeDir, offlineDir: emptyOffline, cacheDir, prevDir: writeDir, writeDir,
    now: new Date('2026-08-29T10:00:00Z'),
  });
  for (const s of result.stats.nrdSources) {
    assert.equal(s.keptCount, 0);
    assert.ok(/failed/.test(s.status), `expected a failure status, got: ${s.status}`);
  }
  const parsed = Bloom.parseBloomFile(fs.readFileSync(path.join(result.outDir, 'nrd.bloom')));
  assert.equal(parsed.n, 0);
});

test('identical NRD inputs produce a byte-identical nrd.bloom across independent reruns', async () => {
  const now = new Date('2026-08-29T10:00:00Z');
  const dirA = tmpDir('parry-feed-nrd-it-a-');
  const dirB = tmpDir('parry-feed-nrd-it-b-');
  const [rA, rB] = await Promise.all([
    runBuild({ repoRoot: dirA, offlineDir: FIXTURES_BASE, cacheDir: tmpDir('cache-nrd-a-'), prevDir: dirA, writeDir: dirA, now }),
    runBuild({ repoRoot: dirB, offlineDir: FIXTURES_BASE, cacheDir: tmpDir('cache-nrd-b-'), prevDir: dirB, writeDir: dirB, now }),
  ]);
  const a = fs.readFileSync(path.join(rA.outDir, 'nrd.bloom'));
  const b = fs.readFileSync(path.join(rB.outDir, 'nrd.bloom'));
  assert.equal(Buffer.compare(a, b), 0, 'nrd.bloom differs between identical reruns');
  assert.deepEqual(rA.meta.nrd, rB.meta.nrd);
});
