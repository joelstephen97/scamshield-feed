'use strict';
const test = require('node:test'); const assert = require('node:assert');
const { buildHot, HOT_CAP, WINDOW_MIN, HOT_SOURCE_KEYS, TAG_RANK } = require('../scripts/build-hot');
const bloomLib = require('../lib/bloom');
const NOW = 1789000000000; const MIN = Math.floor(NOW / 60000);
const allow = new Set(['google.com', 'paypal.com']);
const sources = {
  phishdestroy: new Set(['new-kit.example', 'www.google.com']),
  'metamask-eth-phishing': new Set(['drainer.example']),
  'phishing-database': new Set(['tenant.webflow.io']),
};
const paths = [{ h: 'rb.gy', p: '/88c5r3', s: 'pdb' }, { h: 'paypal.com', p: '/x', s: 'pdb' }];

// A `prevBloom` fixture representing "a baseline already exists" (so a test
// exercises the normal steady-state path instead of accidentally tripping
// the bootstrap branch, which only fires when NO baseline bloom is given —
// see the two dedicated bootstrap tests below for that behavior). Optional
// `hosts` seeds specific hosts as already-graduated ("old").
function baselineFixture(hosts = []) {
  const { mBits, k } = bloomLib.optimalParams(Math.max(10, hosts.length), 0.01);
  const bits = bloomLib.createBitArray(mBits);
  for (const h of hosts) bloomLib.addHost(bits, mBits, k, h);
  return { mBits, k, bits, n: hosts.length };
}

test('buildHot: unions sources, tags first source, applies the allowlist by registrable domain', () => {
  const { hot, state } = buildHot({ sources, paths, allow, prevState: { seen: {} }, prevBloom: baselineFixture(), now: NOW });
  assert.deepStrictEqual(hot.domains.map((d) => d.h).sort(), ['drainer.example', 'new-kit.example', 'tenant.webflow.io']);
  assert.strictEqual(hot.domains.find((d) => d.h === 'drainer.example').s, 'mm');
  assert.deepStrictEqual(hot.paths, [{ h: 'rb.gy', p: '/88c5r3', s: 'pdb', t: MIN }]);
  assert.strictEqual(state.seen['new-kit.example'], MIN);
});

test('buildHot: first-seen persists across runs and the 48 h window expires hosts', () => {
  const prev = { seen: { 'old.example': MIN - WINDOW_MIN - 1, 'recent.example': MIN - 60 }, absent: {} };
  const src = { phishdestroy: new Set(['old.example', 'recent.example']) };
  const { hot } = buildHot({ sources: src, paths: [], allow, prevState: prev, prevBloom: baselineFixture(), now: NOW });
  assert.deepStrictEqual(hot.domains.map((d) => [d.h, d.t]), [['recent.example', MIN - 60]]);
});

test('buildHot: a host missing for two consecutive runs is emitted in removed', () => {
  const prev = { seen: { 'gone.example': MIN - 30 }, absent: { 'gone.example': 1 } };
  const { hot, state } = buildHot({ sources: { phishdestroy: new Set() }, paths: [], allow, prevState: prev, prevBloom: baselineFixture(), now: NOW });
  assert.deepStrictEqual(hot.removed, ['gone.example']);
  assert.strictEqual(state.seen['gone.example'], undefined);
});

test('buildHot: growth guard rejects a source that grew > 25 % vs the previous run', () => {
  const prev = { seen: {}, absent: {}, counts: { phishdestroy: 1000 } };
  const big = new Set(Array.from({ length: 1300 }, (_, i) => `h${i}.example`));
  const { hot, rejected } = buildHot({ sources: { phishdestroy: big }, paths: [], allow, prevState: prev, prevBloom: baselineFixture(), now: NOW });
  assert.deepStrictEqual(rejected, ['phishdestroy']);
  assert.strictEqual(hot.domains.length, 0);
});

test('buildHot: caps at HOT_CAP (12,000) newest first', () => {
  assert.strictEqual(HOT_CAP, 12000);
  const src = { phishdestroy: new Set(Array.from({ length: HOT_CAP + 50 }, (_, i) => `h${i}.example`)) };
  const { hot } = buildHot({ sources: src, paths: [], allow, prevState: { seen: {} }, prevBloom: baselineFixture(), now: NOW });
  assert.strictEqual(hot.domains.length, HOT_CAP);
});

test('buildHot: when the cap binds, source priority keeps pd and cuts hz', () => {
  // Key order matters: srcSets is walked in insertion order, so a host in
  // several sources keeps the highest-priority tag.
  const src = {
    phishdestroy: new Set(Array.from({ length: 100 }, (_, i) => `pd${i}.example`)),
    'hagezi-tif-medium': new Set(Array.from({ length: HOT_CAP }, (_, i) => `hz${i}.example`)),
  };
  const { hot } = buildHot({ sources: src, paths: [], allow, prevState: { seen: {} }, prevBloom: baselineFixture(), now: NOW });
  assert.strictEqual(hot.domains.length, HOT_CAP);
  const bySource = hot.domains.reduce((acc, d) => { acc[d.s] = (acc[d.s] || 0) + 1; return acc; }, {});
  // Every pd host survives; hz is the source that gets sliced off.
  assert.strictEqual(bySource.pd, 100);
  assert.strictEqual(bySource.hz, HOT_CAP - 100);
  // ...and pd sorts ahead of hz in the emitted order.
  assert.strictEqual(hot.domains[0].s, 'pd');
  assert.strictEqual(hot.domains[99].s, 'pd');
  assert.strictEqual(hot.domains[100].s, 'hz');
  assert.strictEqual(TAG_RANK.pd < TAG_RANK.hz, true);
});

test('buildHot: allowlist protects sub-domains of an allowlisted host too (suffix walk via gate.isAllowed)', () => {
  const allowSub = new Set(['mail.google.com']);
  const src = { phishdestroy: new Set(['evil.mail.google.com']) };
  const { hot } = buildHot({ sources: src, paths: [], allow: allowSub, prevState: { seen: {} }, prevBloom: baselineFixture(), now: NOW });
  assert.deepStrictEqual(hot.domains, []);
});

test('buildHot: a total source outage does not evict the list into removed', () => {
  const prev = { seen: { 'known.example': MIN - 100 }, absent: {}, counts: { phishdestroy: 500 }, tags: { 'known.example': 'pd' } };
  const { hot, state } = buildHot({ sources: {}, paths: [], allow, prevState: prev, prevBloom: baselineFixture(), now: NOW });
  assert.deepStrictEqual(hot.domains, [{ h: 'known.example', s: 'pd', t: MIN - 100 }]);
  assert.deepStrictEqual(hot.removed, []);
  assert.strictEqual(state.seen['known.example'], MIN - 100);
  assert.strictEqual(state.absent['known.example'], undefined);
});

// --- Fix round 2: bootstrap + Bloom-graduated baseline -----------------

test('buildHot: a bootstrap run (no baseline bloom) emits no domains and records everything into the baseline', () => {
  const src = { phishdestroy: new Set(['fresh1.example', 'fresh2.example']) };
  const { hot, state, bloom } = buildHot({ sources: src, paths: [], allow, prevState: { seen: {} }, prevBloom: null, now: NOW });
  assert.deepStrictEqual(hot.domains, []);
  assert.deepStrictEqual(state.seen, {});
  assert.ok(bloomLib.testHost(bloom.bits, bloom.mBits, bloom.k, 'fresh1.example'));
  assert.ok(bloomLib.testHost(bloom.bits, bloom.mBits, bloom.k, 'fresh2.example'));
});

test('buildHot: after a baseline exists, only a genuinely new host is emitted (old baseline host is skipped)', () => {
  const prevBloom = baselineFixture(['old-known.example']);
  const src = { phishdestroy: new Set(['old-known.example', 'brand-new.example']) };
  const { hot, state } = buildHot({ sources: src, paths: [], allow, prevState: { seen: {}, absent: {}, counts: {} }, prevBloom, now: NOW });
  assert.deepStrictEqual(hot.domains, [{ h: 'brand-new.example', s: 'pd', t: MIN }]);
  assert.strictEqual(state.seen['old-known.example'], undefined);
  assert.strictEqual(state.seen['brand-new.example'], MIN);
});

test('buildHot: a host older than the window graduates into the bloom and stays excluded even if it reappears', () => {
  const prev = { seen: { 'aged.example': MIN - WINDOW_MIN - 5 }, absent: {}, counts: { phishdestroy: 1 } };
  const src = { phishdestroy: new Set(['aged.example']) };
  const run1 = buildHot({ sources: src, paths: [], allow, prevState: prev, prevBloom: baselineFixture(), now: NOW });
  assert.strictEqual(run1.state.seen['aged.example'], undefined);
  assert.ok(bloomLib.testHost(run1.bloom.bits, run1.bloom.mBits, run1.bloom.k, 'aged.example'));
  assert.deepStrictEqual(run1.hot.domains, []);

  // A later run sees the same host reported again by a source; it must not
  // be re-classified as "new" now that it lives in the baseline bloom.
  const run2 = buildHot({ sources: src, paths: [], allow, prevState: run1.state, prevBloom: run1.bloom, now: NOW + 3600000 });
  assert.strictEqual(run2.state.seen['aged.example'], undefined);
  assert.deepStrictEqual(run2.hot.domains, []);
});

test('buildHot: every source rejected by the growth guard preserves seen and removes nothing', () => {
  const prev = { seen: { 'known.example': MIN - 200 }, absent: {}, counts: { phishdestroy: 1000 }, tags: { 'known.example': 'pd' } };
  const big = new Set(Array.from({ length: 1300 }, (_, i) => `h${i}.example`));
  const { hot, state, rejected } = buildHot({ sources: { phishdestroy: big }, paths: [], allow, prevState: prev, prevBloom: baselineFixture(), now: NOW });
  assert.deepStrictEqual(rejected, ['phishdestroy']);
  assert.deepStrictEqual(hot.domains, [{ h: 'known.example', s: 'pd', t: MIN - 200 }]);
  assert.deepStrictEqual(hot.removed, []);
  assert.strictEqual(state.seen['known.example'], MIN - 200);
});

test('hot builder only reads licence-vetted sources', () => {
  const { sources: registry } = require('../sources');
  const keys = new Set(registry.filter((s) => s.enabled !== false).map((s) => s.key));
  for (const k of HOT_SOURCE_KEYS) assert.ok(keys.has(k), `${k} is not a vetted source`);
  const src = require('fs').readFileSync(require.resolve('../scripts/build-hot'), 'utf8').toLowerCase();
  for (const banned of ['openphish', 'phishtank', 'urlhaus']) assert.ok(!src.includes(banned), banned + ' must not appear');
});
