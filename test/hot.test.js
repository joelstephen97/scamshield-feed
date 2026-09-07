'use strict';
const test = require('node:test'); const assert = require('node:assert');
const { buildHot, HOT_CAP, WINDOW_MIN, HOT_SOURCE_KEYS } = require('../scripts/build-hot');
const NOW = 1789000000000; const MIN = Math.floor(NOW / 60000);
const allow = new Set(['google.com', 'paypal.com']);
const sources = {
  phishdestroy: new Set(['new-kit.example', 'www.google.com']),
  'metamask-eth-phishing': new Set(['drainer.example']),
  'phishing-database': new Set(['tenant.webflow.io']),
};
const paths = [{ h: 'rb.gy', p: '/88c5r3', s: 'pdb' }, { h: 'paypal.com', p: '/x', s: 'pdb' }];

test('buildHot: unions sources, tags first source, applies the allowlist by registrable domain', () => {
  const { hot, state } = buildHot({ sources, paths, allow, prevState: { seen: {} }, now: NOW });
  assert.deepStrictEqual(hot.domains.map((d) => d.h).sort(), ['drainer.example', 'new-kit.example', 'tenant.webflow.io']);
  assert.strictEqual(hot.domains.find((d) => d.h === 'drainer.example').s, 'mm');
  assert.deepStrictEqual(hot.paths, [{ h: 'rb.gy', p: '/88c5r3', s: 'pdb', t: MIN }]);
  assert.strictEqual(state.seen['new-kit.example'], MIN);
});

test('buildHot: first-seen persists across runs and the 48 h window expires hosts', () => {
  const prev = { seen: { 'old.example': MIN - WINDOW_MIN - 1, 'recent.example': MIN - 60 }, absent: {} };
  const src = { phishdestroy: new Set(['old.example', 'recent.example']) };
  const { hot } = buildHot({ sources: src, paths: [], allow, prevState: prev, now: NOW });
  assert.deepStrictEqual(hot.domains.map((d) => [d.h, d.t]), [['recent.example', MIN - 60]]);
});

test('buildHot: a host missing for two consecutive runs is emitted in removed', () => {
  const prev = { seen: { 'gone.example': MIN - 30 }, absent: { 'gone.example': 1 } };
  const { hot, state } = buildHot({ sources: { phishdestroy: new Set() }, paths: [], allow, prevState: prev, now: NOW });
  assert.deepStrictEqual(hot.removed, ['gone.example']);
  assert.strictEqual(state.seen['gone.example'], undefined);
});

test('buildHot: growth guard rejects a source that grew > 25 % vs the previous run', () => {
  const prev = { seen: {}, absent: {}, counts: { phishdestroy: 1000 } };
  const big = new Set(Array.from({ length: 1300 }, (_, i) => `h${i}.example`));
  const { hot, rejected } = buildHot({ sources: { phishdestroy: big }, paths: [], allow, prevState: prev, now: NOW });
  assert.deepStrictEqual(rejected, ['phishdestroy']);
  assert.strictEqual(hot.domains.length, 0);
});

test('buildHot: caps at HOT_CAP newest first', () => {
  const src = { phishdestroy: new Set(Array.from({ length: HOT_CAP + 50 }, (_, i) => `h${i}.example`)) };
  const { hot } = buildHot({ sources: src, paths: [], allow, prevState: { seen: {} }, now: NOW });
  assert.strictEqual(hot.domains.length, HOT_CAP);
});

test('buildHot: allowlist protects sub-domains of an allowlisted host too (suffix walk via gate.isAllowed)', () => {
  const allowSub = new Set(['mail.google.com']);
  const src = { phishdestroy: new Set(['evil.mail.google.com']) };
  const { hot } = buildHot({ sources: src, paths: [], allow: allowSub, prevState: { seen: {} }, now: NOW });
  assert.deepStrictEqual(hot.domains, []);
});

test('buildHot: a total source outage does not evict the list into removed', () => {
  const prev = { seen: { 'known.example': MIN - 100 }, absent: {}, counts: { phishdestroy: 500 }, tags: { 'known.example': 'pd' } };
  const { hot, state } = buildHot({ sources: {}, paths: [], allow, prevState: prev, now: NOW });
  assert.deepStrictEqual(hot.domains, [{ h: 'known.example', s: 'pd', t: MIN - 100 }]);
  assert.deepStrictEqual(hot.removed, []);
  assert.strictEqual(state.seen['known.example'], MIN - 100);
  assert.strictEqual(state.absent['known.example'], undefined);
});

test('hot builder only reads licence-vetted sources', () => {
  const { sources: registry } = require('../sources');
  const keys = new Set(registry.filter((s) => s.enabled !== false).map((s) => s.key));
  for (const k of HOT_SOURCE_KEYS) assert.ok(keys.has(k), `${k} is not a vetted source`);
  const src = require('fs').readFileSync(require.resolve('../scripts/build-hot'), 'utf8').toLowerCase();
  for (const banned of ['openphish', 'phishtank', 'urlhaus']) assert.ok(!src.includes(banned), banned + ' must not appear');
});
