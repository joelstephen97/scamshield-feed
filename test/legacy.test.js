'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildLegacyBlocklist } = require('../lib/legacy');

function scoredFrom(blockHostsWithCounts, warnHosts = []) {
  const scored = new Map();
  for (const [host, count] of blockHostsWithCounts) {
    const sources = new Set(Array.from({ length: count }, (_, i) => `src${i}`));
    scored.set(host, { sources, tier: 'block' });
  }
  for (const host of warnHosts) {
    scored.set(host, { sources: new Set(['src0']), tier: 'warn' });
  }
  return scored;
}

test('legacy blocklist.json is exactly { version, rules } — no extra fields', () => {
  const scored = scoredFrom([['evil.example', 2]]);
  const out = buildLegacyBlocklist(scored, { now: Date.UTC(2026, 7, 29) });
  assert.deepEqual(Object.keys(out).sort(), ['rules', 'version']);
  assert.equal(typeof out.version, 'number');
  assert.ok(Array.isArray(out.rules));
});

test('rules are formatted "||host^" and only include block-tier hosts', () => {
  const scored = scoredFrom([['block-me.example', 1]], ['warn-me.example']);
  const out = buildLegacyBlocklist(scored);
  assert.deepEqual(out.rules, ['||block-me.example^']);
});

test('version is days-since-epoch, matching pipeline v1', () => {
  const scored = scoredFrom([]);
  const now = Date.UTC(2026, 0, 1); // 20454 days since epoch
  const out = buildLegacyBlocklist(scored, { now });
  assert.equal(out.version, Math.floor(now / 86400000));
});

test('caps at 5000 and orders by source-count desc, then alpha for ties', () => {
  const entries = [];
  for (let i = 0; i < 5010; i++) entries.push([`host-${String(i).padStart(5, '0')}.example`, 1]);
  entries[42][1] = 5; // one high-confidence outlier, should sort first
  const scored = scoredFrom(entries);
  const out = buildLegacyBlocklist(scored, { cap: 5000 });
  assert.equal(out.rules.length, 5000);
  assert.equal(out.rules[0], `||${entries[42][0]}^`);
  // Remaining ties (all count=1) should be alphabetical.
  const rest = out.rules.slice(1).map((r) => r.slice(2, -1));
  const sortedRest = rest.slice().sort();
  assert.deepEqual(rest, sortedRest);
});

test('custom cap is respected', () => {
  const scored = scoredFrom([['a.example', 1], ['b.example', 1], ['c.example', 1]]);
  const out = buildLegacyBlocklist(scored, { cap: 2 });
  assert.equal(out.rules.length, 2);
});
