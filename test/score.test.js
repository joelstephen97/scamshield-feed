'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { scoreDomains } = require('../lib/score');

const metaByKey = new Map([
  ['tier1-a', { scoreWeight: 'A' }],
  ['tier1-b', { scoreWeight: 'A' }],
  ['tier2-x', { scoreWeight: 'B' }],
  ['tier2-y', { scoreWeight: 'B' }],
  ['tier2-z', { scoreWeight: 'B' }],
]);

test('any tier-1 (scoreWeight A) hit is block, even with a single source', () => {
  const perSource = new Map([
    ['tier1-a', new Set(['solo-a.com'])],
  ]);
  const scored = scoreDomains(perSource, metaByKey);
  assert.equal(scored.get('solo-a.com').tier, 'block');
});

test('a single tier-2 (scoreWeight B) source is warn only', () => {
  const perSource = new Map([
    ['tier2-x', new Set(['solo-b.com'])],
  ]);
  const scored = scoreDomains(perSource, metaByKey);
  assert.equal(scored.get('solo-b.com').tier, 'warn');
});

test('two independent tier-2 sources promote to block even with no tier-1 hit', () => {
  const perSource = new Map([
    ['tier2-x', new Set(['corroborated.com'])],
    ['tier2-y', new Set(['corroborated.com'])],
  ]);
  const scored = scoreDomains(perSource, metaByKey);
  assert.equal(scored.get('corroborated.com').tier, 'block');
  assert.equal(scored.get('corroborated.com').sources.size, 2);
});

test('three tier-2 sources still just block (not some higher tier)', () => {
  const perSource = new Map([
    ['tier2-x', new Set(['triple.com'])],
    ['tier2-y', new Set(['triple.com'])],
    ['tier2-z', new Set(['triple.com'])],
  ]);
  const scored = scoreDomains(perSource, metaByKey);
  assert.equal(scored.get('triple.com').tier, 'block');
});

test('mixed: one tier-1 + one tier-2 source is block', () => {
  const perSource = new Map([
    ['tier1-a', new Set(['mixed.com'])],
    ['tier2-x', new Set(['mixed.com'])],
  ]);
  const scored = scoreDomains(perSource, metaByKey);
  assert.equal(scored.get('mixed.com').tier, 'block');
});

test('domains absent from all sources never appear in the scored map', () => {
  const perSource = new Map([['tier1-a', new Set(['present.com'])]]);
  const scored = scoreDomains(perSource, metaByKey);
  assert.equal(scored.has('absent.com'), false);
});
