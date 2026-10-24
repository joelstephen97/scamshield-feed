'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { parseExclusions, loadExclusions } = require('../lib/exclusions');
const { dropExcluded, dropUncorroborated } = require('../lib/gate');
const { topSlice } = require('../lib/tranco');

test('parseExclusions: comments, blanks, www, case', () => {
  const s = parseExclusions('# hdr\n\nLifeAtSpotify.com  # 159331, Phishing.Database\nwww.example.org\nnot a domain\n');
  assert.deepEqual([...s].sort(), ['example.org', 'lifeatspotify.com']);
});

test('shipped data/exclusions.txt loads and contains lifeatspotify.com', () => {
  const s = loadExclusions();
  assert.ok(s.size > 100);
  assert.ok(s.has('lifeatspotify.com'));
});

test('dropExcluded: exact host (www folded) only, subdomains are kept', () => {
  const ex = loadExclusions();
  const { kept, dropped } = dropExcluded(['lifeatspotify.com', 'www.lifeatspotify.com', 'jobs.lifeatspotify.com', 'evil.example'], ex);
  assert.deepEqual(dropped, ['lifeatspotify.com', 'www.lifeatspotify.com']);
  assert.deepEqual(kept, ['jobs.lifeatspotify.com', 'evil.example']);
});

test('dropExcludedFromHot removes excluded hosts from the hot list', () => {
  const { dropExcludedFromHot } = require('../scripts/build-hot');
  const hot = { domains: [{ h: 'lifeatspotify.com', s: 'pd' }, { h: 'bad.example', s: 'pd' }] };
  const dropped = dropExcludedFromHot(hot, loadExclusions(), () => {});
  assert.deepEqual(dropped, ['lifeatspotify.com']);
  assert.deepEqual(hot.domains.map((d) => d.h), ['bad.example']);
});

const mk = (...keys) => ({ sources: new Set(keys), tier: 'block' });

test('dropUncorroborated: single-source Phishing.Database top-1M host is dropped', () => {
  const scored = new Map([['legit.example', mk('phishing-database')]]);
  const dropped = dropUncorroborated(scored, new Set(['legit.example']));
  assert.deepEqual(dropped, ['legit.example']);
  assert.equal(scored.size, 0);
});

test('dropUncorroborated: corroborated, other-source, unranked and tenant hosts are kept', () => {
  const scored = new Map([
    ['two.example', mk('phishing-database', 'phishdestroy')],
    ['pd.example', mk('phishdestroy')],
    ['unranked.example', mk('phishing-database')],
    ['sub.ranked.example', mk('phishing-database')],
  ]);
  const dropped = dropUncorroborated(scored, new Set(['two.example', 'pd.example', 'ranked.example']));
  assert.deepEqual(dropped, []);
  assert.equal(scored.size, 4);
});

test('topSlice keeps rank order and size', () => {
  const s = new Set(['a', 'b', 'c', 'd']);
  assert.deepEqual([...topSlice(s, 2)], ['a', 'b']);
  assert.equal(topSlice(s, 10), s);
});
