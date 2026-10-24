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

test('dropExcluded folds only a literal "www." prefix: lookalikes such as wwwxlifeatspotify.com stay listed', () => {
  const { dropExcluded } = require('../lib/gate');
  const ex = new Set(['lifeatspotify.com']);
  const r = dropExcluded(['lifeatspotify.com', 'www.lifeatspotify.com', 'wwwxlifeatspotify.com', 'www-lifeatspotify.com', 'evil.lifeatspotify.com'], ex);
  assert.deepStrictEqual(r.dropped, ['lifeatspotify.com', 'www.lifeatspotify.com']);
  assert.deepStrictEqual(r.kept, ['wwwxlifeatspotify.com', 'www-lifeatspotify.com', 'evil.lifeatspotify.com']);
});

test('dropUncorroborated keeps a single-source host on a strongly abused TLD (.sbs) but drops one on .com or .info', () => {
  const scored = new Map([
    ['3xp3cts1aim.sbs', { sources: new Set(['phishing-database']), tier: 'block' }],
    ['legit-ranked.com', { sources: new Set(['phishing-database']), tier: 'block' }],
    ['legit-ranked.info', { sources: new Set(['phishing-database']), tier: 'block' }]
  ]);
  const wide = new Set(['3xp3cts1aim.sbs', 'legit-ranked.com', 'legit-ranked.info']);
  const dropped = dropUncorroborated(scored, wide);
  assert.deepStrictEqual(dropped.sort(), ['legit-ranked.com', 'legit-ranked.info']);
  assert.ok(scored.has('3xp3cts1aim.sbs'));
});
