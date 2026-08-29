'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const Bloom = require('../lib/bloom');

test('optimalParams sizes m/k for a target false-positive rate, capping k at MAX_K', () => {
  const small = Bloom.optimalParams(1000, 0.005);
  assert.ok(small.mBits > 0 && small.mBits % 8 === 0, 'mBits must be a whole number of bytes');
  assert.ok(small.k >= 1 && small.k <= Bloom.MAX_K);

  // At millions of entries and p~0.5%, the optimal k already sits at/under 7,
  // but the cap is asserted directly regardless (the whole point of the
  // task brief's k<=7 requirement).
  const huge = Bloom.optimalParams(5_000_000, 0.005);
  assert.ok(huge.k <= Bloom.MAX_K);
  assert.ok(huge.mBits > 1_000_000, 'expected tens of millions of bits for 5M entries at 0.5% FP');

  // A deliberately tiny p should never push k past the cap either.
  const tinyP = Bloom.optimalParams(5_000_000, 0.0001);
  assert.ok(tinyP.k <= Bloom.MAX_K);
});

test('buildBloom: known-in hosts always test positive', () => {
  const hosts = new Set();
  for (let i = 0; i < 2000; i++) hosts.add(`known-in-${i}.example`);
  const built = Bloom.buildBloom(hosts, { p: 0.005 });
  assert.equal(built.n, 2000);
  for (const h of hosts) {
    assert.equal(Bloom.testHost(built.bits, built.mBits, built.k, h), true, `expected ${h} to test positive`);
  }
});

test('buildBloom: measured false-positive rate on 10k known-out hosts stays under 1.5%', () => {
  const hosts = new Set();
  for (let i = 0; i < 20000; i++) hosts.add(`fp-rate-in-${i}.example`);
  const built = Bloom.buildBloom(hosts, { p: 0.005 });

  let falsePositives = 0;
  const OUT_COUNT = 10000;
  for (let i = 0; i < OUT_COUNT; i++) {
    const out = `fp-rate-out-${i}.example`;
    assert.equal(hosts.has(out), false, 'test setup bug: known-out host collides with a known-in host');
    if (Bloom.testHost(built.bits, built.mBits, built.k, out)) falsePositives++;
  }
  const rate = falsePositives / OUT_COUNT;
  assert.ok(rate < 0.015, `measured false-positive rate ${rate} exceeds 1.5% tolerance`);
});

test('serializeBloomFile / parseBloomFile: header round-trips exactly', () => {
  const hosts = new Set(['round-trip-one.example', 'round-trip-two.example']);
  const built = Bloom.buildBloom(hosts, { p: 0.01 });
  const fileBuf = Bloom.serializeBloomFile(built);

  assert.equal(fileBuf.length, Bloom.HEADER_LEN + built.bits.length);
  assert.equal(fileBuf.toString('ascii', 0, 4), Bloom.MAGIC);

  const parsed = Bloom.parseBloomFile(fileBuf);
  assert.equal(parsed.version, Bloom.VERSION);
  assert.equal(parsed.k, built.k);
  assert.equal(parsed.n, built.n);
  assert.equal(parsed.mBits, built.mBits);
  assert.equal(Buffer.compare(parsed.bits, built.bits), 0);

  for (const h of hosts) assert.equal(Bloom.testHostInFile(parsed, h), true);
  assert.equal(Bloom.testHostInFile(parsed, 'definitely-not-inserted.example'), false);
});

test('parseBloomFile rejects a bad magic or a length that does not match the header', () => {
  const hosts = new Set(['x.example']);
  const built = Bloom.buildBloom(hosts, { p: 0.01 });
  const fileBuf = Bloom.serializeBloomFile(built);

  const badMagic = Buffer.from(fileBuf);
  badMagic.write('XXXX', 0, 4, 'ascii');
  assert.throws(() => Bloom.parseBloomFile(badMagic), /bad magic/);

  const truncated = fileBuf.subarray(0, fileBuf.length - 1);
  assert.throws(() => Bloom.parseBloomFile(truncated), /does not match/);
});

test('determinism: building twice from the same input set yields byte-identical files', () => {
  const hosts = new Set();
  for (let i = 0; i < 5000; i++) hosts.add(`det-${i}.example`);
  const a = Bloom.serializeBloomFile(Bloom.buildBloom(hosts, { p: 0.005 }));
  const b = Bloom.serializeBloomFile(Bloom.buildBloom(hosts, { p: 0.005 }));
  assert.equal(Buffer.compare(a, b), 0);

  // Insertion order must not matter — same set, reversed insertion order.
  const reversed = new Set([...hosts].reverse());
  const c = Bloom.serializeBloomFile(Bloom.buildBloom(reversed, { p: 0.005 }));
  assert.equal(Buffer.compare(a, c), 0, 'insertion order changed the resulting bit array');
});

// --- index-derivation spec (the exact algorithm mirrored in the extension's
// engine/bloom.js) is pinned here so a future edit to lib/bloom.js can't
// silently drift from the cross-repo spec without a test noticing.
test('indicesFor: Kirsch-Mitzenmacher double hashing from digest bytes 0-7, h2=0 guard', () => {
  const digest = crypto.createHash('sha256').update('spec-pin.example', 'utf8').digest();
  const h1 = digest.readUInt32BE(0);
  const h2raw = digest.readUInt32BE(4);
  const h2 = h2raw === 0 ? 1 : h2raw;
  const k = 5;
  const mBits = 1024;
  const expected = [];
  for (let i = 0; i < k; i++) expected.push((h1 + i * h2) % mBits);
  assert.deepEqual(Bloom.indicesFor(digest, k, mBits), expected);

  // Degenerate digest guard: an all-zero second word must not collapse every
  // index onto h1.
  const fakeDigest = Buffer.alloc(32);
  fakeDigest.writeUInt32BE(42, 0);
  const idxs = Bloom.indicesFor(fakeDigest, 4, 1024);
  assert.deepEqual(idxs, [42, 43, 44, 45]); // h2 forced to 1
});
