'use strict';
/**
 * lib/bloom.js — Bloom filter builder/reader for v/current/nrd.bloom
 * (Task C3, "New site" signal: NRD bloom filter).
 *
 * WHY A BLOOM FILTER: HaGeZi's newly-registered-domains lists run into the
 * MILLIONS of domains for even a 14-day window — far too large for risk.json
 * (a small JSON evidence table) or a sorted 40-bit record set like
 * set40.bin/warn40.bin (which need an exact-shard verify tier this data has
 * no room for). A Bloom filter gives a compact, constant-size membership
 * test with a bounded, tunable false-positive rate and zero false negatives
 * — exactly what a warn-tier-only, never-blocks-alone signal needs.
 *
 * FILE FORMAT (nrd.bloom): 16-byte header + bit array, all big-endian.
 *   offset 0  (4 bytes): magic ASCII 'NRDB'
 *   offset 4  (1 byte ): version (currently 1)
 *   offset 5  (1 byte ): k (number of hash functions, 1..MAX_K)
 *   offset 6  (2 bytes): reserved, always 0
 *   offset 8  (4 bytes): n, big-endian u32 (number of hostnames inserted)
 *   offset 12 (4 bytes): mBits, big-endian u32 (bit-array size, in bits)
 *   offset 16..        : bit array, ceil(mBits/8) bytes. Bit i lives at byte
 *                         (i >> 3), position (7 - (i & 7)) counting from the
 *                         MSB of that byte.
 *
 * INDEX DERIVATION — THE SAME ALGORITHM RUNS ON BOTH SIDES. This exact
 * recipe is mirrored byte-for-byte in the extension repo's engine/bloom.js
 * (see that file's matching header comment); changing either side without
 * the other breaks every install silently (only false negatives — a real
 * NRD hit that stops matching — never false positives, which makes the bug
 * very easy to miss in testing). Given a full (already-normalized, lowercase)
 * hostname:
 *   1. digest = SHA-256(hostname), UTF-8 bytes of the hostname string — the
 *      `sha256()` helper from lib/hash.js here; crypto.subtle.digest on the
 *      extension side, same input encoding.
 *   2. h1 = digest.readUInt32BE(0)   -- first 4 digest bytes, big-endian
 *      h2 = digest.readUInt32BE(4)   -- next 4 digest bytes, big-endian
 *      if (h2 === 0) h2 = 1          -- degenerate-digest guard (SHA-256
 *                                       never produces an all-zero 4-byte
 *                                       window in practice, but this keeps
 *                                       the scheme from ever collapsing to a
 *                                       single repeated index)
 *   3. For i = 0..k-1: index_i = (h1 + i * h2) % mBits
 *      (Kirsch–Mitzenmacher double hashing: derives k roughly-independent
 *      indices from a single digest, so only one SHA-256 is ever needed per
 *      membership test/insert regardless of k.)
 *
 * PARAMETER SIZING: for a target false-positive rate p at n inserted items,
 * the standard optimal-Bloom-filter formulas are used:
 *   m = ceil(-(n * ln(p)) / (ln 2)^2)     -- bits
 *   k = round((m / n) * ln 2)             -- hash-function count
 * k is capped at MAX_K (7): at the actual n this pipeline produces
 * (millions of domains) and the target p (~0.5%), the optimal k already
 * lands at or below 7, so the cap is a defensive ceiling rather than an
 * active tradeoff — see the task brief's "k<=7" requirement. mBits is
 * rounded up to a whole number of bytes.
 */
const { sha256 } = require('./hash');

const MAGIC = 'NRDB';
const VERSION = 1;
const HEADER_LEN = 16;
const MAX_K = 7;

/** Optimal { mBits, k } for n inserted items at target false-positive rate p. */
function optimalParams(n, p) {
  const count = Math.max(1, n);
  const rate = p > 0 && p < 1 ? p : 0.005;
  const mRaw = Math.ceil(-(count * Math.log(rate)) / (Math.LN2 * Math.LN2));
  const mBits = Math.max(8, Math.ceil(mRaw / 8) * 8);
  let k = Math.max(1, Math.round((mBits / count) * Math.LN2));
  if (k > MAX_K) k = MAX_K;
  return { mBits, k };
}

/**
 * The k index derivation shared with the extension's engine/bloom.js (see
 * this file's header comment for the exact spec). `digest` is a 32-byte
 * SHA-256 Buffer (or any indexable byte source with >=8 bytes).
 */
function indicesFor(digest, k, mBits) {
  if (!digest || digest.length < 8) throw new RangeError('indicesFor needs at least 8 digest bytes');
  let h1 = 0;
  for (let i = 0; i < 4; i++) h1 = h1 * 256 + (digest[i] & 0xff);
  let h2 = 0;
  for (let i = 4; i < 8; i++) h2 = h2 * 256 + (digest[i] & 0xff);
  if (h2 === 0) h2 = 1;
  const out = new Array(k);
  for (let i = 0; i < k; i++) out[i] = (h1 + i * h2) % mBits;
  return out;
}

function createBitArray(mBits) {
  return Buffer.alloc(Math.ceil(mBits / 8));
}

function setBit(bits, idx) {
  bits[idx >> 3] |= 1 << (7 - (idx & 7));
}

function testBit(bits, idx) {
  return (bits[idx >> 3] & (1 << (7 - (idx & 7)))) !== 0;
}

function addHost(bits, mBits, k, hostname) {
  const digest = sha256(hostname);
  const idxs = indicesFor(digest, k, mBits);
  for (const idx of idxs) setBit(bits, idx);
}

function testHost(bits, mBits, k, hostname) {
  const digest = sha256(hostname);
  const idxs = indicesFor(digest, k, mBits);
  for (const idx of idxs) {
    if (!testBit(bits, idx)) return false;
  }
  return true;
}

/**
 * Builds a bit array from a Set (or anything with `.size` + `[Symbol.
 * iterator]`) of already-normalized hostnames. Insertion order never
 * affects the resulting bits — deterministic regardless of Set iteration
 * order, which itself is deterministic per JS spec (insertion order), but
 * this build is order-independent by construction (OR-ing bits).
 * Returns { bits, n, mBits, k }.
 */
function buildBloom(hostSet, { p = 0.005, k: forcedK } = {}) {
  const n = typeof hostSet.size === 'number' ? hostSet.size : Array.from(hostSet).length;
  const params = optimalParams(n, p);
  const k = forcedK || params.k;
  const bits = createBitArray(params.mBits);
  for (const h of hostSet) addHost(bits, params.mBits, k, h);
  return { bits, n, mBits: params.mBits, k };
}

/** Serializes { n, mBits, k, bits } into a full nrd.bloom file Buffer. */
function serializeBloomFile({ n, mBits, k, bits, version = VERSION }) {
  if (k < 1 || k > 255) throw new RangeError('k must fit in one byte (1-255)');
  const header = Buffer.alloc(HEADER_LEN);
  header.write(MAGIC, 0, 4, 'ascii');
  header.writeUInt8(version, 4);
  header.writeUInt8(k, 5);
  header.writeUInt16BE(0, 6);
  header.writeUInt32BE(n >>> 0, 8);
  header.writeUInt32BE(mBits >>> 0, 12);
  return Buffer.concat([header, bits]);
}

/** Parses a full nrd.bloom file Buffer back into { version, k, n, mBits, bits }. */
function parseBloomFile(buf) {
  const b = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);
  if (b.length < HEADER_LEN) throw new RangeError('buffer shorter than the 16-byte header');
  const magic = b.toString('ascii', 0, 4);
  if (magic !== MAGIC) throw new RangeError(`bad magic: expected ${MAGIC}, got ${magic}`);
  const version = b.readUInt8(4);
  const k = b.readUInt8(5);
  const n = b.readUInt32BE(8);
  const mBits = b.readUInt32BE(12);
  const expectedLen = HEADER_LEN + Math.ceil(mBits / 8);
  if (b.length !== expectedLen) {
    throw new RangeError(`buffer length ${b.length} does not match header (expected ${expectedLen})`);
  }
  const bits = b.subarray(HEADER_LEN);
  return { version, k, n, mBits, bits };
}

function testHostInFile(parsed, hostname) {
  return testHost(parsed.bits, parsed.mBits, parsed.k, hostname);
}

module.exports = {
  MAGIC, VERSION, HEADER_LEN, MAX_K,
  optimalParams, indicesFor, createBitArray, setBit, testBit,
  addHost, testHost, buildBloom, serializeBloomFile, parseBloomFile, testHostInFile,
};
