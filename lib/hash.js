'use strict';
/**
 * 5-byte record format shared by set40.bin / warn40.bin / delta / exact
 * shards: high 32 bits of SHA-256(hostname) as big-endian u32, plus 1 verify
 * byte (bits 32-39). SHA-256 digests are already big-endian, so a record is
 * simply the first 5 bytes of the digest.
 */
const crypto = require('node:crypto');

const RECORD_LEN = 5;

function sha256(hostname) {
  return crypto.createHash('sha256').update(hostname, 'utf8').digest();
}

/** Returns the 5-byte record Buffer for a hostname. */
function recordFor(hostname) {
  return sha256(hostname).subarray(0, RECORD_LEN);
}

/** First byte of the hash, as a 2-digit lowercase hex string — exact-shard index. */
function shardIndexFor(hostname) {
  return sha256(hostname)[0].toString(16).padStart(2, '0');
}

function sortRecords(buffers) {
  return buffers.slice().sort(Buffer.compare);
}

/** De-dupes an already-sorted array of 5-byte Buffers. */
function dedupeSortedRecords(sorted) {
  const out = [];
  let prev = null;
  for (const b of sorted) {
    if (!prev || Buffer.compare(prev, b) !== 0) out.push(b);
    prev = b;
  }
  return out;
}

function concatRecords(buffers) {
  return Buffer.concat(buffers);
}

function bufferToRecords(buf) {
  const out = [];
  for (let i = 0; i + RECORD_LEN <= buf.length; i += RECORD_LEN) {
    out.push(buf.subarray(i, i + RECORD_LEN));
  }
  return out;
}

/** True if two sorted record arrays contain the same set of records. */
function recordsEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (Buffer.compare(a[i], b[i]) !== 0) return false;
  }
  return true;
}

module.exports = {
  RECORD_LEN,
  sha256,
  recordFor,
  shardIndexFor,
  sortRecords,
  dedupeSortedRecords,
  concatRecords,
  bufferToRecords,
  recordsEqual,
};
