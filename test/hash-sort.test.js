'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const {
  RECORD_LEN, recordFor, sortRecords, dedupeSortedRecords, concatRecords, bufferToRecords,
} = require('../lib/hash');

test('a record is exactly 5 bytes: full SHA-256 high 32 bits + 1 verify byte', () => {
  const rec = recordFor('example.com');
  assert.equal(rec.length, RECORD_LEN);
  const digest = crypto.createHash('sha256').update('example.com', 'utf8').digest();
  assert.equal(Buffer.compare(rec, digest.subarray(0, 5)), 0);
  assert.equal(rec.readUInt32BE(0), digest.readUInt32BE(0));
  assert.equal(rec[4], digest[4]);
});

test('sortRecords orders by the full 40-bit big-endian value', () => {
  const hosts = ['zzz.example', 'aaa.example', 'mmm.example', 'a1.example', 'b2.example'];
  const records = hosts.map(recordFor);
  const sorted = sortRecords(records);
  for (let i = 1; i < sorted.length; i++) {
    const prevVal = sorted[i - 1].readUIntBE(0, 5);
    const curVal = sorted[i].readUIntBE(0, 5);
    assert.ok(prevVal <= curVal, `record ${i - 1} (${prevVal}) should be <= record ${i} (${curVal})`);
  }
  // Sanity: sortRecords does not mutate its input array order.
  assert.equal(Buffer.compare(records[0], recordFor('zzz.example')), 0);
});

test('dedupeSortedRecords collapses exact-duplicate records', () => {
  const a = recordFor('dup.example');
  const b = recordFor('dup.example');
  const c = recordFor('other.example');
  const sorted = sortRecords([a, b, c]);
  const deduped = dedupeSortedRecords(sorted);
  assert.equal(deduped.length, 2);
});

test('concatRecords / bufferToRecords round-trip preserves record boundaries and order', () => {
  const hosts = ['one.example', 'two.example', 'three.example'];
  const records = dedupeSortedRecords(sortRecords(hosts.map(recordFor)));
  const buf = concatRecords(records);
  assert.equal(buf.length, records.length * RECORD_LEN);
  const back = bufferToRecords(buf);
  assert.equal(back.length, records.length);
  for (let i = 0; i < records.length; i++) {
    assert.equal(Buffer.compare(back[i], records[i]), 0);
  }
});
