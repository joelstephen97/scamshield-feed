'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { recordFor, sortRecords, dedupeSortedRecords, recordsEqual } = require('../lib/hash');
const { diffSortedRecords, applyDelta, serializeDelta, deserializeDelta } = require('../lib/delta');

function recordSet(hosts) {
  return dedupeSortedRecords(sortRecords(hosts.map(recordFor)));
}

test('apply(delta(old,new), old) === new — pure add', () => {
  const oldRecs = recordSet(['a.example', 'b.example', 'c.example']);
  const newRecs = recordSet(['a.example', 'b.example', 'c.example', 'd.example']);
  const delta = diffSortedRecords(oldRecs, newRecs);
  const applied = applyDelta(oldRecs, delta);
  assert.equal(recordsEqual(applied, newRecs), true);
  assert.equal(delta.added.length, 1);
  assert.equal(delta.removed.length, 0);
});

test('apply(delta(old,new), old) === new — pure remove', () => {
  const oldRecs = recordSet(['a.example', 'b.example', 'c.example']);
  const newRecs = recordSet(['a.example', 'c.example']);
  const delta = diffSortedRecords(oldRecs, newRecs);
  const applied = applyDelta(oldRecs, delta);
  assert.equal(recordsEqual(applied, newRecs), true);
  assert.equal(delta.added.length, 0);
  assert.equal(delta.removed.length, 1);
});

test('apply(delta(old,new), old) === new — mixed add+remove on a larger set', () => {
  const oldHosts = Array.from({ length: 50 }, (_, i) => `old-${i}.example`);
  const newHosts = oldHosts.slice(10).concat(Array.from({ length: 20 }, (_, i) => `new-${i}.example`));
  const oldRecs = recordSet(oldHosts);
  const newRecs = recordSet(newHosts);
  const delta = diffSortedRecords(oldRecs, newRecs);
  const applied = applyDelta(oldRecs, delta);
  assert.equal(recordsEqual(applied, newRecs), true);
});

test('empty-to-full and full-to-empty deltas round-trip', () => {
  const newRecs = recordSet(['x.example', 'y.example']);
  const delta1 = diffSortedRecords([], newRecs);
  assert.equal(recordsEqual(applyDelta([], delta1), newRecs), true);

  const delta2 = diffSortedRecords(newRecs, []);
  assert.equal(recordsEqual(applyDelta(newRecs, delta2), []), true);
});

test('serializeDelta / deserializeDelta round-trip the binary wire format', () => {
  const oldRecs = recordSet(['a.example', 'b.example']);
  const newRecs = recordSet(['b.example', 'c.example', 'd.example']);
  const delta = diffSortedRecords(oldRecs, newRecs);
  const buf = serializeDelta(delta);
  // header: addedCount u32 BE, removedCount u32 BE
  assert.equal(buf.readUInt32BE(0), delta.added.length);
  assert.equal(buf.readUInt32BE(4), delta.removed.length);
  const back = deserializeDelta(buf);
  assert.equal(recordsEqual(back.added, delta.added), true);
  assert.equal(recordsEqual(back.removed, delta.removed), true);
  const applied = applyDelta(oldRecs, back);
  assert.equal(recordsEqual(applied, newRecs), true);
});
