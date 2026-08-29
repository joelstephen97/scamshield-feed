'use strict';
/**
 * Delta computation/application over sorted, de-duped arrays of 5-byte
 * records (see lib/hash.js). Binary wire format:
 *   header: addedCount u32 BE, removedCount u32 BE
 *   then `added` records (sorted), then `removed` records (sorted).
 */
const { RECORD_LEN } = require('./hash');

/** Both inputs must already be sorted + de-duped. */
function diffSortedRecords(oldRecords, newRecords) {
  const added = [];
  const removed = [];
  let i = 0;
  let j = 0;
  while (i < oldRecords.length && j < newRecords.length) {
    const cmp = Buffer.compare(oldRecords[i], newRecords[j]);
    if (cmp === 0) {
      i++;
      j++;
    } else if (cmp < 0) {
      removed.push(oldRecords[i]);
      i++;
    } else {
      added.push(newRecords[j]);
      j++;
    }
  }
  while (i < oldRecords.length) removed.push(oldRecords[i++]);
  while (j < newRecords.length) added.push(newRecords[j++]);
  return { added, removed };
}

/** Reconstructs the new sorted record array from the old one + a delta. */
function applyDelta(oldRecords, delta) {
  const removedSet = new Set(delta.removed.map((b) => b.toString('hex')));
  const kept = oldRecords.filter((b) => !removedSet.has(b.toString('hex')));
  const merged = kept.concat(delta.added);
  merged.sort(Buffer.compare);
  return merged;
}

function serializeDelta(delta) {
  const header = Buffer.alloc(8);
  header.writeUInt32BE(delta.added.length, 0);
  header.writeUInt32BE(delta.removed.length, 4);
  return Buffer.concat([header, ...delta.added, ...delta.removed]);
}

function deserializeDelta(buf) {
  const addedCount = buf.readUInt32BE(0);
  const removedCount = buf.readUInt32BE(4);
  let off = 8;
  const added = [];
  for (let k = 0; k < addedCount; k++) {
    added.push(buf.subarray(off, off + RECORD_LEN));
    off += RECORD_LEN;
  }
  const removed = [];
  for (let k = 0; k < removedCount; k++) {
    removed.push(buf.subarray(off, off + RECORD_LEN));
    off += RECORD_LEN;
  }
  return { added, removed };
}

module.exports = { diffSortedRecords, applyDelta, serializeDelta, deserializeDelta };
