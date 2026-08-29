'use strict';
/**
 * Tranco top-list fetch + parse. Kept from pipeline v1 (minimal hand-rolled
 * zip reader, no dependency) but raised from top-10k to top-100k per the
 * digest's ALLOWLIST GATE spec.
 */
const zlib = require('node:zlib');

const TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip';
const DEFAULT_TOP_N = 100000;

/** Parses "rank,domain" CSV text into a Set of the first n domains. */
function parseTrancoCsv(csv, n) {
  const top = new Set();
  for (const line of csv.split('\n')) {
    const [, domain] = line.trim().split(',');
    if (domain) top.add(domain.toLowerCase());
    if (top.size >= n) break;
  }
  return top;
}

/** Minimal local-file-header zip reader: single-entry zip -> inflated text. */
function inflateSingleEntryZip(buf) {
  const nameLen = buf.readUInt16LE(26);
  const extraLen = buf.readUInt16LE(28);
  const method = buf.readUInt16LE(8);
  const dataStart = 30 + nameLen + extraLen;
  const raw = buf.subarray(dataStart);
  return method === 0 ? raw.toString('utf8') : zlib.inflateRawSync(raw).toString('utf8');
}

async function fetchTrancoTop(n = DEFAULT_TOP_N, url = TRANCO_URL) {
  const res = await fetch(url, { redirect: 'follow' });
  if (!res.ok) throw new Error(`tranco -> HTTP ${res.status}`);
  const buf = Buffer.from(await res.arrayBuffer());
  const csv = inflateSingleEntryZip(buf);
  return parseTrancoCsv(csv, n);
}

module.exports = { TRANCO_URL, DEFAULT_TOP_N, parseTrancoCsv, inflateSingleEntryZip, fetchTrancoTop };
