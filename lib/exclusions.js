'use strict';
/**
 * Explicit false-positive exclusions: a hand-curated list of legitimate
 * domains that upstream blocklists wrongly list (data/exclusions.txt).
 * Entries join the allowlist gate, so a host equal to or under one of them is
 * never published. Format: one domain per line, `#` starts a comment.
 */
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_EXCLUSIONS_FILE = path.join(__dirname, '..', 'data', 'exclusions.txt');

function parseExclusions(text) {
  const out = new Set();
  for (const raw of String(text || '').split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim().toLowerCase();
    if (!line) continue;
    const host = line.replace(/^www\./, '');
    if (/^[a-z0-9.-]+\.[a-z0-9-]+$/.test(host)) out.add(host);
  }
  return out;
}

function loadExclusions(file = DEFAULT_EXCLUSIONS_FILE) {
  try { return parseExclusions(fs.readFileSync(file, 'utf8')); } catch (_) { return new Set(); }
}

module.exports = { parseExclusions, loadExclusions, DEFAULT_EXCLUSIONS_FILE };
