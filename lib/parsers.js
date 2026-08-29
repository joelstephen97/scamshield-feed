'use strict';
/**
 * Tiny, dependency-free parsers for the raw feed formats used by
 * sources.js. Each returns an array of raw entries (URLs or hostnames) that
 * still need lib/normalize.js applied.
 */

/** One domain (or URL) per line; '#' / '!' comment lines and blanks skipped. */
function parseList(text) {
  const out = [];
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('!')) continue;
    out.push(line);
  }
  return out;
}

/** "hosts" file format: "<ip> <domain> [aliases...]", comments with '#'. */
function parseHosts(text) {
  const out = [];
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(/\s+/);
    for (let i = 1; i < parts.length; i++) {
      if (parts[i].startsWith('#')) break;
      out.push(parts[i]);
    }
  }
  return out;
}

/** Adblock-style "||domain^" lines (also tolerates plain domains/comments). */
function parseAdblock(text) {
  const out = [];
  for (const rawLine of String(text).split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('!') || line.startsWith('#')) continue;
    const m = line.match(/^\|\|([^^/*]+)\^?/);
    out.push(m ? m[1] : line);
  }
  return out;
}

/** A bare JSON array of hostname strings. */
function parseJsonArray(text) {
  const data = JSON.parse(text);
  if (!Array.isArray(data)) throw new Error('parseJsonArray: expected a top-level JSON array');
  return data.filter((x) => typeof x === 'string');
}

/** MetaMask eth-phishing-detect src/config.json shape. */
function parseMetamaskConfig(text) {
  const data = JSON.parse(text);
  return {
    blacklist: Array.isArray(data.blacklist) ? data.blacklist : [],
    whitelist: Array.isArray(data.whitelist) ? data.whitelist : [],
  };
}

/** polkadot-js/phishing all.json shape: { allow: [...], deny: [...] }. */
function parsePolkadotAllDeny(text) {
  const data = JSON.parse(text);
  return {
    deny: Array.isArray(data.deny) ? data.deny : [],
    allow: Array.isArray(data.allow) ? data.allow : [],
  };
}

const PARSERS = {
  list: parseList,
  hosts: parseHosts,
  adblock: parseAdblock,
  'json-array': parseJsonArray,
};

module.exports = {
  parseList,
  parseHosts,
  parseAdblock,
  parseJsonArray,
  parseMetamaskConfig,
  parsePolkadotAllDeny,
  PARSERS,
};
