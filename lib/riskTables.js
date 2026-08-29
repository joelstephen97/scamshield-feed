'use strict';
/**
 * risk.json builder: { tlds:{".top":w,...}, dyndns:[hashed u32,...], hosters:[...] }
 *
 * dyndns/hosters come from HaGeZi's dedicated risk lists (see sources.js
 * riskTableSources) and are hashed the same way as block/warn records (top
 * 32 bits of SHA-256(hostname), read big-endian) — these are evidence
 * tables for B3's detector, not blocklist entries, so no verify byte and no
 * 5-byte record format is needed for them.
 *
 * The "most-abused-TLD" table has no machine-readable source in the
 * research digest (HaGeZi documents it as prose in README/CHEATSHEET, not a
 * fetchable file), so it is hand-curated here from widely-published abuse
 * telemetry (Spamhaus/Interisle "World's Most Abused TLDs" style reporting).
 * Weight scale: 3 = extreme abuse rate, 2 = high, 1 = elevated.
 */
const { sha256 } = require('./hash');

const MOST_ABUSED_TLDS = {
  '.top': 3, '.xyz': 3, '.icu': 3, '.cyou': 3, '.cfd': 3, '.sbs': 3,
  '.rest': 2, '.bond': 2, '.buzz': 2, '.mom': 2, '.beauty': 2, '.cam': 2,
  '.quest': 2, '.fit': 2, '.support': 2, '.work': 2, '.click': 2, '.lol': 2,
  '.gq': 3, '.cf': 3, '.tk': 3, '.ml': 3, '.ga': 3,
  '.rocks': 1, '.live': 1, '.club': 1, '.online': 1, '.host': 1, '.site': 1,
  '.info': 1, '.pw': 2, '.biz': 1, '.win': 2, '.loan': 2, '.men': 2,
  '.date': 2, '.stream': 2, '.download': 2, '.review': 1, '.trade': 2,
  '.accountant': 2, '.science': 1, '.party': 2, '.faith': 2,
};

function hashedU32(hostname) {
  return sha256(hostname).readUInt32BE(0);
}

/** hosts -> sorted, de-duped array of hashed u32 values. */
function toHashedU32List(hosts) {
  const set = new Set();
  for (const h of hosts) set.add(hashedU32(h));
  return Array.from(set).sort((a, b) => a - b);
}

function buildRiskTable(dyndnsHosts, hosterHosts) {
  return {
    tlds: MOST_ABUSED_TLDS,
    dyndns: toHashedU32List(dyndnsHosts),
    hosters: toHashedU32List(hosterHosts),
  };
}

module.exports = { MOST_ABUSED_TLDS, hashedU32, toHashedU32List, buildRiskTable };
