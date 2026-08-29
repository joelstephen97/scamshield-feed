'use strict';
/**
 * SCORE stage: Map<host, sourceKeys> -> tier.
 * tier "block" = >=2 independent sources OR any scoreWeight 'A' source.
 * tier "warn"  = exactly one source and it is scoreWeight 'B'.
 */
function scoreDomains(perSourceSets, sourceMetaByKey) {
  const scored = new Map();
  for (const [sourceKey, domainSet] of perSourceSets) {
    for (const host of domainSet) {
      let entry = scored.get(host);
      if (!entry) {
        entry = { sources: new Set() };
        scored.set(host, entry);
      }
      entry.sources.add(sourceKey);
    }
  }
  for (const entry of scored.values()) {
    let hasA = false;
    for (const key of entry.sources) {
      const meta = sourceMetaByKey.get(key);
      if (meta && meta.scoreWeight === 'A') {
        hasA = true;
        break;
      }
    }
    entry.tier = hasA || entry.sources.size >= 2 ? 'block' : 'warn';
  }
  return scored;
}

module.exports = { scoreDomains };
