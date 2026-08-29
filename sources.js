'use strict';
/**
 * Source registry for the parry-feed pipeline (v0.9 / Task B1).
 *
 * Every entry names: key, human name, license (+ licenseTier: 'green'
 * freely-redistributable or 'amber' isolate-in-this-GPL-repo), scoreWeight
 * ('A' = tier-1 quality, any single hit promotes a domain to block; 'B' =
 * tier-2/noisy, needs a 2nd corroborating source or stays warn-only), the
 * fetch URL, the parser format (see lib/parsers.js), and an `offlineFile`
 * name used by `--offline <fixturesDir>` / tests.
 *
 * scoreWeight defaults to licenseTier ('green'->'A', 'amber'->'B') per the
 * digest's SCORE-stage rule ("tier B warn = single tier-2/noisy source").
 * Two sources carry an explicit override annotation in the digest
 * ("-> tier-B weight") demoting them below their license tier's default —
 * see the `scoreWeight` field on each.
 *
 * REMOVED vs pipeline v1: OpenPhish (terms ban redistribution) and URLhaus
 * (auth-key + non-commercial + no-derivatives terms). See README "License
 * fix" / CHANGELOG section.
 */

const sources = [
  // ---- TIER-1 GREEN (freely redistributable) --------------------------
  {
    key: 'phishing-database',
    name: 'Phishing.Database',
    licenseTier: 'green',
    scoreWeight: 'A',
    license: 'MIT',
    homepage: 'https://github.com/Phishing-Database/Phishing.Database',
    url: 'https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-domains-ACTIVE.txt',
    format: 'list',
    offlineFile: 'phishing-database.txt',
    enabled: true,
  },
  {
    key: 'phishdestroy',
    name: 'PhishDestroy destroylist',
    licenseTier: 'green',
    scoreWeight: 'A',
    license: 'MIT',
    homepage: 'https://github.com/PhishDestroy/destroylist',
    url: 'https://raw.githubusercontent.com/phishdestroy/destroylist/main/dns/active_domains.txt',
    format: 'list',
    offlineFile: 'phishdestroy.txt',
    enabled: true,
  },
  {
    key: 'polkadot-phishing',
    name: 'polkadot-js/phishing',
    licenseTier: 'green',
    scoreWeight: 'A',
    license: 'Apache-2.0',
    homepage: 'https://github.com/polkadot-js/phishing',
    url: 'https://raw.githubusercontent.com/polkadot-js/phishing/master/all.json',
    format: 'polkadot-all-deny',
    offlineFile: 'polkadot-phishing.json',
    enabled: true,
  },
  {
    key: 'metamask-eth-phishing',
    name: 'MetaMask eth-phishing-detect (blacklist)',
    licenseTier: 'green',
    scoreWeight: 'A',
    license: 'DBAD-1.2 (permissive; data reused, no code)',
    homepage: 'https://github.com/MetaMask/eth-phishing-detect',
    url: 'https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json',
    format: 'metamask-config',
    offlineFile: 'metamask-eth-phishing.json',
    enabled: true,
    // This source ALSO feeds the allowlist gate: its `whitelist` array is
    // unioned into Tranco + hand brand list (see build.js loadAllowlist()).
    contributesAllowlist: true,
  },
  {
    key: 'blocklist-project-phishing',
    name: 'The Block List Project (phishing.txt)',
    licenseTier: 'green',
    // Digest: "moderate quality -> tier-B weight" — explicit override.
    scoreWeight: 'B',
    license: 'Unlicense',
    homepage: 'https://github.com/blocklistproject/Lists',
    url: 'https://raw.githubusercontent.com/blocklistproject/Lists/main/phishing.txt',
    format: 'hosts',
    offlineFile: 'blocklist-project-phishing.txt',
    enabled: true,
  },
  {
    key: 'global-anti-scam-org',
    name: 'GlobalAntiScamOrg-blocklist',
    licenseTier: 'green',
    scoreWeight: 'A',
    license: 'BSD-3-Clause',
    homepage: 'https://github.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist',
    url: 'https://raw.githubusercontent.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist/main/global-anti-scam-org-scam-urls-pihole.txt',
    format: 'list',
    offlineFile: 'global-anti-scam-org.txt',
    enabled: true,
  },
  {
    key: 'durablenapkin-scamblocklist',
    name: 'durablenapkin/scamblocklist',
    licenseTier: 'green',
    scoreWeight: 'A',
    license: 'MIT',
    homepage: 'https://github.com/durablenapkin/scamblocklist',
    url: 'https://raw.githubusercontent.com/durablenapkin/scamblocklist/master/hosts.txt',
    format: 'hosts',
    offlineFile: 'durablenapkin-scamblocklist.txt',
    enabled: true,
  },

  // ---- TIER-2 AMBER (isolated in this GPL feed repo) ------------------
  {
    key: 'malware-filter-phishing',
    name: 'malware-filter phishing-filter',
    licenseTier: 'amber',
    scoreWeight: 'B',
    license: 'CC BY-SA 4.0',
    homepage: 'https://gitlab.com/malware-filter/phishing-filter',
    // GitLab Pages published mirror (the repo itself only holds build
    // scripts; the list.txt from the digest is a generated CI artifact
    // served from Pages, not committed to the repo tree).
    url: 'https://malware-filter.gitlab.io/phishing-filter/phishing-filter-agh.txt',
    format: 'adblock',
    offlineFile: 'malware-filter-phishing.txt',
    enabled: true,
  },
  {
    key: 'hagezi-fake',
    name: "HaGeZi fake-shop/subscription-trap list",
    licenseTier: 'amber',
    scoreWeight: 'B',
    license: 'GPL-3.0',
    homepage: 'https://github.com/hagezi/dns-blocklists',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/fake-onlydomains.txt',
    format: 'list',
    offlineFile: 'hagezi-fake.txt',
    enabled: true,
  },
  {
    key: 'hagezi-tif-medium',
    name: 'HaGeZi Threat-Intelligence-Feeds (medium)',
    licenseTier: 'amber',
    scoreWeight: 'B',
    license: 'GPL-3.0',
    homepage: 'https://github.com/hagezi/dns-blocklists',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif.medium-onlydomains.txt',
    format: 'list',
    offlineFile: 'hagezi-tif-medium.txt',
    enabled: true,
  },
  {
    key: 'scamsniffer',
    name: 'ScamSniffer scam-database',
    licenseTier: 'amber',
    scoreWeight: 'B',
    license: 'GPL-3.0',
    homepage: 'https://github.com/scamsniffer/scam-database',
    url: 'https://raw.githubusercontent.com/scamsniffer/scam-database/main/blacklist/domains.json',
    format: 'json-array',
    offlineFile: 'scamsniffer.json',
    enabled: true,
  },
  {
    key: 'jarelllama-scam-blocklist',
    name: 'jarelllama/Scam-Blocklist',
    licenseTier: 'amber',
    scoreWeight: 'B',
    license: 'GPL-3.0',
    homepage: 'https://github.com/jarelllama/Scam-Blocklist',
    url: 'https://raw.githubusercontent.com/jarelllama/Scam-Blocklist/main/lists/wildcard_domains/scams.txt',
    format: 'list',
    offlineFile: 'jarelllama-scam-blocklist.txt',
    enabled: true,
  },

  // ---- PENDING JOEL'S EMAILS — do NOT wire until permission/license is
  // confirmed (see research-threat-feeds.md). Left commented out on
  // purpose so `require('./sources')` never sees or fetches them.
  //
  // {
  //   key: 'cert-pl',
  //   name: 'CERT Polska',
  //   licenseTier: 'amber',
  //   scoreWeight: 'B',
  //   license: 'no published license — pending permission',
  //   homepage: 'https://cert.pl/en/',
  //   url: 'https://hole.cert.pl/domains/domains.txt',
  //   format: 'list',
  //   pendingPermission: true,
  //   enabled: false,
  // },
  // {
  //   key: 'discord-antiscam',
  //   name: 'Discord-AntiScam',
  //   licenseTier: 'amber',
  //   scoreWeight: 'B',
  //   license: 'no license file — pending permission',
  //   homepage: 'https://github.com/Discord-AntiScam/scam-links',
  //   url: 'https://raw.githubusercontent.com/Discord-AntiScam/scam-links/main/list.txt',
  //   format: 'list',
  //   pendingPermission: true,
  //   enabled: false,
  // },
];

/**
 * HaGeZi risk-table-only lists: NOT part of the block/warn union or SCORE
 * stage — they feed risk.json's dyndns[]/hosters[] evidence tables only
 * (digest: "Also take: ... dyndns (1,540), badware-hosters (1,238) as RISK
 * TABLES (separate outputs, not blocklist)").
 */
const riskTableSources = [
  {
    key: 'hagezi-dyndns',
    name: 'HaGeZi Dynamic DNS list',
    license: 'GPL-3.0',
    homepage: 'https://github.com/hagezi/dns-blocklists',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dyndns-onlydomains.txt',
    format: 'list',
    offlineFile: 'hagezi-dyndns.txt',
    riskKey: 'dyndns',
    enabled: true,
  },
  {
    key: 'hagezi-hoster',
    name: 'HaGeZi Badware Hoster list',
    license: 'GPL-3.0',
    homepage: 'https://github.com/hagezi/dns-blocklists',
    url: 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/hoster-onlydomains.txt',
    format: 'list',
    offlineFile: 'hagezi-hoster.txt',
    riskKey: 'hosters',
    enabled: true,
  },
];

/**
 * Hand brand list: a small set of heavily-impersonated consumer brands
 * (banking/payments/big-tech/exchanges) unioned into the allowlist gate
 * alongside Tranco top-100k and MetaMask's whitelist. Deliberately short —
 * this is a hand-curated FP guard, not an attempt at a full allowlist.
 */
const handBrandList = [
  'google.com', 'accounts.google.com', 'microsoft.com', 'live.com', 'office.com',
  'apple.com', 'icloud.com', 'amazon.com', 'paypal.com', 'facebook.com',
  'instagram.com', 'whatsapp.com', 'x.com', 'twitter.com', 'linkedin.com',
  'netflix.com', 'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com',
  'hsbc.com', 'coinbase.com', 'binance.com', 'kraken.com', 'metamask.io',
  'wetransfer.com', 'dropbox.com', 'adobe.com', 'dhl.com', 'fedex.com',
  'ups.com', 'usps.com', 'irs.gov', 'gov.uk', 'ebay.com', 'steamcommunity.com',
  'roblox.com', 'discord.com', 'yahoo.com', 'outlook.com', 'zoom.us',
];

module.exports = { sources, riskTableSources, handBrandList };
