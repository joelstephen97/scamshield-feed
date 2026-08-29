# Attribution

parry-feed aggregates domain-reputation data from the public sources listed
below. `build.js` and everything else in this repository is original code by
Joel Stephen, licensed GPL-3.0 (see `LICENSE`). The upstream **data** each
source contributes is redistributed here under its own license, unmodified in
substance (only normalized: lowercased, punycoded, scheme/path/port stripped
— see `lib/normalize.js`).

## Blocklist sources

| Source | License | Score weight | Homepage |
|---|---|---|---|
| Phishing.Database | MIT | Tier-1 (A) | https://github.com/Phishing-Database/Phishing.Database |
| PhishDestroy destroylist | MIT | Tier-1 (A) | https://github.com/PhishDestroy/destroylist |
| polkadot-js/phishing | Apache-2.0 | Tier-1 (A) | https://github.com/polkadot-js/phishing |
| MetaMask eth-phishing-detect | DBAD-1.2 (data reused, no code) | Tier-1 (A) | https://github.com/MetaMask/eth-phishing-detect |
| The Block List Project (phishing.txt) | Unlicense | Tier-2 (B — moderate quality) | https://github.com/blocklistproject/Lists |
| GlobalAntiScamOrg-blocklist | BSD-3-Clause | Tier-1 (A) | https://github.com/elliotwutingfeng/GlobalAntiScamOrg-blocklist |
| durablenapkin/scamblocklist | MIT | Tier-1 (A) | https://github.com/durablenapkin/scamblocklist |
| malware-filter phishing-filter | CC BY-SA 4.0 | Tier-2 (B) | https://gitlab.com/malware-filter/phishing-filter |
| HaGeZi fake-shop/subscription-trap list | GPL-3.0 | Tier-2 (B) | https://github.com/hagezi/dns-blocklists |
| HaGeZi Threat Intelligence Feeds (medium) | GPL-3.0 | Tier-2 (B) | https://github.com/hagezi/dns-blocklists |
| ScamSniffer scam-database | GPL-3.0 | Tier-2 (B) | https://github.com/scamsniffer/scam-database |
| jarelllama/Scam-Blocklist | GPL-3.0 | Tier-2 (B — NRD-heavy, noisy) | https://github.com/jarelllama/Scam-Blocklist |

CC BY-SA 4.0 note (malware-filter phishing-filter): that list itself
launders data originally sourced from OpenPhish, PhishTank, and IPThreat —
none of which permit direct redistribution by us. We only consume
malware-filter's own CC-BY-SA-licensed republication, which is the license
that actually governs this feed artifact; the underlying upstreams get no
separate credit here beyond this note, since we never touch them directly.

## Risk-table-only sources

Not part of the block/warn union — feed `risk.json`'s `dyndns[]` / `hosters[]`
evidence tables only.

| Source | License | Homepage |
|---|---|---|
| HaGeZi Dynamic DNS list | GPL-3.0 | https://github.com/hagezi/dns-blocklists |
| HaGeZi Badware Hoster list | GPL-3.0 | https://github.com/hagezi/dns-blocklists |

The most-abused-TLD weight table in `risk.json` (`lib/riskTables.js`) has no
machine-readable upstream source — HaGeZi documents it as prose, not a
fetchable file — so it is hand-curated from widely published abuse telemetry
(Spamhaus/Interisle "World's Most Abused TLDs" style reporting), not scraped
from any single licensed dataset.

## Allowlist inputs

| Source | License | Use |
|---|---|---|
| Tranco top-1m list | Tranco research license (free for use) | top-100k subtracted as the primary FP guard |
| MetaMask eth-phishing-detect `whitelist` | DBAD-1.2 | unioned into the allowlist gate |

Plus a small hand-curated list of heavily-impersonated consumer brand
domains (`handBrandList` in `sources.js`) — not sourced from any external
license, written by Joel Stephen.

## Removed vs pipeline v1

**OpenPhish** and **URLhaus (abuse.ch)** were removed in v2. Both were used
by pipeline v1 but their terms prohibit redistribution of the raw feed
(OpenPhish: no redistribution, no commercial use; URLhaus: auth-key-gated,
non-commercial, no-derivatives). See `README.md`'s License section and the
CHANGELOG entry there.

## Excluded (evaluated, not used)

PhishTank direct (restrictive terms; reached indirectly via malware-filter's
laundered feed instead), Google Safe Browsing / AdGuard Browsing Security
(real-time hash-prefix lookups would violate the zero-telemetry design),
PhishFort (dead), CryptoScamDB (dead), TweetFeed (CC0, candidate for a future
heuristic tier, not this pipeline).

## Pending permission (not wired)

CERT Polska and Discord-AntiScam are commented out in `sources.js`
(`pendingPermission: true`) until their licensing status is confirmed
directly with the maintainers. Neither is fetched by `build.js`.
