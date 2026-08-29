# parry-feed

Threat-feed pipeline for [Parry](https://github.com/joelstephen97/scamshield)
(formerly ScamShield). Aggregates ~1M+ phishing/scam domains from a dozen
license-vetted public feeds, scores them by source corroboration, and
publishes hash-based block/warn sets that the extension consumes over
jsDelivr with 6-hourly deltas.

## Pipeline (v2, Task B1)

```
FETCH (per source, continue-on-error, reuse last-good on failure,
       reject a source if its count shrinks >30% — poisoning guard)
  -> NORMALIZE (lowercase; strip scheme/port/path/query; punycode;
                strip leading www.; drop IPs/bare TLDs/len>253;
                KEEP FULL HOSTNAME — never collapse to eTLD+1, so a
                phishing tenant on *.pages.dev never blocks the platform)
  -> ALLOWLIST GATE (subtract Tranco top-100k UNION MetaMask's own
                      whitelist UNION a hand brand list)
  -> SCORE (tier "block" = >=2 independent sources OR any tier-1 source;
            tier "warn" = a single tier-2/noisy source)
  -> EMIT (meta.json, set40.bin, warn40.bin, delta-<prev>.bin,
           exact-NN.jsonl.gz shards, risk.json, legacy blocklist.json)
```

Run it:

```
node build.js                      # real build: fetches live sources,
                                    # writes v/current/* + blocklist.json
node build.js --dry-run            # fetches live sources, builds to a
                                    # temp dir, prints per-source stats,
                                    # touches nothing under version control
node build.js --offline <dir>      # builds from local fixture files
                                    # (used by the test suite)
```

Node >=20, **zero npm dependencies** — everything is `node:fs`, `node:zlib`,
`node:crypto`, `node:url`, `node:net`, and the global `fetch`. The tiny
CSV/hosts/adblock/JSON parsers live in `lib/parsers.js`; there is no
public-suffix-list dependency because the pipeline never collapses hostnames
to eTLD+1 (see NORMALIZE above) and the allowlist gate only needs a
label-boundary suffix walk (`lib/gate.js`), not real PSL awareness.

### Tests

```
node --test                        # auto-discovers test/*.test.js
node --test "test/**/*.test.js"    # equivalent, explicit glob
```

36 tests across normalization edge cases, the allowlist gate, tier
scoring (2-source promotion vs single-source warn), the >30% shrink
poisoning guard, delta correctness (`apply(delta(old,new), old) === new`),
legacy `blocklist.json` format stability, and 5-byte record sort order —
plus end-to-end offline-fixture builds that check the full output contract
and byte-identical determinism on reruns.

## Sources

See `sources.js` for the full registry (license, score weight, fetch URL,
parser format) and `ATTRIBUTION.md` for the complete licensed source list
with homepages. Summary: 12 blocklist sources (7 tier-1 "green" — freely
redistributable — and 5 tier-2 "amber" — isolated in this GPL-3.0 repo) plus
2 risk-table-only sources feeding `risk.json`. Two more sources (CERT Polska,
Discord-AntiScam) are commented out in `sources.js`, pending direct
permission from their maintainers.

## Output contract

Published under `v/current/` (overwritten in place each run — see
"Versioning" below) plus the legacy file at the repo root:

| File | Contents |
|---|---|
| `meta.json` | version, counts, sha256 of set40/delta, prev version, CDN URLs, TTL |
| `set40.bin` | sorted binary 5-byte records (block tier) — high 32 bits of SHA-256(hostname) + 1 verify byte |
| `warn40.bin` | same record format, warn tier |
| `delta-<prevVersion>.bin` | `{addedCount u32, removedCount u32}` header + sorted added/removed records (block tier only) |
| `exact-<NN>.jsonl.gz` | 256 shards (NN = first hash byte, hex) of `{"d":"domain","s":["source",...]}` for warning-page provenance |
| `risk.json` | `{ tlds, dyndns: [hashed u32...], hosters: [...] }` evidence tables |
| `/blocklist.json` (repo root) | **legacy, unchanged since v1**: `{ version, rules: ["||domain^"] }`, cap 5000 — pre-0.9 installs poll this forever |

### Versioning

`version` is a UTC `yyyymmddHH` string. Outputs are overwritten in place
under `v/current/` on every run (no per-version directory pile-up in git);
immutability for jsDelivr comes from tagging the commit `v<version>` after
each publish, so `https://cdn.jsdelivr.net/gh/joelstephen97/parry-feed@v<version>/v/current/...`
always resolves to that exact snapshot even though the branch tip moves on.
`meta.json`'s `urls.fallback` points at the mutable `main` branch path for
when jsDelivr is unreachable.

Deltas only exist for the block tier (`set40.bin`). The warn tier has no
delta mechanism — `warn40.bin` is small enough to refetch in full each cycle.

## License

**This repository (code) is GPL-3.0** (`LICENSE`) — several of the
tier-2 data sources it aggregates (HaGeZi, ScamSniffer, jarelllama/Scam-Blocklist)
are themselves GPL-3.0, and GPL is viral over derivative works, so the
pipeline that merges their data in must carry the same license. `build.js`
and every file under `lib/` are original code by Joel Stephen.

**The generated data output** (`v/current/*`, `blocklist.json`) is a
compilation of many individually-licensed sources — see `ATTRIBUTION.md` for
the full per-source breakdown, including the CC BY-SA 4.0 attribution note
for malware-filter's laundered OpenPhish/PhishTank/IPThreat channel.

**The Parry extension itself stays MIT.** It only *downloads* this repo's
published data output at runtime (over jsDelivr/raw.githubusercontent) — it
never links against, imports, or bundles any GPL code from this repo. Under
GPL-3.0, distributing a program that merely fetches data produced by GPL
tooling does not make the consuming program a derivative work; only code
that statically or dynamically links against GPL-licensed code becomes
GPL-encumbered. The extension repo and this feed repo are intentionally kept
separate for exactly this reason.

## Changelog

### v2 (Task B1 — pipeline rebuild)

- **License fix:** removed **OpenPhish** and **URLhaus (abuse.ch)**. Both
  were used in v1 but their terms forbid redistribution (OpenPhish: no
  redistribution/no commercial use; URLhaus: auth-key-gated, non-commercial,
  no-derivatives). Continuing to republish their data would have put every
  downstream Parry install in breach of those terms.
- Replaced the two-source v1 pipeline with a 12-source registry
  (`sources.js`) split into tier-1 "green" (freely redistributable) and
  tier-2 "amber" (GPL-isolated) by license, and into scoreWeight A/B by
  data quality for the SCORE stage.
- Normalization no longer collapses hostnames to eTLD+1 — pipeline v1's
  `registrableDomain()`/`SHARED_HOSTS` collapsing logic is preserved in
  `lib/normalize.js` (tested) but is no longer on the emit path, since
  collapsing would merge unrelated tenants on shared hosting (`*.pages.dev`,
  `*.vercel.app`, etc.) into one over-broad rule.
- Raised the Tranco allowlist gate from top-10k to top-100k, and unioned in
  MetaMask's own whitelist plus a hand-curated brand list.
- New binary hash-set output format (`set40.bin`/`warn40.bin`/delta) so the
  extension can ship ~1M+ domains without JSON-inflating `storage.local`;
  see the B2 spec in the SDD research digest for the consumer side.
- Legacy root `blocklist.json` is preserved byte-for-byte in format and
  path — pre-0.9 installs keep working unmodified.

### v1

Two-source (OpenPhish + URLhaus) pipeline, registrable-domain collapsing,
Tranco top-10k gate, single `blocklist.json` output. See git history prior
to the v2 commit for the original `build.js`.

## Privacy

Still a pure build-time artifact. Nothing about any user or their browsing
is ever sent anywhere — the extension only downloads this repo's static
published output on a periodic alarm.
