# parry-feed

Threat-feed pipeline for [ScamShield](https://github.com/joelstephen97/scamshield)
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
           exact-NN.jsonl.gz shards, risk.json, nrd.bloom, legacy blocklist.json)
```

`nrd.bloom` (Task C3, "New site" signal) is a separate stage: HaGeZi's
newly-registered-domains lists run into the millions, so they never touch
the block/warn union or risk.json — they are folded into their own compact
Bloom filter instead. See `lib/bloom.js` for the file format and the exact
hash-index derivation, mirrored byte-for-byte in the extension's
`engine/bloom.js`.

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
| `nrd.bloom` | Bloom filter (16-byte header + bit array) over HaGeZi's 14-day newly-registered-domains window; `meta.json`'s `nrd` block carries its sha256/n/mBits/k |
| `/blocklist.json` (repo root) | **legacy, unchanged since v1**: `{ version, rules: ["||domain^"] }`, cap 5000 — pre-0.9 installs poll this forever |

### Versioning

`version` is a UTC `yyyymmddHH` string. Outputs are overwritten in place
under `v/current/` on every run (no per-version directory pile-up in git);
immutability for jsDelivr comes from tagging the commit `v<version>` after
each publish, so `https://cdn.jsdelivr.net/gh/joelstephen97/scamshield-feed@v<version>/v/current/...`
always resolves to that exact snapshot even though the branch tip moves on.
`meta.json`'s `urls.fallback` points at the mutable `main` branch path for
when jsDelivr is unreachable.

Deltas only exist for the block tier (`set40.bin`). The warn tier has no
delta mechanism — `warn40.bin` is small enough to refetch in full each cycle.

## Hot list

The 6-hourly build above is deliberately conservative (poisoning guards,
2-source corroboration, full re-fetch of every source). That is too slow for
domains that live for minutes — DNS takedowns and browser blocklists mean a
fresh phishing kit's useful life is often shorter than 6 hours. `scripts/
build-hot.js` runs **hourly** against a narrow set of the fastest-moving
licence-vetted sources already in `sources.js` (PhishDestroy, MetaMask
eth-phishing-detect, Phishing.Database's "NEW today" delta files,
malware-filter's phishing-filter, and HaGeZi's TIF-medium list — see
`HOT_SOURCE_KEYS` in the script) and publishes a small, fast-changing
`hot.json` on its own **orphan branch, `hot`**, so it never adds to `main`'s
history:

```
https://raw.githubusercontent.com/joelstephen97/scamshield-feed/hot/hot.json
```

"Hot" means **first seen by this builder within the last 48 hours** — a host
drops out of `hot.json`'s `domains[]` once it ages past the window (it is
presumed already covered by the next 6-hourly full build by then), and a
host absent from every hot source for two consecutive hourly runs is listed
once in `removed[]` so a consumer can evict it from a local cache. State
(`hot-state.json`, first-seen timestamps + per-source counts) is versioned
alongside `hot.json` on the `hot` branch so each hourly run can pick up
where the last one left off. A per-source growth guard rejects any source
whose host count jumps more than 25% versus its last run (a feed outage or
poisoning symptom) rather than ingesting a spike. Output caps at 4,000
domains / 300 paths (newest-first) per run.

`hot.json` format:

```json
{
  "v": 1,
  "generatedAt": 1789000000000,
  "ttlMinutes": 360,
  "domains": [{ "h": "new-kit.example", "s": "pd", "t": 29816666 }],
  "paths": [{ "h": "rb.gy", "p": "/88c5r3", "s": "pdb", "t": 29816666 }],
  "removed": ["gone.example"]
}
```

`s` is a short source tag (`pd` PhishDestroy, `mm` MetaMask, `pdb`
Phishing.Database, `mf` malware-filter, `hz` HaGeZi TIF); `t` is the
first-seen time in minutes-since-epoch. `paths[]` exists because some abuse
lives on a shared, otherwise-legitimate host (URL shorteners, Google
Forms/Sites, Linktree, Notion pages) where the *host* is correctly
Tranco-allowlisted but a specific *path* on it is not — see
`SHARED_PATH_HOSTS` in `scripts/build-hot.js`.

Run it locally: `node scripts/build-hot.js` (writes `hot.json` +
`hot-state.json` at the repo root — both are gitignored on `main`, since
they only ever live on the `hot` branch). The GitHub Actions workflow
(`.github/workflows/hot.yml`) runs it hourly, restores the previous
`hot-state.json` from the `hot` branch, then force-pushes a single fresh
commit to `hot` (no history growth) — see the workflow for the orphan-branch
publish mechanics. Both `hot.yml` and `build.yml` share a `concurrency`
group (`feed-publish`) so the hourly and 6-hourly publishers never race each
other's push.

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

**The ScamShield extension itself stays MIT.** It only *downloads* this repo's
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
  downstream ScamShield install in breach of those terms.
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
