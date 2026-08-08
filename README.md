# scamshield-feed

Curated blocklist feed for [ScamShield](https://github.com/joelstephen97/scamshield),
rebuilt daily by GitHub Actions.

**Consumed by the extension at:**
`https://raw.githubusercontent.com/joelstephen97/scamshield-feed/main/blocklist.json`

## What it is

`build.js` pulls live phishing / malware-distribution URLs from two public
sources, reduces them to domain-level block rules, and applies aggressive
false-positive guards:

| Step | Detail |
|---|---|
| Sources | [OpenPhish](https://openphish.com/) community feed, [URLhaus](https://urlhaus.abuse.ch/) online URLs |
| FP guard | Anything whose registrable domain is in the **Tranco top-10k** is dropped — a compromised big site is never blocked wholesale |
| Shared hosting | On platforms like `pages.dev` / `netlify.app` / `github.io`, only the exact abusive hostname is blocked, never the platform |
| Path gateways | IPFS gateways, archive.org, Drive/Dropbox links are skipped entirely (abuse lives in the path; hostname blocking would break the service) |
| Suffix safety | Multi-label public suffixes (`com.bn`, `co.uk`, …) can never become a rule |
| Cap | 5,000 rules (ScamShield's dynamic-rule budget) |

Output format is what ScamShield's download-only OTA updater expects:

```json
{ "version": 20673, "rules": ["||evil.example^", "..."] }
```

`version` is days-since-epoch, so it increments exactly once per day.

## Privacy

This is a build-time artifact. The extension **downloads** this static file on
a 12-hour alarm; nothing about any user or their browsing is ever sent
anywhere. See ScamShield's privacy policy.

## Regenerate locally

```
node build.js                                  # blocklist.json (feed)
node build.js --snapshot path/to/blocklist.json # static DNR ruleset for the extension bundle
```
