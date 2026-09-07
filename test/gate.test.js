'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildAllowlist, isAllowed, SHARED_HOST_APEXES } = require('../lib/gate');

test('allowlist gate drops exact matches and subdomains of allowed entries', () => {
  const allow = buildAllowlist({
    tranco: new Set(['google.com', 'bbc.co.uk']),
    metamaskWhitelist: ['metamask.io'],
    handBrandList: ['paypal.com'],
  });
  assert.equal(isAllowed('google.com', allow), true);
  assert.equal(isAllowed('mail.google.com', allow), true);
  assert.equal(isAllowed('a.b.mail.google.com', allow), true);
  assert.equal(isAllowed('news.bbc.co.uk', allow), true);
  assert.equal(isAllowed('metamask.io', allow), true);
  assert.equal(isAllowed('secure.paypal.com', allow), true); // subdomain of paypal.com
});

test('allowlist gate does NOT false-positive on lookalike domains', () => {
  const allow = buildAllowlist({
    tranco: new Set(['google.com']),
    metamaskWhitelist: [],
    handBrandList: ['paypal.com'],
  });
  assert.equal(isAllowed('evil-google.com', allow), false); // not a subdomain, just similar
  assert.equal(isAllowed('googlle.com', allow), false);
  assert.equal(isAllowed('paypal.com.evil.example', allow), false); // brand as a prefix label only
  assert.equal(isAllowed('login-paypal.com', allow), false); // hyphenated lookalike, not a subdomain
});

test('allowlist gate is a pure union of tranco + metamask whitelist + brand list', () => {
  const allow = buildAllowlist({ tranco: new Set(['a.com']), metamaskWhitelist: ['b.com'], handBrandList: ['c.com'] });
  assert.equal(allow.size, 3);
  for (const d of ['a.com', 'b.com', 'c.com']) assert.ok(allow.has(d));
});

test('allowlist gate: a tenant under a shared-hosting apex is never allowlisted by its platform', () => {
  const allow = new Set(['vercel.app']);
  assert.equal(isAllowed('foo.vercel.app', allow), false);
  assert.equal(isAllowed('a.b.foo.vercel.app', allow), false);
  assert.equal(isAllowed('vercel.app', allow), true); // the platform apex itself stays allowed
});

test('allowlist gate: a non-shared apex still protects its sub-domains (suffix walk unchanged)', () => {
  assert.equal(isAllowed('evil.mail.google.com', new Set(['google.com'])), true);
});

test('allowlist gate: an explicitly listed tenant host wins over the shared-apex rule', () => {
  assert.equal(isAllowed('foo.vercel.app', new Set(['foo.vercel.app'])), true);
  // ...and it wins even when the platform apex is listed too.
  assert.equal(isAllowed('foo.vercel.app', new Set(['foo.vercel.app', 'vercel.app'])), true);
});

test('SHARED_HOST_APEXES covers the tenant platforms that dominate hosted phishing kits', () => {
  for (const apex of ['vercel.app', 'netlify.app', 'pages.dev', 'github.io', 'workers.dev', 'blogspot.com', 'weebly.com', 'wixsite.com', 'webflow.io', 'gitbook.io', 'trycloudflare.com', 'amplifyapp.com']) {
    assert.ok(SHARED_HOST_APEXES.has(apex), apex + ' must be a shared-hosting apex');
    assert.equal(isAllowed('kit.' + apex, new Set([apex])), false);
  }
});
