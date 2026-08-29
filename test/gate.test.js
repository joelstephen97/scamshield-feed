'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildAllowlist, isAllowed } = require('../lib/gate');

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
