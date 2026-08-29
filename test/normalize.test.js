'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeHost, registrableDomain } = require('../lib/normalize');

test('lowercases and strips scheme/port/path/query', () => {
  assert.equal(normalizeHost('HTTPS://Evil.Example.COM:8443/login?x=1'), 'evil.example.com');
  assert.equal(normalizeHost('evil.example.com/some/path'), 'evil.example.com');
  assert.equal(normalizeHost('evil.example.com:8080'), 'evil.example.com');
});

test('strips a single leading www.', () => {
  assert.equal(normalizeHost('www.evil-example.com'), 'evil-example.com');
  assert.equal(normalizeHost('http://www.evil-example.com/'), 'evil-example.com');
});

test('converts unicode hostnames to punycode', () => {
  const out = normalizeHost('xn--fiq228c.com'); // already-ASCII form should pass through
  assert.equal(out, 'xn--fiq228c.com');
  const idn = normalizeHost('黑猫宅配.top'); // 黑貓宅配.top
  assert.ok(idn.startsWith('xn--'), `expected punycode, got ${idn}`);
  assert.ok(idn.endsWith('.top'));
});

test('keeps the FULL hostname on shared hosting — never collapses to eTLD+1', () => {
  assert.equal(normalizeHost('evil-tenant.pages.dev'), 'evil-tenant.pages.dev');
  assert.equal(normalizeHost('http://sub.evil.vercel.app/x'), 'sub.evil.vercel.app');
  assert.notEqual(normalizeHost('evil-tenant.pages.dev'), 'pages.dev');
});

test('drops IPv4 and IPv6 literals', () => {
  assert.equal(normalizeHost('192.168.1.1'), null);
  assert.equal(normalizeHost('http://203.0.113.5/path'), null);
  assert.equal(normalizeHost('[::1]'), null);
  assert.equal(normalizeHost('2001:db8::1'), null);
});

test('drops bare TLDs / single-label hosts', () => {
  assert.equal(normalizeHost('com'), null);
  assert.equal(normalizeHost('localhost'), null);
  assert.equal(normalizeHost(''), null);
  assert.equal(normalizeHost(null), null);
});

test('drops hosts over 253 chars', () => {
  const long = 'a'.repeat(250) + '.com';
  assert.ok(long.length > 253);
  assert.equal(normalizeHost(long), null);
});

test('registrableDomain helper is preserved and still works standalone', () => {
  assert.equal(registrableDomain('mail.google.co.uk'), 'google.co.uk');
  assert.equal(registrableDomain('evil.pages.dev'), 'pages.dev'); // collapsing behavior of the OLD helper
  assert.equal(registrableDomain('example.com'), 'example.com');
});
