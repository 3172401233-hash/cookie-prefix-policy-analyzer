'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { CookieJar } = require('../index');

function codes(result) {
  return result.findings.map((f) => f.code);
}

test('合法 __Host- Cookie 被接受', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('__Host-sid=abc; Secure; Path=/', 'https://example.com/');
  assert.equal(r.accepted, true);
  assert.equal(jar.cookiesFor('https://example.com/').header, '__Host-sid=abc');
});

test('__Host- 携带 Domain 被拒绝（会话未失效的根因）', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('__Host-sid=abc; Secure; Path=/; Domain=example.com', 'https://example.com/');
  assert.equal(r.rejected, true);
  assert.ok(codes(r).includes('HOST_PREFIX_VIOLATION'));
  assert.equal(jar.cookies().length, 0);
});

test('__Host- 缺少 Secure 被拒绝', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('__Host-sid=abc; Path=/', 'https://example.com/');
  assert.equal(r.rejected, true);
  assert.ok(codes(r).includes('HOST_PREFIX_VIOLATION'));
});

test('__Host- Path 非 / 被拒绝', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('__Host-sid=abc; Secure; Path=/app', 'https://example.com/app');
  assert.equal(r.rejected, true);
  assert.ok(codes(r).includes('HOST_PREFIX_VIOLATION'));
});

test('__Host- 通过 HTTP 设置被拒绝', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('__Host-sid=abc; Secure; Path=/', 'http://example.com/');
  assert.equal(r.rejected, true);
});

test('__Secure- 缺少 Secure 属性被拒绝', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('__Secure-sid=abc; Path=/', 'https://example.com/');
  assert.equal(r.rejected, true);
  assert.ok(codes(r).includes('SECURE_PREFIX_VIOLATION'));
});

test('__Secure- 带 Secure 被接受，但不发送到 HTTP', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('__Secure-sid=abc; Secure; Path=/', 'https://example.com/');
  assert.equal(r.accepted, true);
  const out = jar.cookiesFor('http://example.com/');
  assert.equal(out.header, '');
  assert.ok(out.findings.some((f) => f.code === 'SECURE_COOKIE_WITHHELD'));
});

test('HTTP 页面设置 Secure Cookie 被拒绝', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('sid=abc; Secure', 'http://example.com/');
  assert.equal(r.rejected, true);
  assert.ok(codes(r).includes('SECURE_OVER_HTTP'));
  assert.equal(jar.cookies().length, 0);
});

test('SameSite=None 缺少 Secure 产生警告', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('x=1; SameSite=None', 'https://example.com/');
  assert.ok(codes(r).includes('SAMESITE_NONE_WITHOUT_SECURE'));
});
