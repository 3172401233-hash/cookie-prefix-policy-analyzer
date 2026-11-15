'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { CookieJar } = require('../index');

function codes(result) {
  return result.findings.map((f) => f.code);
}

test('Max-Age=0 删除同作用域 Cookie', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=1; Path=/', 'https://example.com/');
  const r = jar.setCookie('sid=; Max-Age=0; Path=/', 'https://example.com/');
  assert.equal(r.deleted, true);
  assert.ok(codes(r).includes('COOKIE_DELETED'));
  assert.equal(jar.cookies().length, 0);
});

test('过期 Expires 删除同作用域 Cookie', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=1; Path=/', 'https://example.com/');
  const r = jar.setCookie('sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/', 'https://example.com/');
  assert.equal(r.deleted, true);
  assert.equal(jar.cookies().length, 0);
});

test('删除请求 Path 不匹配时原 Cookie 存活（DELETE_SCOPE_MISMATCH）', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=1; Path=/app', 'https://example.com/app');
  const r = jar.setCookie('sid=; Max-Age=0; Path=/', 'https://example.com/');
  assert.equal(r.deleted, false);
  const f = r.findings.find((x) => x.code === 'DELETE_SCOPE_MISMATCH');
  assert.ok(f);
  assert.deepEqual(f.details.surviving, [{ name: 'sid', domain: 'example.com', path: '/app' }]);
  assert.equal(jar.cookiesFor('https://example.com/app/x').header, 'sid=1');
});

test('host-only Cookie 不能通过 Domain= 删除（旧会话未失效场景）', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=secret; Path=/', 'https://example.com/');
  // 攻击者/测试子域尝试用 Domain=example.com 删除父域 host-only Cookie
  const r = jar.setCookie('sid=; Max-Age=0; Domain=example.com; Path=/', 'https://sub.example.com/');
  assert.equal(r.deleted, false);
  assert.ok(codes(r).includes('DELETE_SCOPE_MISMATCH'));
  // 原会话 Cookie 仍然有效
  assert.equal(jar.cookiesFor('https://example.com/').header, 'sid=secret');
});

test('带 Domain 的 __Host- 删除请求被前缀规则拒绝，原会话存活', () => {
  const jar = new CookieJar();
  jar.setCookie('__Host-sid=secret; Secure; Path=/', 'https://example.com/');
  // 这就是“__Host- 因带 Domain 被浏览器丢弃，旧会话没有失效”的场景
  const r = jar.setCookie('__Host-sid=; Max-Age=0; Domain=example.com; Path=/', 'https://example.com/');
  assert.equal(r.rejected, true);
  assert.ok(codes(r).includes('HOST_PREFIX_VIOLATION'));
  assert.equal(jar.cookiesFor('https://example.com/').header, '__Host-sid=secret');
});

test('Domain= 设置的 Cookie 不能用 host-only 作用域删除', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=1; Domain=example.com; Path=/', 'https://example.com/');
  const r = jar.setCookie('sid=; Max-Age=0; Path=/', 'https://example.com/');
  assert.equal(r.deleted, false);
  assert.ok(codes(r).includes('DELETE_SCOPE_MISMATCH'));
  assert.equal(jar.cookiesFor('https://sub.example.com/').header, 'sid=1');
});

test('无匹配 Cookie 的删除请求只产生提示', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('ghost=; Max-Age=0', 'https://example.com/');
  assert.ok(codes(r).includes('DELETE_NO_TARGET'));
});

test('Max-Age 与 Expires 同时存在时 Max-Age 优先', () => {
  const jar = new CookieJar();
  const r = jar.setCookie(
    'sid=1; Max-Age=3600; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
    'https://example.com/'
  );
  assert.ok(codes(r).includes('MAX_AGE_OVERRIDES_EXPIRES'));
  assert.equal(jar.cookiesFor('https://example.com/').header, 'sid=1');
});

test('Max-Age 到期后 Cookie 惰性过期', () => {
  let now = 1_000_000;
  const jar = new CookieJar({ now: () => now });
  jar.setCookie('sid=1; Max-Age=10', 'https://example.com/');
  assert.equal(jar.cookiesFor('https://example.com/').header, 'sid=1');
  now += 11_000;
  assert.equal(jar.cookiesFor('https://example.com/').header, '');
});
