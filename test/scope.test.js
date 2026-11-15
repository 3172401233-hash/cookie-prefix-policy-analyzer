'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { CookieJar } = require('../index');

function codes(result) {
  return result.findings.map((f) => f.code);
}

test('子域可以为父域设置 Cookie（Domain=example.com）', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('sid=1; Domain=example.com', 'https://sub.example.com/');
  assert.equal(r.accepted, true);
  assert.ok(codes(r).includes('SCOPE_WIDENED_TO_PARENT'));
  // 父域与兄弟子域都会收到
  assert.equal(jar.cookiesFor('https://example.com/').header, 'sid=1');
  assert.equal(jar.cookiesFor('https://other.example.com/').header, 'sid=1');
});

test('父域不能为子域设置 Cookie', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('sid=1; Domain=sub.example.com', 'https://example.com/');
  assert.equal(r.rejected, true);
  assert.ok(codes(r).includes('DOMAIN_NOT_SUFFIX'));
});

test('不能为无关域设置 Cookie', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('sid=1; Domain=evil.com', 'https://example.com/');
  assert.equal(r.rejected, true);
  assert.ok(codes(r).includes('DOMAIN_NOT_SUFFIX'));
});

test('host-only Cookie 不发送到子域', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=1', 'https://example.com/');
  assert.equal(jar.cookiesFor('https://sub.example.com/').header, '');
  assert.equal(jar.cookiesFor('https://example.com/').header, 'sid=1');
});

test('IP 主机携带 Domain 属性被拒绝', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('sid=1; Domain=127.0.0.1', 'http://127.0.0.1/');
  assert.equal(r.rejected, true);
  assert.ok(codes(r).includes('DOMAIN_ON_IP'));
});

test('IP 主机 host-only Cookie 正常工作', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('sid=1', 'http://127.0.0.1:8080/');
  assert.equal(r.accepted, true);
  assert.equal(jar.cookiesFor('http://127.0.0.1/').header, 'sid=1');
});

test('IPv6 主机 host-only Cookie 正常工作', () => {
  const jar = new CookieJar();
  const r = jar.setCookie('sid=1', 'http://[::1]:3000/');
  assert.equal(r.accepted, true);
  assert.equal(jar.cookiesFor('http://[::1]/').header, 'sid=1');
});

test('Cookie 不区分端口：跨端口发送并产生提示', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=1', 'http://example.com:8080/');
  const out = jar.cookiesFor('http://example.com:9090/');
  assert.equal(out.header, 'sid=1');
  assert.ok(out.findings.some((f) => f.code === 'PORT_SCOPE_CROSSING'));
});

test('路径边界：/foo 不匹配 /foobar，匹配 /foo/bar', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=1; Path=/foo', 'https://example.com/foo');
  assert.equal(jar.cookiesFor('https://example.com/foobar').header, '');
  assert.equal(jar.cookiesFor('https://example.com/foo').header, 'sid=1');
  assert.equal(jar.cookiesFor('https://example.com/foo/bar').header, 'sid=1');
  assert.equal(jar.cookiesFor('https://example.com/').header, '');
});

test('默认 Path 取请求路径的目录', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=1', 'https://example.com/app/login');
  const c = jar.cookies()[0];
  assert.equal(c.path, '/app');
  assert.equal(jar.cookiesFor('https://example.com/app/other').header, 'sid=1');
  assert.equal(jar.cookiesFor('https://example.com/').header, '');
});

test('子域同名 Cookie 遮蔽父域 host-only Cookie', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=parent', 'https://example.com/');
  const r = jar.setCookie('sid=injected; Domain=example.com', 'https://sub.example.com/');
  assert.ok(codes(r).includes('SUBDOMAIN_PARENT_OVERRIDE'));
  const out = jar.cookiesFor('https://example.com/');
  assert.ok(out.findings.some((f) => f.code === 'SHADOWED_IN_REQUEST'));
  assert.equal(out.cookies.length, 2);
});

test('同名不同 Path 的 Cookie 同时发送，路径最长者优先', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=root; Path=/', 'https://example.com/');
  const r = jar.setCookie('sid=nested; Path=/app', 'https://example.com/app');
  assert.ok(codes(r).includes('SHADOWED_COOKIE'));
  const out = jar.cookiesFor('https://example.com/app/page');
  assert.equal(out.header, 'sid=nested; sid=root');
  assert.ok(out.findings.some((f) => f.code === 'SHADOWED_IN_REQUEST'));
});

test('同名同作用域设置视为覆盖', () => {
  const jar = new CookieJar();
  jar.setCookie('sid=old', 'https://example.com/');
  const r = jar.setCookie('sid=new', 'https://example.com/');
  assert.ok(codes(r).includes('COOKIE_OVERWRITTEN'));
  assert.equal(jar.cookiesFor('https://example.com/').header, 'sid=new');
});
