'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { parseSetCookie } = require('../index');

test('解析基本 name=value 与属性', () => {
  const c = parseSetCookie('sid=abc; Domain=Example.COM; Path=/app; Secure; HttpOnly; SameSite=Lax; Max-Age=3600');
  assert.equal(c.name, 'sid');
  assert.equal(c.value, 'abc');
  assert.equal(c.attrs.domain, 'example.com');
  assert.equal(c.attrs.path, '/app');
  assert.equal(c.attrs.secure, true);
  assert.equal(c.attrs.httpOnly, true);
  assert.equal(c.attrs.sameSite, 'Lax');
  assert.equal(c.attrs.maxAge, 3600);
});

test('Domain 前导点被去除', () => {
  const c = parseSetCookie('a=1; Domain=.example.com');
  assert.equal(c.attrs.domain, 'example.com');
});

test('重复属性第一次生效，后续记入 duplicates', () => {
  const c = parseSetCookie('a=1; Domain=sub.example.com; Domain=evil.example.com; SameSite=Strict; SameSite=None');
  assert.equal(c.attrs.domain, 'sub.example.com');
  assert.equal(c.attrs.sameSite, 'Strict');
  assert.deepEqual(c.duplicates.sort(), ['domain', 'samesite']);
});

test('非法 Max-Age 被忽略', () => {
  const c = parseSetCookie('a=1; Max-Age=abc');
  assert.equal(c.attrs.maxAge, undefined);
});

test('负 Max-Age 解析为删除语义', () => {
  const c = parseSetCookie('a=1; Max-Age=-1');
  assert.equal(c.attrs.maxAge, -1);
});

test('Expires 解析为时间戳', () => {
  const c = parseSetCookie('a=1; Expires=Wed, 21 Oct 2015 07:28:00 GMT');
  assert.equal(c.attrs.expires, Date.parse('Wed, 21 Oct 2015 07:28:00 GMT'));
});

test('非绝对 Path 被忽略', () => {
  const c = parseSetCookie('a=1; Path=relative');
  assert.equal(c.attrs.path, undefined);
});

test('空 name 报错', () => {
  const c = parseSetCookie('=value; Path=/');
  assert.ok(c.errors.length > 0);
});

test('SameSite 大小写归一化，未知值原样保留', () => {
  assert.equal(parseSetCookie('a=1; SameSite=STRICT').attrs.sameSite, 'Strict');
  assert.equal(parseSetCookie('a=1; SameSite=bogus').attrs.sameSite, 'bogus');
});
