'use strict';

const { parseSetCookie } = require('./parse');
const { isIPAddress, domainMatch, pathMatch, defaultPath, normalizeURL } = require('./model');

const PREFIX_HOST = '__host-';
const PREFIX_SECURE = '__secure-';

function scopeOf(cookie) {
  return { name: cookie.name, domain: cookie.domain, path: cookie.path };
}

function finding(code, severity, message, cookie, url, details) {
  return { code, severity, message, cookie: cookie ? scopeOf(cookie) : undefined, url, details };
}

class CookieJar {
  constructor({ now } = {}) {
    this._now = now || (() => Date.now());
    this._store = new Map(); // key: name\0domain\0path
    this.findings = [];
  }

  static _key(name, domain, path, hostOnly) {
    return [name, domain, path, hostOnly ? 1 : 0].join("\u0001");
  }

  _report(f) {
    this.findings.push(f);
    return f;
  }

  cookies() {
    return [...this._store.values()].map((c) => ({ ...c }));
  }

  // Process one Set-Cookie header received on a response for `urlString`.
  // Returns { accepted, rejected, deleted, cookie, findings }.
  setCookie(header, urlString) {
    const req = normalizeURL(urlString);
    const parsed = parseSetCookie(header);
    const local = [];
    const report = (code, severity, message, cookie, details) => {
      const f = finding(code, severity, message, cookie, req.url, details);
      local.push(f);
      this._report(f);
      return f;
    };
    const done = (result) => ({ findings: local, ...result });

    for (const err of parsed.errors) {
      report('PARSE_ERROR', 'error', `Set-Cookie 解析失败: ${err}`, { name: parsed.name, domain: req.host, path: '/' });
    }
    if (parsed.errors.length > 0) {
      return done({ accepted: false, rejected: true, deleted: false, cookie: null });
    }

    for (const dup of parsed.duplicates) {
      report(
        'DUPLICATE_ATTRIBUTE',
        'warning',
        `属性 "${dup}" 重复出现，按 RFC 6265 只有第一次生效，后续被忽略`,
        { name: parsed.name, domain: req.host, path: '/' },
        { attribute: dup }
      );
    }

    const { name, value, attrs } = parsed;
    const lowerName = name.toLowerCase();

    // --- Domain scope resolution -------------------------------------
    let cookieDomain;
    let hostOnly;
    if (attrs.domain !== undefined) {
      if (isIPAddress(req.host)) {
        report(
          'DOMAIN_ON_IP',
          'error',
          `IP 主机 "${req.host}" 上的 Cookie 携带 Domain=${attrs.domain}，浏览器忽略该 Cookie`,
          { name, domain: attrs.domain, path: attrs.path || '/' }
        );
        return done({ accepted: false, rejected: true, deleted: false, cookie: null });
      }
      if (!domainMatch(req.host, attrs.domain)) {
        report(
          'DOMAIN_NOT_SUFFIX',
          'error',
          `主机 "${req.host}" 不能为 "${attrs.domain}" 设置 Cookie（Domain 必须是请求主机的后缀）`,
          { name, domain: attrs.domain, path: attrs.path || '/' }
        );
        return done({ accepted: false, rejected: true, deleted: false, cookie: null });
      }
      cookieDomain = attrs.domain;
      hostOnly = false;
      if (attrs.domain !== req.host) {
        report(
          'SCOPE_WIDENED_TO_PARENT',
          'info',
          `子域 "${req.host}" 将 Cookie 作用域放宽到父域 "${attrs.domain}"，该 Cookie 会发送到整个域树`,
          { name, domain: cookieDomain, path: attrs.path || '/' }
        );
      }
    } else {
      cookieDomain = req.host;
      hostOnly = true;
    }

    const cookiePath = attrs.path !== undefined ? attrs.path : defaultPath(req.path);
    const cookie = {
      name,
      value,
      domain: cookieDomain,
      hostOnly,
      path: cookiePath,
      secure: attrs.secure,
      httpOnly: attrs.httpOnly,
      sameSite: attrs.sameSite,
      maxAge: attrs.maxAge,
      expires: attrs.expires,
      setFrom: { url: req.url, host: req.host, port: req.port, secure: req.secure },
    };

    // --- Prefix rules (RFC 6265bis §4.1.3) ---------------------------
    if (lowerName.startsWith(PREFIX_HOST)) {
      const problems = [];
      if (!attrs.secure) problems.push('缺少 Secure');
      if (attrs.domain !== undefined) problems.push(`携带 Domain=${attrs.domain}`);
      if (cookiePath !== '/') problems.push(`Path 不是 "/"（实际为 "${cookiePath}"）`);
      if (!req.secure) problems.push('通过非安全通道设置');
      if (problems.length > 0) {
        report(
          'HOST_PREFIX_VIOLATION',
          'error',
          `__Host- Cookie 被拒绝：${problems.join('；')}`,
          cookie
        );
        return done({ accepted: false, rejected: true, deleted: false, cookie: null });
      }
    } else if (lowerName.startsWith(PREFIX_SECURE)) {
      if (!attrs.secure || !req.secure) {
        const problems = [];
        if (!attrs.secure) problems.push('缺少 Secure 属性');
        if (!req.secure) problems.push('通过非安全通道设置');
        report('SECURE_PREFIX_VIOLATION', 'error', `__Secure- Cookie 被拒绝：${problems.join('；')}`, cookie);
        return done({ accepted: false, rejected: true, deleted: false, cookie: null });
      }
    }

    // --- Secure cookie over insecure channel (RFC 6265bis §4.1.2.5) --
    if (attrs.secure && !req.secure) {
      report(
        'SECURE_OVER_HTTP',
        'error',
        `HTTP 页面不能设置带 Secure 属性的 Cookie，浏览器拒绝该 Cookie`,
        cookie
      );
      return done({ accepted: false, rejected: true, deleted: false, cookie: null });
    }

    // --- SameSite sanity ---------------------------------------------
    if (attrs.sameSite === 'None' && !attrs.secure) {
      report(
        'SAMESITE_NONE_WITHOUT_SECURE',
        'warning',
        'SameSite=None 必须搭配 Secure，否则现代浏览器拒绝该 Cookie',
        cookie
      );
    }
    if (
      attrs.sameSite !== undefined &&
      !['Strict', 'Lax', 'None'].includes(attrs.sameSite)
    ) {
      report(
        'SAMESITE_INVALID',
        'warning',
        `无法识别的 SameSite 值 "${attrs.sameSite}"，浏览器按 Lax/默认值处理`,
        cookie
      );
    }

    // --- Expiry / deletion -------------------------------------------
    const now = this._now();
    if (attrs.maxAge !== undefined && attrs.expires !== undefined) {
      report(
        'MAX_AGE_OVERRIDES_EXPIRES',
        'info',
        'Max-Age 与 Expires 同时存在，Max-Age 优先',
        cookie
      );
    }
    const isDeletion =
      (attrs.maxAge !== undefined && attrs.maxAge <= 0) ||
      (attrs.maxAge === undefined && attrs.expires !== undefined && attrs.expires <= now);
    if (!isDeletion && attrs.maxAge !== undefined) {
      cookie.expiresAt = now + attrs.maxAge * 1000;
    } else if (!isDeletion && attrs.expires !== undefined) {
      cookie.expiresAt = attrs.expires;
    }

    const key = CookieJar._key(name, cookieDomain, cookiePath, hostOnly);

    if (isDeletion) {
      const existing = this._store.get(key);
      if (existing) {
        this._store.delete(key);
        report(
          'COOKIE_DELETED',
          'info',
          `删除请求命中作用域 ${cookieDomain}${cookiePath}，Cookie "${name}" 已清除`,
          cookie
        );
        return done({ accepted: true, rejected: false, deleted: true, cookie });
      }
      const sameName = [...this._store.values()].filter((c) => c.name === name);
      if (sameName.length > 0) {
        report(
          'DELETE_SCOPE_MISMATCH',
          'warning',
          `删除请求的作用域 ${cookieDomain}${cookiePath}（host-only=${hostOnly}）与现有 Cookie 不匹配，` +
            `原 Cookie 仍然有效：${sameName
              .map((c) => `${c.domain}${c.path}(host-only=${c.hostOnly})`)
              .join(', ')}`,
          cookie,
          { surviving: sameName.map(scopeOf) }
        );
      } else {
        report('DELETE_NO_TARGET', 'info', `删除请求没有匹配的 Cookie "${name}"`, cookie);
      }
      return done({ accepted: true, rejected: false, deleted: false, cookie });
    }

    // --- Shadowing / overwrite analysis ------------------------------
    const replaced = this._store.get(key);
    if (replaced) {
      report(
        'COOKIE_OVERWRITTEN',
        'info',
        `同名同作用域 Cookie "${name}" 被覆盖（旧值来自 ${replaced.setFrom.url}）`,
        cookie,
        { previousSetFrom: replaced.setFrom }
      );
    }
    const shadowed = [...this._store.values()].filter(
      (c) => c.name === name && CookieJar._key(c.name, c.domain, c.path, c.hostOnly) !== key
    );
    for (const other of shadowed) {
      const isParentOverride =
        !hostOnly && other.hostOnly && other.domain === cookieDomain;
      if (isParentOverride) {
        report(
          'SUBDOMAIN_PARENT_OVERRIDE',
          'warning',
          `"${req.host}" 设置的 Domain=${cookieDomain} Cookie 与父域 "${other.domain}" 的 host-only Cookie "${name}" 同名，` +
            `对父域的请求会同时携带两个值，子域可借此遮蔽/注入父域会话`,
          cookie,
          { victim: scopeOf(other) }
        );
      } else {
        report(
          'SHADOWED_COOKIE',
          'warning',
          `Cookie "${name}" 与现有 ${other.domain}${other.path}（host-only=${other.hostOnly}）同名但作用域不同，` +
            `在交集请求中两个值会同时出现在 Cookie 头里，服务端取第一个，可能读到非预期值`,
          cookie,
          { other: scopeOf(other) }
        );
      }
    }

    this._store.set(key, cookie);
    return done({ accepted: true, rejected: false, deleted: false, cookie });
  }

  // Process all Set-Cookie headers of one response.
  setCookies(headers, urlString) {
    return headers.map((h) => this.setCookie(h, urlString));
  }

  // Compute which cookies a request to `urlString` would carry.
  // Returns { cookies, header, findings }.
  cookiesFor(urlString) {
    const req = normalizeURL(urlString);
    const now = this._now();
    const local = [];
    const report = (code, severity, message, cookie, details) => {
      const f = finding(code, severity, message, cookie, req.url, details);
      local.push(f);
      this._report(f);
      return f;
    };

    // Expire lazily.
    for (const [key, c] of this._store) {
      if (c.expiresAt !== undefined && c.expiresAt <= now) this._store.delete(key);
    }

    const matched = [];
    for (const c of this._store.values()) {
      if (c.hostOnly ? c.domain !== req.host : !domainMatch(req.host, c.domain)) continue;
      if (c.secure && !req.secure) {
        report(
          'SECURE_COOKIE_WITHHELD',
          'info',
          `Secure Cookie "${c.name}" 不会通过 HTTP 发送`,
          c
        );
        continue;
      }
      if (!pathMatch(req.path, c.path)) continue;
      matched.push(c);
    }

    // RFC 6265 §5.4: longer paths first, then earlier creation first.
    matched.sort((a, b) => b.path.length - a.path.length);

    for (const c of matched) {
      if (c.setFrom.port !== req.port) {
        report(
          'PORT_SCOPE_CROSSING',
          'info',
          `Cookie "${c.name}" 设置于端口 ${c.setFrom.port}，但会发送到端口 ${req.port}（Cookie 不区分端口）`,
          c,
          { setFromPort: c.setFrom.port, requestPort: req.port }
        );
      }
    }

    const byName = new Map();
    for (const c of matched) {
      if (!byName.has(c.name)) byName.set(c.name, []);
      byName.get(c.name).push(c);
    }
    for (const [name, list] of byName) {
      if (list.length > 1) {
        report(
          'SHADOWED_IN_REQUEST',
          'warning',
          `请求携带 ${list.length} 个同名 Cookie "${name}"（${list
            .map((c) => `${c.domain}${c.path}`)
            .join(', ')}），服务端通常只取第一个（路径最长者）`,
          list[0],
          { candidates: list.map(scopeOf) }
        );
      }
    }

    return {
      cookies: matched.map((c) => ({ ...c })),
      header: matched.map((c) => `${c.name}=${c.value}`).join('; '),
      findings: local,
    };
  }
}

module.exports = { CookieJar };
