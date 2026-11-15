'use strict';

// Parse a single Set-Cookie header value.
// RFC 6265 §5.3: when an attribute appears more than once, the FIRST
// occurrence wins and later ones are ignored (reported as duplicates).
function parseSetCookie(header) {
  if (typeof header !== 'string') {
    throw new TypeError('Set-Cookie header must be a string');
  }
  const errors = [];
  const duplicates = [];
  const segments = header.split(';');
  const pair = segments.shift();
  const eq = pair.indexOf('=');
  let name;
  let value;
  if (eq === -1) {
    name = '';
    value = pair.trim();
  } else {
    name = pair.slice(0, eq).trim();
    value = pair.slice(eq + 1).trim();
  }
  if (name === '') {
    errors.push('cookie-name 为空');
  }

  const attrs = {
    domain: undefined,
    path: undefined,
    maxAge: undefined, // seconds, number
    expires: undefined, // epoch ms, number
    secure: false,
    httpOnly: false,
    sameSite: undefined, // 'Strict' | 'Lax' | 'None' | raw value
    unrecognized: [],
  };

  const seen = new Set();
  for (const segment of segments) {
    const idx = segment.indexOf('=');
    const key = (idx === -1 ? segment : segment.slice(0, idx)).trim().toLowerCase();
    const val = idx === -1 ? '' : segment.slice(idx + 1).trim();
    if (key === '') continue;
    if (seen.has(key)) {
      duplicates.push(key);
      continue; // first occurrence wins
    }
    seen.add(key);
    switch (key) {
      case 'domain':
        attrs.domain = val.replace(/^\.+/, '').toLowerCase();
        break;
      case 'path':
        // Non-absolute paths are ignored per RFC 6265 §5.2.4.
        if (val.startsWith('/')) attrs.path = val;
        break;
      case 'max-age': {
        if (/^-?\d+$/.test(val)) attrs.maxAge = parseInt(val, 10);
        break;
      }
      case 'expires': {
        const ts = Date.parse(val);
        if (!Number.isNaN(ts)) attrs.expires = ts;
        break;
      }
      case 'secure':
        attrs.secure = true;
        break;
      case 'httponly':
        attrs.httpOnly = true;
        break;
      case 'samesite': {
        const norm = val.toLowerCase();
        attrs.sameSite =
          norm === 'strict' ? 'Strict' : norm === 'lax' ? 'Lax' : norm === 'none' ? 'None' : val;
        break;
      }
      default:
        attrs.unrecognized.push(key);
    }
  }

  return { name, value, attrs, duplicates, errors };
}

module.exports = { parseSetCookie };
