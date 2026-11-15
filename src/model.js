'use strict';

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

function isIPAddress(host) {
  if (typeof host !== 'string' || host.length === 0) return false;
  const bare = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  if (bare.includes(':')) return true; // IPv6
  const m = IPV4_RE.exec(bare);
  if (!m) return false;
  return m.slice(1).every((octet) => Number(octet) <= 255);
}

// RFC 6265 §5.1.3 domain matching.
function domainMatch(host, domain) {
  const h = String(host).toLowerCase();
  const d = String(domain).toLowerCase().replace(/^\.+/, '');
  if (h === d) return true;
  if (isIPAddress(h)) return false;
  return h.endsWith('.' + d);
}

// RFC 6265 §5.1.4 path matching.
function pathMatch(requestPath, cookiePath) {
  const req = requestPath || '/';
  const cp = cookiePath || '/';
  if (req === cp) return true;
  if (req.startsWith(cp)) {
    if (cp.endsWith('/')) return true;
    if (req.charAt(cp.length) === '/') return true;
  }
  return false;
}

// RFC 6265 §5.1.4 default-path of a request URI.
function defaultPath(requestPath) {
  const p = requestPath || '/';
  if (!p.startsWith('/')) return '/';
  const firstSlash = p.indexOf('/');
  const lastSlash = p.lastIndexOf('/');
  if (firstSlash === lastSlash) return '/';
  return p.slice(0, lastSlash);
}

function normalizeURL(urlString) {
  const url = new URL(urlString);
  const protocol = url.protocol.toLowerCase();
  const hostname = url.hostname.toLowerCase();
  const port = url.port || (protocol === 'https:' ? '443' : protocol === 'http:' ? '80' : '');
  return {
    protocol,
    secure: protocol === 'https:' || protocol === 'wss:',
    host: hostname,
    port,
    path: url.pathname || '/',
    url: urlString,
  };
}

module.exports = { isIPAddress, domainMatch, pathMatch, defaultPath, normalizeURL };
