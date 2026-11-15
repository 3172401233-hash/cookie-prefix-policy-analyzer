# cookie-prefix-policy-analyzer

JavaScript Cookie 作用域与会话隔离审计库。解析响应中的 `Set-Cookie` 与后续请求 URL，
把 Cookie 作用域当作安全边界检查：`__Host-` / `__Secure-` 前缀、Domain、Path、
SameSite、Secure、Max-Age 与过期删除组合。

## 使用

```js
const { CookieJar, parseSetCookie } = require('cookie-prefix-policy-analyzer');

const jar = new CookieJar();

// 处理响应中的 Set-Cookie，逐条得到审计发现
const r = jar.setCookie(
  '__Host-sid=abc; Secure; Path=/; Domain=example.com',
  'https://example.com/'
);
// r.rejected === true
// r.findings[0].code === 'HOST_PREFIX_VIOLATION'（__Host- 不允许携带 Domain）

// 计算后续请求会携带哪些 Cookie，以及遮蔽/跨端口等提示
const out = jar.cookiesFor('https://sub.example.com:8443/app');
// out.header   -> 实际发送的 Cookie 头
// out.findings -> SHADOWED_IN_REQUEST / PORT_SCOPE_CROSSING / ...

// 全量审计日志（跨多次调用累积）
console.log(jar.findings);
```

每条 finding 都定位到具体 Cookie 与作用域：

```js
{
  code: 'DELETE_SCOPE_MISMATCH',
  severity: 'warning',            // error | warning | info
  message: '删除请求的作用域 example.com/（host-only=false）与现有 Cookie 不匹配…',
  cookie: { name: 'sid', domain: 'example.com', path: '/' },
  url: 'https://sub.example.com/logout',
  details: { surviving: [{ name: 'sid', domain: 'example.com', path: '/app' }] }
}
```

## 审计规则

| code | 级别 | 含义 |
| --- | --- | --- |
| `HOST_PREFIX_VIOLATION` | error | `__Host-` 缺 Secure、带 Domain、Path 非 `/` 或经非安全通道设置，浏览器拒绝 |
| `SECURE_PREFIX_VIOLATION` | error | `__Secure-` 缺 Secure 或经非安全通道设置 |
| `SECURE_OVER_HTTP` | error | HTTP 页面设置带 Secure 属性的 Cookie（RFC 6265bis 拒绝） |
| `DOMAIN_NOT_SUFFIX` | error | Domain 不是请求主机的后缀（父域不能种到子域、不能种到无关域） |
| `DOMAIN_ON_IP` | error | IP 主机上的 Cookie 携带 Domain 属性 |
| `SCOPE_WIDENED_TO_PARENT` | info | 子域把作用域放宽到父域，Cookie 会发送到整个域树 |
| `SUBDOMAIN_PARENT_OVERRIDE` | warning | 子域用 `Domain=父域` 种了与父域 host-only Cookie 同名的 Cookie，可遮蔽/注入父域会话 |
| `SHADOWED_COOKIE` / `SHADOWED_IN_REQUEST` | warning | 同名不同作用域的 Cookie 在交集中同时发送，服务端通常只取第一个（路径最长者） |
| `DELETE_SCOPE_MISMATCH` | warning | 删除请求（`Max-Age=0` / 过期 `Expires`）的 (domain, path, host-only) 与原 Cookie 不匹配，原 Cookie 仍然有效 |
| `COOKIE_DELETED` / `DELETE_NO_TARGET` | info | 删除命中 / 无目标 |
| `COOKIE_OVERWRITTEN` | info | 同名同作用域覆盖 |
| `DUPLICATE_ATTRIBUTE` | warning | 属性重复出现，按 RFC 6265 第一次生效 |
| `MAX_AGE_OVERRIDES_EXPIRES` | info | 两者同时存在时 Max-Age 优先 |
| `SAMESITE_NONE_WITHOUT_SECURE` / `SAMESITE_INVALID` | warning | SameSite 组合问题 |
| `PORT_SCOPE_CROSSING` | info | Cookie 不区分端口，会跨端口发送 |
| `SECURE_COOKIE_WITHHELD` | info | Secure Cookie 不会经 HTTP 发送 |

## 关键语义

- **Cookie 身份 = (name, domain, path, host-only)**。host-only 的 `example.com` 与
  `Domain=example.com` 是两个不同的 Cookie（与 Chrome/Firefox 行为一致）：
  删除或覆盖必须精确匹配原作用域，否则旧会话不会失效。
- **Domain 匹配**（RFC 6265 §5.1.3）：`Domain=example.com` 覆盖所有子域；
  不带 Domain 的 host-only Cookie 只发给精确主机。IP 主机不做后缀匹配。
- **Path 匹配**（§5.1.4）：`/foo` 匹配 `/foo` 与 `/foo/bar`，不匹配 `/foobar`；
  缺省 Path 取请求路径的目录。
- **重复属性**：第一次出现生效，后续忽略并产生 `DUPLICATE_ATTRIBUTE`。
- **端口**：Cookie 作用域不含端口，`:8080` 设置的 Cookie 会发到 `:9090`。

## 判断边界：未使用公共后缀列表（PSL）

本库**不内置 Public Suffix List**，父子域关系只按字符串后缀计算，因此：

- `foo.bar.co.uk` 设置 `Domain=bar.co.uk` 会被判定为“放宽到父域”并允许；
  但真实浏览器依据 PSL 知道 `co.uk` 是公共后缀，会拒绝 `Domain=co.uk`——
  本库无法识别这种情况，会把 `Domain=co.uk` 误判为合法的父域放宽。
- 同理，`github.io`、`appspot.com` 这类“私有但列入 PSL”的后缀，
  本库会把 `user-a.github.io` 与 `user-b.github.io` 视为同一域树的兄弟子域，
  而浏览器将它们完全隔离。
- 结论：涉及多租户/公共后缀域名时，本库的 `SCOPE_WIDENED_TO_PARENT`、
  `SUBDOMAIN_PARENT_OVERRIDE` 等跨域判断会**偏宽松**（少报）；
  单租户私有域名（如 `*.example.com`）下判断是准确的。
  如需精确边界，可在接入层用 PSL 先校验 `Domain` 属性再交给本库。

## 测试

```sh
npm test   # node --test
```

覆盖：主域/子域作用域、IPv4/IPv6、端口边界、路径边界、重复属性、
删除型 Cookie（`Max-Age=0` / 过期 `Expires`）、同名覆盖与遮蔽、
`__Host-` / `__Secure-` 前缀、HTTP 设置 Secure Cookie。
