# Security

## Hardening

- **CSRF-protected login form**: the form carries an HMAC-signed token bound
  to the form action, the full OAuth2 parameter set, and a per-browser nonce
  delivered in an `HttpOnly`/`SameSite=Lax`/`Secure` cookie. A token
  pre-fetched by an attacker is useless in a victim's browser, and
  `SameSite=Lax` keeps the cookie off cross-site POSTs. `Secure` is always
  set — on plain-HTTP localhost this relies on the browser's secure-context
  exception (works in Chrome and Firefox; Safari doesn't implement it, so
  use Chrome/Firefox or TLS there).
- **Rate limiting**: per-client-IP token bucket on the login endpoint
  (`IDP_LOGIN_RATE_LIMIT`, default 20/min). The limiter runs after CSRF
  validation, so junk form posts can't exhaust the IP budget of a
  legitimate user behind the same NAT. Behind a reverse proxy, set
  `TRUSTED_PROXIES` — a spoofed `X-Forwarded-For` from an untrusted peer is
  ignored.
- **Constant-time credential check** against bcrypt hashes; unknown
  usernames burn the same bcrypt cost as real ones, so usernames can't be
  probed.
- **Persistent signing key**: with `IDP_KEY_DIR` set, the RSA key is
  generated once (mode 0600, temp-file + rename) and reloaded on restart,
  so tokens survive restarts and the JWKS stays stable.
- **Single-use authorization codes** (10 min TTL) and **single-use refresh
  tokens** with rotation. Replay is rejected, and replaying a rotated token
  revokes the whole token family of that authorization (RFC 9700 §4.14.2).
- **Token responses are not cacheable**: `/token` always answers with
  `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749 §5.1).
- **Working revocation**: `/revoke` deletes refresh tokens with their family
  (RFC 7009) and denies access tokens by `jti` denylist until expiry, so
  `/userinfo` and `/introspect` reject them immediately instead of after the
  full TTL. `/end_session?id_token_hint=…` revokes the authorization the
  hint belongs to (`sid` claim = token family).
- **Security headers**: strict CSP (`frame-ancestors 'none'`, no
  `unsafe-inline`), `X-Frame-Options: DENY`, `nosniff`, strict referrer
  policy.
- **Confidential client authentication**: constant-time secret comparison
  (Basic and form methods) against the named client's own secret, checked
  before any code or refresh token is consumed, RFC 9700 §2.3.2
  Basic-vs-form `client_id` conflict rejection, and fail-fast startup
  validation of every profile/secret combination.
- **Audit logging**: login success/failure (client IP, attempted username),
  code issuance, token grants and rejections, via slog.
- **Graceful shutdown** on SIGTERM/SIGINT for k8s/compose rolling updates.
- golangci-lint and gosec clean (enforced in CI); no `#nosec` directives.

## Accepted trade-offs

These are inherent to the public-client profile (no secret, no
sender-constrained tokens). They're recorded here as conscious decisions —
revisit them if the deployment profile changes.

- **`/revoke` and `/introspect` are unauthenticated when every client is
  public.** `/revoke` is a write operation: anyone who merely observes a
  bearer token (a proxy log, a `Referer`, mixed-content capture) can use it
  to revoke that session — refresh family revoked, live access tokens
  denied by `jti` — a targeted denial of service against the victim. Public
  clients have no secret to authenticate the call, and sender-constraining
  tokens (e.g. DPoP) is out of scope for minidp; token confidentiality in
  transit is the mitigation. As soon as any confidential client is
  registered, both endpoints require client authentication.
- **Refresh tokens are unconstrained bearer tokens.** For public clients
  they're redeemable with only the `client_id` — a leaked refresh token is
  fully replayable until its TTL. Single-use rotation and family-wide
  revocation on reuse (RFC 9700 §4.14.2) limit the blast radius but don't
  eliminate the exposure. This is the standard public-client trade-off; use
  the confidential profile when the client can keep a secret (see
  [Client profiles](clients.md#client-profiles-public-vs-confidential)).
