# minidp

A minimal OIDC/OAuth2 identity provider written in Go. It implements the
**Authorization Code flow** for **public clients with mandatory PKCE (S256)**
and for **confidential clients with client authentication at the token
endpoint** (`MINIDP_MODE`), issues signed
**access tokens**, **id tokens** and **rotating refresh tokens**, and is
designed to work out of the box as the IdP for
[github.com/ghmer/rego-adventure](https://github.com/ghmer/rego-adventure).

> **Scope.** minidp is production-ready **for what it is**: a lightweight IdP
> for demo and pilot deployments such as rego-adventure — with a small set of
> users managed through a mounted JSON file and a **single registered client**.
> It deliberately has no user database, no admin UI, no dynamic client
> registration and no clustering — that is what keeps it a 10 MB container
> instead of a Keycloak. The sections below describe the hardening that ships
> (CSRF, rate limiting, key persistence) and the operational decisions you
> must make (key management, TLS termination).
>
> If you need multiple clients, multi-user self-service or HA, use
> Keycloak/Zitadel/Ory — that is a different tier of problem.

## Features

- **Single registered client** with a configurable `client_id` (`IDP_CLIENT_ID`,
  default `rego-adventure`) and a configurable token **audience**
  (`IDP_AUDIENCE`, defaults to the client id) — every other `client_id` is
  rejected at `/authorize` and `/token`, and resource endpoints reject tokens
  whose `aud` does not match
- **Multi-user accounts** via a mounted JSON file of bcrypt-hashed accounts
  (managed with the bundled `minidp-users` tool) — the only credential source;
  there are no built-in accounts
- **Mandatory redirect policy** (`ALLOWED_REDIRECTS`): the registered client's
  redirect URIs; minidp refuses to start without it
- OIDC discovery document (`/.well-known/openid-configuration`)
- Authorization Code flow for **public clients** with **mandatory PKCE**
  (`S256` only, per RFC 9700, RFC 7636 syntax enforced) — see
  [Client modes](#client-modes-public-vs-confidential) for the confidential
  variant
- RS256-signed tokens with the RFC 9068 `at+jwt` token profile for access
  tokens (`typ` header) — an **id token can never be replayed as an access
  token**
- Claims are released **according to the granted scopes** from the
  authoritative users-file record (`profile` → `preferred_username`/`name`,
  `email` → `email`); `roles` are released as the `roles` claim on the access
  and ID tokens **whenever the user record defines them** (they are
  authorization data, not scope-gated profile claims)
- Refresh token grant with **single-use rotation**
- `userinfo`, `introspect` (RFC 7662) and `revoke` (RFC 7009) endpoints
- CORS support so browser-based SPAs (e.g. `oidc-client-ts`) can exchange
  codes — only origins derived from the registered redirects (or listed in
  `IDP_ALLOWED_ORIGINS`) are reflected, with credentials; any other `Origin`
  gets no CORS grant
- Login page styled after the **Rego Adventure** theme

## Hardening

- **CSRF-protected login form**: the form carries an HMAC-signed token bound
  to the form action, the full OAuth2 parameter set **and a per-browser nonce
  delivered in an `HttpOnly`/`SameSite=Lax`/`Secure` cookie** — a token
  pre-fetched by an attacker is worthless in a victim's browser, and
  `SameSite=Lax` keeps the cookie off cross-site POSTs entirely. `Secure` is
  always set: on plain-HTTP localhost this relies on the browsers'
  secure-context exception (Chrome, Firefox — Safari does not implement it,
  use Chrome/Firefox or TLS there).
- **Rate limiting**: per-client-IP token bucket on the login endpoints
  (`IDP_LOGIN_RATE_LIMIT`, default 20/min). The limiter runs **after** CSRF
  validation, so junk form posts cannot exhaust the IP budget of a legitimate
  user sharing the same NAT. Behind a reverse proxy, set
  `TRUSTED_PROXIES` so the real client IP is used (spoofing
  `X-Forwarded-For` from an untrusted peer is ignored).
- **Constant-time credential check** against bcrypt hashes; unknown usernames
  burn the same bcrypt cost as real ones (no username probing).
- **Persistent signing key**: with `IDP_KEY_DIR` set, the RSA key is generated
  once (mode 0600, temp-file + rename) and reloaded on restart, so tokens
  survive restarts and the JWKS stays stable.
- **Single-use authorization codes** (10 min TTL) and **single-use refresh
  tokens** with rotation — replay is rejected, and replaying a rotated token
  revokes the **whole token family** of that authorization (RFC 9700 §4.14.2).
- **Token responses are not cacheable**: `/token` always answers with
  `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749 §5.1).
- **Working revocation**: `/revoke` deletes refresh tokens (with their family,
  RFC 7009) and denies access tokens by `jti` denylist until their expiry, so
  `/userinfo` and `/introspect` reject them immediately instead of after the
  full TTL. `/end_session?id_token_hint=…` revokes the authorization the hint
  belongs to (`sid` claim = token family).
- **Security headers**: strict CSP (`frame-ancestors 'none'`, no
  `unsafe-inline`), `X-Frame-Options: DENY`, `nosniff`, strict referrer policy.
- **Confidential client authentication** (`MINIDP_MODE=confidential`):
  constant-time secret comparison (Basic and form methods), client
  authentication **before** codes/refresh tokens are consumed, RFC 9700
  §2.3.2 Basic-vs-form `client_id` conflict rejection, and fail-fast startup
  validation of the mode/secret combination.
- **Audit logging**: login success/failure (with client IP and attempted
  username), code issuance, token grants and rejections via slog.
- **Graceful shutdown** on SIGTERM/SIGINT for k8s/compose rolling updates.
- Golang-ci-lint and gosec clean (enforced in CI); no `#nosec` directives.

### Security trade-offs (accepted by design)

These limitations are inherent to the public-client profile (no secret, no
sender-constrained tokens). They are recorded here so they remain **conscious
decisions** rather than surprises; revisit them if the deployment profile ever
changes:

- **`/revoke` and `/introspect` are unauthenticated in public mode** — and
  `/revoke` is a *write* operation: anyone who merely **observes** a bearer
  token (a proxy or browser log, a `Referer`, mixed-content capture) can use
  it to revoke that session (refresh family revoked, live access tokens
  denied by `jti`) — a targeted denial of service for the victim. The public
  profile has no client secret to authenticate the call, and
  sender-constraining the tokens (e.g. DPoP) is out of scope for minidp;
  token confidentiality in transit is the mitigation. `confidential` mode
  requires client authentication on both endpoints.
- **Refresh tokens are unconstrained bearer tokens.** In public mode they are
  redeemable with only the `client_id` — a leaked refresh token is fully
  replayable by anyone until its TTL. Single-use rotation and family-wide
  revocation on reuse (RFC 9700 §4.14.2) contain the blast radius but do not
  eliminate the exposure; this is the standard public-client trade-off,
  accepted here deliberately. Use `confidential` mode when the client can
  keep a secret.

## Quick start

minidp has no built-in accounts and no open redirect fallback, so a users file
and a redirect policy are mandatory. The repository ships `users.json` with
the demo account **rego** / **adventure** (bcrypt-hashed):

```sh
go build -o minidp .
go build -o minidp-users ./cmd/minidp-users

IDP_ISSUER=http://localhost:8080 \
IDP_USERS_FILE=$PWD/users.json \
ALLOWED_REDIRECTS=http://localhost:3000/callback \
./minidp
```

Then open
`http://localhost:8080/authorize?client_id=rego-adventure&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&code_challenge=<challenge>&code_challenge_method=S256&state=x&nonce=y`
and sign in with **rego** / **adventure**.

Run the self-contained end-to-end smoke test (builds, boots its own instance
on port 8099 and exercises the whole flow):

```sh
./smoke-test.sh
```

## Configuration

All settings are provided through environment variables.

| Variable                | Default                              | Description                                                                                                                                                                          |
| ----------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `IDP_HOST`              | `0.0.0.0`                            | Interface to bind                                                                                                                                                                    |
| `IDP_PORT`              | `8080`                               | TCP port to listen on                                                                                                                                                                |
| `IDP_ISSUER`            | `http://localhost:8080`              | Issuer URL; written into every token's `iss` and the discovery doc                                                                                                                   |
| `IDP_CLIENT_ID`         | `rego-adventure`                     | The single registered client; every other `client_id` is rejected at `/authorize` and `/token`                                                                                       |
| `IDP_AUDIENCE`          | *(= `IDP_CLIENT_ID`)*                | `aud` claim of every token; `/userinfo` and `/introspect` reject tokens with a foreign audience                                                                                      |
| `IDP_USERS_FILE`        | *(required)*                         | JSON file with user accounts (bcrypt hashes, see below) — **the only credential source**                                                                                             |
| `IDP_ACCESS_TOKEN_TTL`  | `3600`                               | Access/id token lifetime in seconds                                                                                                                                                  |
| `IDP_REFRESH_TOKEN_TTL` | `7200`                               | Refresh token lifetime in seconds                                                                                                                                                    |
| `ALLOWED_REDIRECTS`     | *(required)*                         | Comma-separated registered `redirect_uri` values of the client — minidp refuses to start without it                                                                                  |
| `IDP_ALLOWED_ORIGINS`   | *(derived from `ALLOWED_REDIRECTS`)* | Explicit CORS origin allowlist; other origins are never reflected with credentials                                                                                                   |
| `IDP_RSA_PEM`           | *(unset)*                            | Path to a PKCS#1/PKCS#8 RSA private key; takes precedence over `IDP_KEY_DIR`                                                                                                         |
| `IDP_KEY_DIR`           | *(unset)*                            | Directory for the auto-generated, persisted signing key (`minidp-rsa.pem`)                                                                                                           |
| `TRUSTED_PROXIES`       | *(empty)*                            | Comma-separated CIDR ranges of proxies whose `X-Forwarded-For` is trusted                                                                                                            |
| `MINIDP_MODE`           | `public`                             | Client profile: `public` (mandatory PKCE, no secret allowed) or `confidential` (client auth at `/token`, secret required) — see [Client modes](#client-modes-public-vs-confidential) |
| `IDP_CLIENT_SECRET`     | *(unset)*                            | The registered client's secret; **only valid in `confidential` mode** — also gates `/introspect` and `/revoke`                                                                       |
| `IDP_LOGIN_RATE_LIMIT`  | `20`                                 | Login attempts per minute and client IP                                                                                                                                              |
| `IDP_TITLE`             | `Rego Adventure`                     | Title shown on the login page                                                                                                                                                        |
| `IDP_SUBTITLE`          | `Sign in to begin …`                 | Subtitle shown on the login page                                                                                                                                                     |

The single-user credential variables of earlier versions (`IDP_USERNAME`,
`IDP_PASSWORD`, `IDP_PASSWORD_BCRYPT`, `IDP_PASSWORD_FILE`) were **removed**;
setting any of them aborts startup with a migration hint. Manage accounts in
the users file.

## Client modes: public vs confidential

`MINIDP_MODE` selects the RFC 6749 client profile of the single registered
client. minidp refuses to start on inconsistent combinations (a secret in
public mode is dead configuration; a confidential mode without a secret would
authenticate every caller), so the mode and the secret are validated together
at startup.

**`MINIDP_MODE=public`** (default) — the SPA profile used by rego-adventure:

- PKCE (S256) is **mandatory** at `/authorize` and verified at `/token`
- `/token` accepts only `client_id` identification — public clients cannot
  keep secrets, so none is configured (`IDP_CLIENT_SECRET` must be unset)
- `/introspect` and `/revoke` are open (documented trade-off, see
  [Security trade-offs](#security-trade-offs-accepted-by-design))

**`MINIDP_MODE=confidential`** — the backend/profile for a client that can
hold a secret (requires `IDP_CLIENT_SECRET`):

- `/token` (and `/revoke`, `/introspect`) **require client authentication**:
  `client_secret_basic` (HTTP Basic, RFC 6749 §2.3.1 form-urlencoded
  credentials) or `client_secret_post` (`client_id` + `client_secret` form
  fields). Failures answer `401 invalid_client` and are **logged** (audit/IDS),
  not rate limited — the same rationale as the token endpoint itself.
- PKCE becomes **optional**: the secret is the client's proof of identity. If
  the client still sends a `code_challenge`, it is validated as strictly as in
  public mode (S256, RFC 7636 shape) and the matching `code_verifier` is
  required at `/token`. RFC 9700 §2.1.1 recommends PKCE for all clients —
  keep using it if you can.
- Failed client authentication happens **before** the authorization code or
  refresh token is consumed: a wrong secret can never burn a valid code.
- Client authentication is also required on the **refresh token grant**
  (RFC 6749 §6); on success the refresh chain (rotation, family revocation on
  reuse) behaves exactly as in public mode.
- Discovery advertises `client_secret_basic` + `client_secret_post` for the
  token/revocation/introspection endpoints instead of `none`.

```sh
MINIDP_MODE=confidential IDP_CLIENT_SECRET="$(openssl rand -base64 32)" minidp
```

Use a cryptographically random secret of at least 128 bits; shorter secrets
trigger a startup warning.

## Using minidp with rego-adventure

minidp serves exactly **one registered client** (`IDP_CLIENT_ID`), and every
token carries the configured audience (`IDP_AUDIENCE`). Nothing is reflected:
a token minted for — or presented at — any other audience is rejected. Point
the rego-adventure authentication environment variables at minidp:

| rego-adventure variable | Value                                               |
| ----------------------- | --------------------------------------------------- |
| `AUTH_ENABLED`          | `true`                                              |
| `AUTH_ISSUER`           | minidp's `IDP_ISSUER`                               |
| `AUTH_DISCOVERY_URL`    | `<IDP_ISSUER>/.well-known/openid-configuration`     |
| `AUTH_CLIENT_ID`        | `rego-adventure` (public client, = `IDP_CLIENT_ID`) |
| `AUTH_AUDIENCE`         | `rego-adventure` (public client, = `IDP_AUDIENCE`)  |

The frontend performs the PKCE code exchange directly against minidp (CORS is
enabled for this); the backend validates the Bearer JWT against minidp's JWKS.
The SPA should request `openid profile email` — claims are released strictly
by scope: `profile` unlocks `preferred_username`/`name` (on both tokens and
`/userinfo`), `email` unlocks the `email` claim, and a token without the
`openid` scope cannot call `/userinfo`.
Roles set on the users-file record are released as the `roles` array claim on
both tokens independent of the scopes.

## Accounts: the users file

Set `IDP_USERS_FILE` to a JSON file containing an array of users. Passwords
must be **salted bcrypt hashes** (the salt is embedded in the bcrypt format) —
the IdP refuses to start on a file with plaintext passwords, duplicate
usernames or malformed entries. Create and maintain the file with the bundled
tool:

```sh
# build the tool
go build -o minidp-users ./cmd/minidp-users

minidp-users add    -file users.json -username alice -email alice@example.com   # prompts for the password
minidp-users add    -file users.json -username bob -password -                   # reads one line from stdin
minidp-users add    -file users.json -username carol -roles admin,auditor        # comma-separated roles
minidp-users update -file users.json -username bob -password 'new-secret'        # rotate a password
minidp-users update -file users.json -username carol -roles admin                # replace the role set
minidp-users update -file users.json -username carol -roles ''                   # clear all roles
minidp-users remove -file users.json -username bob
minidp-users list   -file users.json                                             # never prints hashes
minidp-users hash   -password '...'                                              # print a hash for manual editing
```

The file format:

```json
[
  {
    "username": "alice",
    "password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
    "email": "alice@example.com",
    "name": "Alice",
    "roles": ["admin"]
  }
]
```

Notes:

- The file is read **once at startup**; tool changes take effect on restart.
  Keep the file mode `0600` (the tool does) and mount it read-only into the
  container.
- `sub`, `preferred_username` and the audit log use the username; `email` and
  `name` appear in the tokens when set in the file **and** the corresponding
  scope (`email` / `profile`) was granted. `roles`, when set, appear as the
  `roles` array on **both** the access and the ID token regardless of the
  granted scopes; users without roles get no `roles` claim.
- Usernames cannot be probed: failed lookups burn the same bcrypt cost as a
  real hash comparison (timing equalisation).
- The account backend is an interface (`idp.UserStore`); swapping the JSON
  file for a database later only requires implementing `Lookup` and `Count`.

## Deployment

**Docker Compose** — the quickest way to a complete demo: the stack pairs
minidp with [rego-adventure](https://github.com/ghmer/rego-adventure)
`v2.2.0`, pre-wired for the PKCE flow (`IDP_CLIENT_ID=rego-adventure`,
audience enforced, discovery via the compose network, the app's redirect URI
registered). The bundled `users.json` (rego / **adventure** — demo only, the
container mounts it read-only) provides the account:

```sh
docker compose up -d --build
# App:      http://localhost:3000  (sign in with rego / adventure)
# IdP:      http://localhost:8080
```

For a non-localhost deployment override the public URLs:
`IDP_ISSUER=https://idp.example.com APP_DOMAIN=https://adventure.example.com`.

**Kubernetes**: `deploy/k8s/minidp.yaml` ships a hardened Deployment (non-root,
read-only root filesystem, dropped capabilities, probes, resource limits) plus
a Service. Accounts come from a `minidp-users` Secret mounted as the users
file; the signing key persists to an emptyDir by default (logins after
reschedule are the only impact) — follow the commented instructions in the
manifest to mount the key from a Secret instead.

**TLS**: terminate at your usual edge (ingress, Traefik, Caddy). Point the
proxy at port 8080, set `IDP_ISSUER` to the public HTTPS URL, and declare the
proxy's network in `TRUSTED_PROXIES`.

**Operational limits** — document, don't discover them in production:

- **Single instance only.** Authorization codes, refresh tokens, replay
  history and revocation state are process-local (in-memory). Run exactly one
  replica behind `strategy: Recreate`; a restart invalidates refresh tokens
  and revocation state, and multiple replicas would diverge. This is a
  deliberate trade-off of the 10 MB container scope.
- **Logout is minimal, not full OIDC RP-Initiated Logout.** `/end_session`
  accepts an `id_token_hint` (verified for signature, issuer and audience; an
  expired hint still identifies the token family) and revokes that
  authorization's tokens;
  `post_logout_redirect_uri` must exactly match a registered redirect. There
  is no browser session cookie to terminate without a hint, `client_id`,
  `logout_hint` and an independent `sid` parameter are not handled, and
  `prompt=none` requests answer `login_required` because no browser session
  is ever kept.

## Key management & rotation

The signing key is identified by a stable `kid` (`minidp-1`) published in the
JWKS. To rotate:

1. Put a **new** RSA key next to the old one (e.g. a second file in the key
   volume, or a new Secret).
2. Point `IDP_RSA_PEM` at the new key and restart minidp. All previously
   issued tokens become invalid — users log in again; refresh tokens in flight
   are rejected and the SPA falls back to a fresh authorization request.
3. A zero-downtime dual-key JWKS (old + new key published simultaneously) is
   deliberately out of scope for a single-client demo IdP.

Keep the key file mode `0600` and never commit it; treat it like the credential
it effectively is.

## Endpoints

| Endpoint                                 | Purpose                                                                   |
| ---------------------------------------- | ------------------------------------------------------------------------- |
| `GET  /.well-known/openid-configuration` | OIDC discovery                                                            |
| `GET  /jwks`                             | JSON Web Key Set (`RS256` public key)                                     |
| `GET/POST /authorize`                    | Login form + authorization code issuance                                  |
| `POST /token`                            | `authorization_code` and `refresh_token` grants                           |
| `GET/POST /userinfo`                     | Claims of the bearer token's subject                                      |
| `POST /introspect`                       | RFC 7662 token introspection                                              |
| `POST /revoke`                           | RFC 7009 revocation (refresh + access tokens via `jti` denylist)          |
| `GET  /end_session`                      | Logout; with `id_token_hint` the whole authorization's tokens are revoked |
| `GET  /healthz`                          | Liveness probe                                                            |

## Development

```sh
golangci-lint run            # 0 issues
gosec ./...                  # 0 issues
go test -race -timeout 120s ./...   # unit + HTTP flow tests
```

CI (`.github/workflows/ci.yml`) runs all three on every push. Test timeouts are
mandatory — never run the suite without `-timeout`.

## Attribution

The login page styling is derived from the Rego Adventure frontend theme and
the logo is taken from the Rego Adventure project (© Mario Enrico Ragucci,
Apache License 2.0).
