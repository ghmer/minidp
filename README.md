# minidp

A minimal OIDC/OAuth2 identity provider written in Go. It implements the
**public-client Authorization Code flow with PKCE (S256)**, issues signed
**access tokens**, **id tokens** and **rotating refresh tokens**, and is
designed to work out of the box as the IdP for
[github.com/ghmer/rego-adventure](https://github.com/ghmer/rego-adventure).

> **Scope.** minidp is production-ready **for what it is**: a lightweight IdP
> for demo and pilot deployments such as rego-adventure — with a single user,
> or a small set of users managed through a mounted JSON file. It deliberately
> has no user database, no admin UI and no clustering — that is what keeps it
> a 10 MB container instead of a Keycloak. The sections below describe the
> hardening that ships (CSRF, rate limiting, key persistence) and the
> operational decisions you must make (key management, secret handling, TLS
> termination).
>
> If you need multi-user, HA or user self-service, use Keycloak/Zitadel/Ory —
> that is a different tier of problem.

## Features

- **Multi-user mode** via a mounted JSON file of bcrypt-hashed accounts
  (managed with the bundled `minidp-users` tool), or single-user mode via env
- OIDC discovery document (`/.well-known/openid-configuration`)
- Authorization Code flow for public clients with **PKCE** (`S256` only, per RFC 9700) — PKCE is mandatory
- RS256-signed access and id tokens (JWT), `iss`/`aud`/`nonce` claims included
- Refresh token grant with **single-use rotation**
- `userinfo`, `introspect` (RFC 7662) and `revoke` (RFC 7009) endpoints
- CORS support so browser-based SPAs (e.g. `oidc-client-ts`) can exchange codes —
  only origins derived from `ALLOWED_REDIRECTS` (or listed in
  `IDP_ALLOWED_ORIGINS`) are reflected, with credentials; any other `Origin`
  gets no CORS grant
- Login page styled after the **Rego Adventure** theme

## Hardening

- **CSRF-protected login form**: the form carries an HMAC-signed token bound
  to the form action, the full OAuth2 parameter set **and a per-browser nonce
  delivered in an `HttpOnly`/`SameSite=Lax` cookie** — a token pre-fetched by
  an attacker is worthless in a victim's browser, and `SameSite=Lax` keeps the
  cookie off cross-site POSTs entirely.
- **Rate limiting**: per-client-IP token bucket on the login endpoints
  (`IDP_LOGIN_RATE_LIMIT`, default 20/min). Behind a reverse proxy, set
  `TRUSTED_PROXIES` so the real client IP is used (spoofing
  `X-Forwarded-For` from an untrusted peer is ignored).
- **Constant-time credential check**; passwords can be supplied as plaintext
  (`IDP_PASSWORD`), as a bcrypt hash (`IDP_PASSWORD_BCRYPT`) or read from a
  Docker/k8s secret file (`IDP_PASSWORD_FILE`).
- **Persistent signing key**: with `IDP_KEY_DIR` set, the RSA key is generated
  once (mode 0600, temp-file + rename) and reloaded on restart, so tokens
  survive restarts and the JWKS stays stable.
- **Single-use authorization codes** (10 min TTL) and **single-use refresh
  tokens** with rotation — replay is rejected, and replaying a rotated token
  revokes the **whole token family** of that authorization (RFC 9700 §4.14.2).
- **Working revocation**: `/revoke` deletes refresh tokens (with their family,
  RFC 7009) and denies access tokens by `jti` denylist until their expiry, so
  `/userinfo` and `/introspect` reject them immediately instead of after the
  full TTL. `/end_session?id_token_hint=…` revokes the authorization the hint
  belongs to (`sid` claim = token family).
- **Security headers**: strict CSP (`frame-ancestors 'none'`, no
  `unsafe-inline`), `X-Frame-Options: DENY`, `nosniff`, strict referrer policy.
- **Audit logging**: login success/failure (with client IP and attempted
  username), code issuance, token grants and rejections via slog.
- **Graceful shutdown** on SIGTERM/SIGINT for k8s/compose rolling updates.
- Golang-ci-lint and gosec clean (enforced in CI); `#nosec` is not used.

## Quick start

```sh
go build -o minidp .
IDP_ISSUER=http://localhost:8080 ./minidp
```

Then open `http://localhost:8080/authorize?client_id=demo&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&code_challenge=<challenge>&code_challenge_method=S256&state=x&nonce=y`
and sign in with the default user **rego** / **adventure**.

Run the end-to-end smoke test (expects the server on port 8099):

```sh
IDP_PORT=8099 IDP_ISSUER=http://localhost:8099 \
ALLOWED_REDIRECTS=http://localhost:3000/callback ./minidp &
./smoke-test.sh
```

## Configuration

All settings are provided through environment variables.

| Variable                | Default                 | Description                                                        |
| ----------------------- | ----------------------- | ------------------------------------------------------------------ |
| `IDP_HOST`              | `0.0.0.0`               | Interface to bind                                                  |
| `IDP_PORT`              | `8080`                  | TCP port to listen on                                              |
| `IDP_ISSUER`            | `http://localhost:8080` | Issuer URL; written into every token's `iss` and the discovery doc |
| `IDP_USERNAME`          | `rego`                  | The (single) user's login name                                     |
| `IDP_PASSWORD`          | `adventure`             | Plaintext password (ignored when a hash or file is configured)     |
| `IDP_PASSWORD_BCRYPT`   | *(unset)*               | bcrypt hash of the password — keeps plaintext out of manifests     |
| `IDP_PASSWORD_FILE`     | *(unset)*               | File to read the password from (Docker/k8s secrets pattern)        |
| `IDP_ACCESS_TOKEN_TTL`  | `3600`                  | Access/id token lifetime in seconds                                |
| `IDP_REFRESH_TOKEN_TTL` | `7200`                  | Refresh token lifetime in seconds                                  |
| `ALLOWED_REDIRECTS`     | *(empty = any http(s))* | Comma-separated allowlist of `redirect_uri` values — **set this in production** |
| `IDP_ALLOWED_ORIGINS`   | *(derived from `ALLOWED_REDIRECTS`)* | Explicit CORS origin allowlist; other origins are never reflected with credentials |
| `IDP_RSA_PEM`           | *(unset)*               | Path to a PKCS#1/PKCS#8 RSA private key; takes precedence over `IDP_KEY_DIR` |
| `IDP_KEY_DIR`           | *(unset)*               | Directory for the auto-generated, persisted signing key (`minidp-rsa.pem`) |
| `TRUSTED_PROXIES`       | *(empty)*               | Comma-separated CIDR ranges of proxies whose `X-Forwarded-For` is trusted |
| `IDP_CLIENT_SECRET`     | *(unset = open)*        | When set, `/introspect` and `/revoke` require client auth (Basic or `client_secret` form field) |
| `IDP_LOGIN_RATE_LIMIT`  | `20`                    | Login attempts per minute and client IP                            |
| `IDP_USERS_FILE`        | *(unset)*               | JSON file with user accounts — enables multi-user mode (see below) |
| `IDP_TITLE`             | `Rego Adventure`        | Title shown on the login page                                      |
| `IDP_SUBTITLE`          | `Sign in to begin …`    | Subtitle shown on the login page                                   |

## Using minidp with rego-adventure

Point the rego-adventure authentication environment variables at minidp:

| rego-adventure variable | Value                                   |
| ----------------------- | --------------------------------------- |
| `AUTH_ENABLED`          | `true`                                  |
| `AUTH_ISSUER`           | minidp's `IDP_ISSUER`                   |
| `AUTH_DISCOVERY_URL`    | `<IDP_ISSUER>/.well-known/openid-configuration` |
| `AUTH_CLIENT_ID`        | `rego-adventure` (public client)        |
| `AUTH_AUDIENCE`         | `rego-adventure` (minidp sets `aud` to the client id) |

The frontend performs the PKCE code exchange directly against minidp (CORS is
enabled for this); the backend validates the Bearer JWT against minidp's JWKS.

## Multi-user mode

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
minidp-users update -file users.json -username bob -password 'new-secret'        # rotate a password
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
    "name": "Alice"
  }
]
```

Notes:

- The file is read **once at startup**; tool changes take effect on restart.
  Keep the file mode `0600` (the tool does) and mount it read-only into the
  container.
- `sub`, `preferred_username` and the audit log use the username; `email` and
  `name` appear in the access/id tokens when set in the file.
- Usernames cannot be probed: failed lookups burn the same bcrypt cost as a
  real hash comparison (timing equalisation).
- Single-user mode (`IDP_USERNAME`/`IDP_PASSWORD*`) and `IDP_USERS_FILE` are
  mutually exclusive — minidp fails fast if both are configured.
- The account backend is an interface (`idp.UserStore`); swapping the JSON
  file for a database later only requires implementing `Lookup` and `Count`.

## Deployment

**Docker Compose** — the quickest way to a complete demo: the stack pairs
minidp with [rego-adventure](https://github.com/ghmer/rego-adventure) `v2.2.0`,
pre-wired for the PKCE flow (`AUTH_CLIENT_ID=rego-adventure`, discovery via the
compose network, redirect URI allowlisted):

```sh
docker compose up -d --build
# App:      http://localhost:3000  (sign in with rego / adventure)
# IdP:      http://localhost:8080
```

For a non-localhost deployment override the public URLs:
`IDP_ISSUER=https://idp.example.com APP_DOMAIN=https://adventure.example.com`.

**Kubernetes**: `deploy/k8s/minidp.yaml` ships a hardened Deployment (non-root,
read-only root filesystem, dropped capabilities, probes, resource limits) plus
a Service. Credentials come from a Secret; the signing key persists to an
emptyDir by default (logins after reschedule are the only impact) — follow the
commented instructions in the manifest to mount the key from a Secret instead.

**TLS**: terminate at your usual edge (ingress, Traefik, Caddy). Point the
proxy at port 8080, set `IDP_ISSUER` to the public HTTPS URL, and declare the
proxy's network in `TRUSTED_PROXIES`.

## Key management & rotation

The signing key is identified by a stable `kid` (`minidp-1`) published in the
JWKS. To rotate:

1. Put a **new** RSA key next to the old one (e.g. a second file in the key
   volume, or a new Secret).
2. Point `IDP_RSA_PEM` at the new key and restart minidp. All previously
   issued tokens become invalid — users log in again; refresh tokens in flight
   are rejected and the SPA falls back to a fresh authorization request.
3. A zero-downtime dual-key JWKS (old + new key published simultaneously) is
   deliberately out of scope for a single-user demo IdP.

Keep the key file mode `0600` and never commit it; treat it like the credential
it effectively is.

## Endpoints

| Endpoint                                   | Purpose                                   |
| ------------------------------------------ | ----------------------------------------- |
| `GET  /.well-known/openid-configuration`   | OIDC discovery                            |
| `GET  /jwks`                               | JSON Web Key Set (`RS256` public key)     |
| `GET/POST /authorize`                      | Login form + authorization code issuance  |
| `POST /token`                              | `authorization_code` and `refresh_token` grants |
| `GET/POST /userinfo`                       | Claims of the bearer token's subject      |
| `POST /introspect`                         | RFC 7662 token introspection              |
| `POST /revoke`                             | RFC 7009 revocation (refresh + access tokens via `jti` denylist) |
| `GET  /end_session`                        | Logout; with `id_token_hint` the whole authorization's tokens are revoked |
| `GET  /healthz`                            | Liveness probe                            |

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
