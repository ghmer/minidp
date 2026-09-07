# minidp

A minimal **multi-client** OIDC/OAuth2 identity provider written in Go. It
implements the **Authorization Code flow** for **public clients with
mandatory PKCE (S256)** and for **confidential clients with client
authentication at the token endpoint**, issues signed **access tokens**,
**id tokens** and **rotating refresh tokens**, and works with any
standards-compliant OIDC client — browser SPAs using libraries such as
[oidc-client-ts](https://github.com/authts/oidc-client-ts) as well as backend
resource servers that validate JWTs against the published JWKS.

> **Scope.** minidp is production-ready **for what it is**: a lightweight IdP
> for demo and pilot deployments — with a small set of registered clients
> (each with its own redirect policy, audience and user accounts) managed
> through a mounted JSON file. It deliberately has no user database, no admin
> UI, no dynamic client registration and no clustering — that is what keeps
> it a 10 MB container instead of a Keycloak. The sections below describe the
> hardening that ships (CSRF, rate limiting, key persistence) and the
> operational decisions you must make (key management, TLS termination).
>
> If you need multi-tenancy, multi-user self-service or HA, use
> Keycloak/Zitadel/Ory — that is a different tier of problem.

## Features

- **Multiple registered clients** in one clients file (`IDP_CLIENTS_FILE`,
  managed with the bundled `clientctl` tool): every client has its own
  profile (public or confidential), its own **redirect policy**, its own
  token **audience** (defaulting to the client id) and its **own user
  accounts** — a client's users can never sign in to another client's flow,
  and every other `client_id` is rejected at `/authorize` and `/token`
- **Per-client accounts** live inside the clients file as bcrypt-hashed
  entries — the only credential source; there are no built-in accounts
- **Mandatory redirect policy**: every client declares at least one
  `redirect_uri`; minidp refuses to start without them
- OIDC discovery document (`/.well-known/openid-configuration`)
- Authorization Code flow for **public clients** with **mandatory PKCE**
  (`S256` only, per RFC 9700, RFC 7636 syntax enforced) — see
  [Client profiles](#client-profiles-public-vs-confidential) for the
  confidential variant
- RS256-signed tokens with the RFC 9068 `at+jwt` token profile for access
  tokens (`typ` header) — an **id token can never be replayed as an access
  token**
- Claims are released **according to the granted scopes** from the
  authoritative account record (`profile` → `preferred_username`/`name`,
  `email` → `email`); `roles` are released as the `roles` claim on the access
  and ID tokens **whenever the user record defines them** (they are
  authorization data, not scope-gated profile claims)
- Refresh token grant with **single-use rotation**
- `userinfo`, `introspect` (RFC 7662) and `revoke` (RFC 7009) endpoints
- CORS support so browser-based SPAs (e.g. `oidc-client-ts`) can exchange
  codes — only origins derived from any client's registered redirects (or
  listed in the client's `allowed_origins`) are reflected, with credentials;
  any other `Origin` gets no CORS grant
- Login page with the built-in **Deep Water** theme — light and dark mode via
  the OS `prefers-color-scheme` — configurable title/subtitle, and per-file
  asset overrides (see [Login page branding](#login-page-branding))

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
- **Confidential client authentication**: constant-time secret comparison
  (Basic and form methods) against the named client's own secret, client
  authentication **before** codes/refresh tokens are consumed, RFC 9700
  §2.3.2 Basic-vs-form `client_id` conflict rejection, and fail-fast startup
  validation of every profile/secret combination.
- **Audit logging**: login success/failure (with client IP and attempted
  username), code issuance, token grants and rejections via slog.
- **Graceful shutdown** on SIGTERM/SIGINT for k8s/compose rolling updates.
- Golang-ci-lint and gosec clean (enforced in CI); no `#nosec` directives.

### Security trade-offs (accepted by design)

These limitations are inherent to the public-client profile (no secret, no
sender-constrained tokens). They are recorded here so they remain **conscious
decisions** rather than surprises; revisit them if the deployment profile ever
changes:

- **`/revoke` and `/introspect` are unauthenticated when every client is
  public** — and `/revoke` is a *write* operation: anyone who merely
  **observes** a bearer token (a proxy or browser log, a `Referer`,
  mixed-content capture) can use it to revoke that session (refresh family
  revoked, live access tokens denied by `jti`) — a targeted denial of service
  for the victim. Public clients have no client secret to authenticate the
  call, and sender-constraining the tokens (e.g. DPoP) is out of scope for
  minidp; token confidentiality in transit is the mitigation. As soon as
  **any** confidential client is registered, both endpoints require client
  authentication (the named client's own secret, via Basic or form pair).
- **Refresh tokens are unconstrained bearer tokens.** For public clients they
  are redeemable with only the `client_id` — a leaked refresh token is fully
  replayable by anyone until its TTL. Single-use rotation and family-wide
  revocation on reuse (RFC 9700 §4.14.2) contain the blast radius but do not
  eliminate the exposure; this is the standard public-client trade-off,
  accepted here deliberately. Use the `confidential` profile when the client
  can keep a secret.

## Quick start

minidp has no built-in accounts and no open redirect fallback, so a clients
file with registered clients, redirect policies and accounts is mandatory.
Create it with the bundled tool (or copy `clients.json.example` and rotate
the credentials):

```sh
go build -o minidp .
go build -o clientctl ./cmd/clientctl

clientctl client add -file clients.json -client demo-app -type public \
  -redirect http://localhost:3000/callback
clientctl user add -file clients.json -client demo-app -username alice -email alice@example.com   # prompts for the password

IDP_ISSUER=http://localhost:8080 \
IDP_CLIENTS_FILE=$PWD/clients.json \
./minidp
```

Then open
`http://localhost:8080/authorize?client_id=demo-app&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&code_challenge=<challenge>&code_challenge_method=S256&state=x&nonce=y`
and sign in with the account you created.

Run the self-contained end-to-end smoke test (builds, boots its own instances
and exercises the whole flow, public and confidential):

```sh
./smoke-test.sh
```

## Configuration

All server settings are provided through environment variables; **everything
about the clients** (profiles, secrets, redirect policies, audiences,
accounts) lives exclusively in the clients file.

| Variable                | Default                 | Description                                                                        |
| ----------------------- | ----------------------- | ---------------------------------------------------------------------------------- |
| `IDP_HOST`              | `0.0.0.0`               | Interface to bind                                                                  |
| `IDP_PORT`              | `8080`                  | TCP port to listen on                                                              |
| `IDP_ISSUER`            | `http://localhost:8080` | Issuer URL; written into every token's `iss` and the discovery doc                 |
| `IDP_CLIENTS_FILE`      | *(required)*            | JSON file with the registered clients and their users (see below)                  |
| `IDP_ACCESS_TOKEN_TTL`  | `3600`                  | Access/id token lifetime in seconds                                                |
| `IDP_REFRESH_TOKEN_TTL` | `7200`                  | Refresh token lifetime in seconds                                                  |
| `IDP_RSA_PEM`           | *(unset)*               | Path to a PKCS#1/PKCS#8 RSA private key; takes precedence over `IDP_KEY_DIR`       |
| `IDP_KEY_DIR`           | *(unset)*               | Directory for the auto-generated, persisted signing key (`minidp-rsa.pem`)         |
| `TRUSTED_PROXIES`       | *(empty)*               | Comma-separated CIDR ranges of proxies whose `X-Forwarded-For` is trusted          |
| `IDP_LOGIN_RATE_LIMIT`  | `20`                    | Login attempts per minute and client IP                                            |
| `IDP_TITLE`             | `minidp`                | Title shown on the login page                                                      |
| `IDP_SUBTITLE`          | `Sign in to continue`   | Subtitle shown on the login page                                                   |

The single-user credential variables (`IDP_USERNAME`, `IDP_PASSWORD`,
`IDP_PASSWORD_BCRYPT`, `IDP_PASSWORD_FILE`) and the single-client variables
of earlier versions (`IDP_CLIENT_ID`, `IDP_AUDIENCE`, `IDP_CLIENT_SECRET`,
`ALLOWED_REDIRECTS`, `IDP_ALLOWED_ORIGINS`, `IDP_USERS_FILE`, `MINIDP_MODE`)
were **removed**; setting any of them aborts startup with a migration hint.
Register clients and accounts in the clients file.

## Client profiles: public vs confidential

Each client entry carries its own RFC 6749 profile. minidp refuses to start
on inconsistent entries (a secret on a public client is dead configuration; a
confidential client without a secret would authenticate every caller), so the
profile and the secret are validated together at startup — and on every
clientctl save.

**`"type": "public"`** — the browser-SPA profile:

- PKCE (S256) is **mandatory** at `/authorize` and verified at `/token`
- `/token` accepts only `client_id` identification — public clients cannot
  keep secrets, so none may be configured
- when **every** client is public, `/introspect` and `/revoke` are open
  (documented trade-off, see
  [Security trade-offs](#security-trade-offs-accepted-by-design))

**`"type": "confidential"`** — the profile for a client that can hold a
secret (requires `client_secret` in the entry):

- `/token` **requires client authentication**: `client_secret_basic` (HTTP
  Basic, RFC 6749 §2.3.1 form-urlencoded credentials) or
  `client_secret_post` (`client_id` + `client_secret` form fields). The
  presented `client_id` is resolved first and the secret is compared only
  against that client's own secret, in constant time. Failures answer
  `401 invalid_client` and are **logged** (audit/IDS), not rate limited — the
  same rationale as the token endpoint itself.
- PKCE becomes **optional**: the secret is the client's proof of identity. If
  the client still sends a `code_challenge`, it is validated as strictly as in
  public mode (S256, RFC 7636 shape) and the matching `code_verifier` is
  required at `/token`. RFC 9700 §2.1.1 recommends PKCE for all clients —
  keep using it if you can.
- Failed client authentication happens **before** the authorization code or
  refresh token is consumed: a wrong secret can never burn a valid code.
- Client authentication is also required on the **refresh token grant**
  (RFC 6749 §6); on success the refresh chain (rotation, family revocation on
  reuse) behaves exactly as for public clients.
- With at least one confidential client registered, discovery advertises
  `client_secret_basic` + `client_secret_post` alongside `none` for the
  token/revocation/introspection endpoints, and `/introspect`//`revoke`
  require client authentication.

```sh
clientctl client add -file clients.json -client backend -type confidential \
  -secret "$(openssl rand -base64 32)" -redirect https://backend.example.com/cb
```

Use a cryptographically random secret of at least 128 bits; shorter secrets
trigger a startup warning.

## Connecting a client application

Every token carries the audience of the client it was issued for (the
client's `audience`, defaulting to its `client_id`). Nothing is reflected: a
token minted for — or presented at — any other audience is rejected. Point
your OIDC client library (oidc-client-ts, AppAuth, Auth.js or any library
that speaks the standard) at minidp:

| Client setting      | Value                                                       |
| ------------------- | ----------------------------------------------------------- |
| Issuer / authority  | minidp's `IDP_ISSUER`                                       |
| Discovery           | `<IDP_ISSUER>/.well-known/openid-configuration`             |
| `client_id`         | a registered client's `client_id`                           |
| Redirect URI        | one of that client's `redirect_uris` (exact match)          |
| Scopes              | `openid profile email`                                      |
| PKCE                | `S256` (mandatory for public clients)                       |

The browser SPA performs the PKCE code exchange directly against minidp (CORS
is enabled for this); a backend resource server validates the Bearer JWT
against minidp's JWKS (`/jwks`) and rejects tokens whose `aud` does not equal
its client's audience. The SPA should request `openid profile email` — claims
are released strictly by scope: `profile` unlocks `preferred_username`/`name`
(on both tokens and `/userinfo`), `email` unlocks the `email` claim, and a
token without the `openid` scope cannot call `/userinfo`. Roles set on the
account record are released as the `roles` array claim on both tokens
independent of the scopes.

A client's authorization **code is bound to that client** (RFC 6749 §4.1.3):
another client cannot redeem it even with valid credentials — the attempt
burns the code (theft signal), just as a client mismatch on a refresh token
revokes the whole token family.

## Login page branding

The login page ships with the embedded **Deep Water** theme (light and dark
mode, following the OS `prefers-color-scheme`) and an embedded logo. Both can
be replaced without rebuilding: at startup minidp checks the fixed directory
`assets/` relative to its working directory and overrides per file.

| File               | Overrides                   |
| ------------------ | --------------------------- |
| `assets/login.css` | the `/login.css` stylesheet |
| `assets/logo.svg`  | the `/logo.svg` logo, favicon |

- **Per-file fallback**: a missing file keeps the embedded default, so
  mounting only a logo is enough.
- Files are read **once at startup** (2 MiB limit each) and cached in memory;
  changes take effect on restart.
- The location is a **compiled-in constant** — there is no environment
  variable for paths. In the container the working directory is `/app`, so the
  mount point is `/app/assets` (Docker: `-v ./assets:/app/assets:ro`;
  Kubernetes: mount a ConfigMap there, see `deploy/k8s/minidp.yaml`).
- The page title and subtitle come from `IDP_TITLE` / `IDP_SUBTITLE`.

An override that exists but cannot be read (e.g. wrong permissions) aborts
startup: a mount the operator meant to take effect must never degrade into
silence.

## Clients and accounts: the clients file

Set `IDP_CLIENTS_FILE` to a JSON file containing an array of clients. Each
client carries its own profile, redirect policy, audience and user accounts.
Passwords must be **salted bcrypt hashes** (the salt is embedded in the
bcrypt format) — the IdP refuses to start on a file with plaintext passwords,
duplicate usernames or malformed entries. Create and maintain the file with
the bundled tool:

```sh
# build the tool
go build -o clientctl ./cmd/clientctl

clientctl client list                                                # overview (never prints secrets)
clientctl client show  -file clients.json -client demo-app           # one client + its users
clientctl client add   -file clients.json -client demo-app -type public \
    -redirect http://localhost:3000/callback,https://app.example.com/cb
clientctl client add   -file clients.json -client backend -type confidential \
    -secret "$(openssl rand -base64 32)" -redirect https://backend.example.com/cb \
    -post-logout https://backend.example.com/ -origin https://backend-spa.example.com
clientctl client update -file clients.json -client backend -audience my-api
clientctl client remove -file clients.json -client backend

clientctl user list   -file clients.json -client demo-app            # never prints hashes
clientctl user add    -file clients.json -client demo-app -username alice -email alice@example.com   # prompts for the password
clientctl user add    -file clients.json -client demo-app -username bob -password -                  # reads one line from stdin
clientctl user add    -file clients.json -client demo-app -username carol -roles admin,auditor       # comma-separated roles
clientctl user update -file clients.json -client demo-app -username bob -password 'new-secret'        # rotate a password
clientctl user update -file clients.json -client demo-app -username carol -roles admin                # replace the role set
clientctl user update -file clients.json -client demo-app -username carol -roles ''                   # clear all roles
clientctl user remove -file clients.json -client demo-app -username bob
clientctl hash        -password '...'                                 # print a hash for manual editing
```

The file format (see `clients.json.example`):

```json
[
  {
    "client_id": "spa-app",
    "type": "public",
    "audience": "spa-app",
    "redirect_uris": ["http://localhost:3000/callback"],
    "post_logout_redirect_uris": ["http://localhost:3000/callback"],
    "allowed_origins": [],
    "users": [
      {
        "username": "alice",
        "password_hash": "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
        "email": "alice@example.com",
        "name": "Alice",
        "roles": ["admin"]
      }
    ]
  }
]
```

Notes:

- `client_id` must be unique and free of whitespace; `type` is `public` or
  `confidential`; a confidential entry requires `client_secret` (≥128 random
  bits), a public entry must not have one. `audience` defaults to the
  `client_id`. Every `redirect_uri` must be an absolute http(s) URL without a
  fragment, compared by exact string match at `/authorize`.
- `post_logout_redirect_uris` are the targets `/end_session` may redirect to
  for that client (resolved from the `id_token_hint`'s audience or the
  `client_id` parameter); an empty list means logout renders a confirmation
  page instead of redirecting.
- `allowed_origins` adds explicit CORS origins on top of the hosts derived
  from the redirect URIs.
- Each client's `users` are the only accounts that can sign in for that
  client — one client's users are invisible to another client's login form.
- The file is read **once at startup**; tool changes take effect on restart.
  Keep the file mode `0600` (the tool does; it holds client secrets and
  password hashes) and mount it read-only into the container. The tool may
  write transient states (a client without users yet); the IdP refuses to
  start with those and says exactly which entry is incomplete.
- `sub`, `preferred_username` and the audit log use the username; `email` and
  `name` appear in the tokens when set in the file **and** the corresponding
  scope (`email` / `profile`) was granted. `roles`, when set, appear as the
  `roles` array on **both** the access and the ID token regardless of the
  granted scopes; users without roles get no `roles` claim.
- Usernames cannot be probed: failed lookups burn the same bcrypt cost as a
  real hash comparison (timing equalisation, per client).
- The account backend is an interface (`idp.UserStore`); swapping the
  clients file for a database later only requires implementing `Lookup`,
  `Count` and `DummyHash`.

## Deployment

**Docker** — build the image and run it with the mandatory files mounted:

```sh
docker build -t minidp .
docker run -d --name minidp -p 8080:8080 \
  -e IDP_ISSUER=http://localhost:8080 \
  -e IDP_CLIENTS_FILE=/config/clients.json \
  -v "$PWD/clients.json:/config/clients.json:ro" \
  -v minidp-data:/data \
  minidp
# IdP: http://localhost:8080
```

For a non-localhost deployment override the public URL:
`IDP_ISSUER=https://idp.example.com`, and register the client's public
redirect URI in its clients-file entry.

**Kubernetes**: `deploy/k8s/minidp.yaml` ships a hardened Deployment (non-root,
read-only root filesystem, dropped capabilities, probes, resource limits) plus
a Service. Clients and accounts come from a `minidp-clients` Secret mounted as
the clients file; the signing key persists to an emptyDir by default (logins
after reschedule are the only impact) — follow the commented instructions in
the manifest to mount the key from a Secret instead.

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
   `post_logout_redirect_uri` must exactly match a post-logout target
   registered for the client resolved from the hint (or the `client_id`
   parameter). There is no browser session cookie to terminate without a
   hint, `logout_hint` and an independent `sid` parameter are not handled,
   and `prompt=none` requests answer `login_required` because no browser
   session is ever kept.

## Key management & rotation

The signing key is identified by a stable `kid` (`minidp-1`) published in the
JWKS. To rotate:

1. Put a **new** RSA key next to the old one (e.g. a second file in the key
   volume, or a new Secret).
2. Point `IDP_RSA_PEM` at the new key and restart minidp. All previously
   issued tokens become invalid — users log in again; refresh tokens in flight
   are rejected and the SPA falls back to a fresh authorization request.
3. A zero-downtime dual-key JWKS (old + new key published simultaneously) is
   deliberately out of scope for a demo IdP.

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

The embedded login page logo is taken from the Rego Adventure project
(© Mario Enrico Ragucci, Apache License 2.0). The default login page styling
is minidp's own "Deep Water" theme.
