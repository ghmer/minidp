# minidp

A minimal multi-client OIDC/OAuth2 identity provider written in Go. It
implements the Authorization Code flow for public clients (mandatory PKCE,
S256) and confidential clients (client authentication at the token
endpoint), and issues signed access tokens, ID tokens, and rotating refresh
tokens. It works with any standards-compliant OIDC client — browser SPAs
using libraries such as [oidc-client-ts](https://github.com/authts/oidc-client-ts),
and backend resource servers that validate JWTs against the published JWKS.

**Scope.** minidp is built for demo and pilot deployments with a small,
fixed set of registered clients — each with its own redirect policy,
audience and user accounts, managed through a mounted JSON file. There is no
user database, no admin UI and no dynamic client registration. Sorry :-)

## Features

- Multiple registered clients in one clients file (`IDP_CLIENTS_FILE`,
  managed with the bundled `clientctl` tool). Each client has its own
  profile (public or confidential), redirect policy, token audience
  (defaults to the client ID) and user accounts. A client's users cannot
  sign in through another client's flow, and any other `client_id` is
  rejected at `/authorize` and `/token`.
- Per-client accounts, stored as bcrypt hashes inside the clients file —
  the only credential source; there are no built-in accounts.
- OIDC discovery document (`/.well-known/openid-configuration`).
- Authorization Code flow for public clients with mandatory PKCE (S256
  only, per RFC 9700, RFC 7636 syntax enforced). See
  [Client profiles](docs/clients.md#client-profiles-public-vs-confidential) for the
  confidential variant.
- RS256-signed tokens using the RFC 9068 `at+jwt` profile for access tokens
   (`typ` header), so an ID token can't be replayed as an access token.
- Claims are released according to the granted scopes, from the
  authoritative account record (`profile` → `preferred_username`/`name`,
    `email` → `email`). `roles` is released on both access and ID tokens
  whenever the user record defines it — roles are authorization data, not
  scope-gated profile claims.
- Refresh token grant with single-use rotation.
- `userinfo`, `introspect` (RFC 7662) and `revoke` (RFC 7009) endpoints.
- CORS support for browser-based SPAs (e.g. `oidc-client-ts`). Only origins
  derived from a client's registered redirects, or listed in its
    `allowed_origins`, are reflected, with credentials.
- Login page with configurable title/subtitle, and per-file asset
  overrides (see [Login page branding](docs/branding.md)).

Security hardening — CSRF protection, rate limiting, constant-time
credential checks, persistent signing key, single-use codes and refresh
tokens, working revocation, security headers, and audit logging — is
documented in **[docs/security.md](docs/security.md)**. The public-client
profile carries two accepted trade-offs (unauthenticated `/revoke`/
`/introspect`, unconstrained refresh tokens), also listed there.

## Quick start

minidp has no built-in accounts and no open-redirect fallback, so a clients
file with registered clients, redirect policies and accounts is required.
Create one with the bundled tool (or copy `clients.json.example` and rotate
the credentials):

```sh
go build -o minidp .
go build -o clientctl ./cmd/clientctl

clientctl client add -file clients.json -client demo-app -type public \
    -redirect http://localhost:3000/callback
clientctl user add -file clients.json -client demo-app -username alice -email alice@example.com    # prompts for the password

IDP_ISSUER=http://localhost:8080 \
IDP_CLIENTS_FILE=$PWD/clients.json \
./minidp
```

Then open
`http://localhost:8080/authorize?client_id=demo-app&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&code_challenge=<challenge>&code_challenge_method=S256&state=x&nonce=y`
and sign in with the account you created.

Run the self-contained end-to-end smoke test (builds, boots its own
instances, exercises the full flow for both profiles):

```sh
./smoke-test.sh
```

## Configuration

Server settings come from environment variables; everything about the
clients lives in the clients file. Full tables and the list of removed
variables are in **[docs/configuration.md](docs/configuration.md)** — key
ones: `IDP_ISSUER`, `IDP_CLIENTS_FILE` (required), `IDP_ACCESS_TOKEN_TTL`,
`IDP_REFRESH_TOKEN_TTL`, `IDP_KEY_DIR` / `IDP_RSA_PEM`, `TRUSTED_PROXIES`,
`IDP_LOGIN_RATE_LIMIT`, `IDP_TITLE`, `IDP_SUBTITLE`.

Managing clients and accounts — profiles, secrets, redirect policies, the
`clientctl` tool and the clients-file format — is in
**[docs/clients.md](docs/clients.md)**.

## Endpoints

| Endpoint                                  | Purpose                                                              |
| ----------------------------------------- | -------------------------------------------------------------------- |
| `GET   /.well-known/openid-configuration` | OIDC discovery                                                       |
| `GET   /jwks`                             | JSON Web Key Set (`RS256` public key)                                |
| `GET/POST /authorize`                     | Login form + authorization code issuance                             |
| `POST /token`                             | `authorization_code` and `refresh_token` grants                      |
| `GET/POST /userinfo`                      | Claims of the bearer token's subject                                 |
| `POST /introspect`                        | RFC 7662 token introspection                                         |
| `POST /revoke`                            | RFC 7009 revocation (refresh + access tokens via `jti` denylist)     |
| `GET   /end_session`                      | Logout; with `id_token_hint`, the authorization's tokens are revoked |
| `GET   /healthz`                          | Liveness probe                                                       |

## Deployment

Docker, Kubernetes and TLS are covered in
**[docs/deployment.md](docs/deployment.md)** — including the single-instance
operational limit and key management/rotation.

## Development

```sh
golangci-lint run             # 0 issues
gosec ./...                   # 0 issues
go test -race -timeout 120s ./...    # unit + HTTP flow tests
```

CI (`.github/workflows/ci.yml`) runs all three on every push. Test timeouts
are mandatory — never run the suite without `-timeout`.

## Attribution

The embedded login page logo is taken from the Rego Adventure project
(© Mario Enrico Ragucci, Apache License 2.0). The default login page
styling is minidp's own "Deep Water" theme.
