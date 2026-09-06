# minidp

A minimal OIDC/OAuth2 identity provider written in Go. It implements the
**public-client Authorization Code flow with PKCE (S256)**, issues signed
**access tokens**, **id tokens** and **rotating refresh tokens**, and is
designed to work out of the box as the IdP for
[github.com/ghmer/rego-adventure](https://github.com/ghmer/rego-adventure).

> ⚠️ **This is a development-grade IdP.** It supports exactly one user, keeps
> authorization codes and refresh tokens in memory (they are lost on restart)
> and generates an ephemeral RSA signing key unless one is provided. Do not use
> it in production without swapping the store and key handling for persistent,
> hardened implementations.

## Features

- OIDC discovery document (`/.well-known/openid-configuration`)
- Authorization Code flow for public clients with **PKCE** (`S256`, `plain`)
- RS256-signed access and id tokens (JWT), `iss`/`aud`/`nonce` claims included
- Refresh token grant with **single-use rotation**
- `userinfo`, `introspect` (RFC 7662) and `revoke` (RFC 7009) endpoints
- CORS support so browser-based SPAs (e.g. `oidc-client-ts`) can exchange codes
- Login page styled after the **Rego Adventure** theme

## Quick start

```sh
go build -o minidp .
IDP_ISSUER=http://localhost:8080 ./minidp
```

Then open `http://localhost:8080/authorize?client_id=demo&redirect_uri=http://localhost:3000/callback&response_type=code&scope=openid&code_challenge=<challenge>&code_challenge_method=S256&state=x&nonce=y`
and sign in with the default user **rego** / **adventure**.

Run the end-to-end smoke test (expects the server on port 8099):

```sh
IDP_PORT=8099 IDP_ISSUER=http://localhost:8099 ./minidp &
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
| `IDP_PASSWORD`          | `adventure`             | The (single) user's password                                       |
| `IDP_ACCESS_TOKEN_TTL`  | `3600`                  | Access/id token lifetime in seconds                                |
| `IDP_REFRESH_TOKEN_TTL` | `7200`                  | Refresh token lifetime in seconds                                  |
| `ALLOWED_REDIRECTS`     | *(empty = any http(s))* | Comma-separated allowlist of `redirect_uri` values                 |
| `IDP_RSA_PEM`           | *(empty = ephemeral)*   | Path to a PKCS#1/PKCS#8 RSA private key (keeps tokens valid across restarts) |
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

## Endpoints

| Endpoint                                   | Purpose                                   |
| ------------------------------------------ | ----------------------------------------- |
| `GET  /.well-known/openid-configuration`   | OIDC discovery                            |
| `GET  /jwks`                               | JSON Web Key Set (`RS256` public key)     |
| `GET/POST /authorize`                      | Login form + authorization code issuance  |
| `POST /token`                              | `authorization_code` and `refresh_token` grants |
| `GET/POST /userinfo`                       | Claims of the bearer token's subject      |
| `POST /introspect`                         | RFC 7662 token introspection              |
| `POST /revoke`                             | RFC 7009 token revocation                 |
| `GET  /end_session`                        | Minimal logout                            |
| `GET  /healthz`                            | Liveness probe                            |

## Development

```sh
golangci-lint run   # 0 issues
gosec ./...         # 0 issues
go test -race ./... # unit + HTTP flow tests
```

## Attribution

The login page styling is derived from the Rego Adventure frontend theme and
the logo is taken from the Rego Adventure project (© Mario Enrico Ragucci,
Apache License 2.0).
