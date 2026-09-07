# Configuration

Server settings come from environment variables. Everything about the
clients — profiles, secrets, redirect policies, audiences, accounts — lives
exclusively in the clients file (see [Clients and accounts](clients.md)).

| Variable                | Default                 | Description                                                                  |
| ----------------------- | ----------------------- | ---------------------------------------------------------------------------- |
| `IDP_HOST`              | `0.0.0.0`               | Interface to bind                                                            |
| `IDP_PORT`              | `8080`                  | TCP port to listen on                                                        |
| `IDP_ISSUER`            | `http://localhost:8080` | Issuer URL; written into every token's `iss` and the discovery doc           |
| `IDP_CLIENTS_FILE`      | *(required)*            | JSON file with registered clients and their users (see below)                |
| `IDP_ACCESS_TOKEN_TTL`  | `3600`                  | Access/ID token lifetime in seconds                                          |
| `IDP_REFRESH_TOKEN_TTL` | `7200`                  | Refresh token lifetime in seconds                                            |
| `IDP_RSA_PEM`           | *(unset)*               | Path to a PKCS#1/PKCS#8 RSA private key; takes precedence over `IDP_KEY_DIR` |
| `IDP_KEY_DIR`           | *(unset)*               | Directory for the auto-generated, persisted signing key (`minidp-rsa.pem`)   |
| `TRUSTED_PROXIES`       | *(empty)*               | Comma-separated CIDR ranges of proxies whose `X-Forwarded-For` is trusted    |
| `IDP_LOGIN_RATE_LIMIT`  | `20`                    | Login attempts per minute and client IP                                      |
| `IDP_TITLE`             | `minidp`                | Title shown on the login page                                                |
| `IDP_SUBTITLE`          | `Sign in to continue`   | Subtitle shown on the login page                                             |

## Removed variables

The single-user credential variables from earlier versions
(`IDP_USERNAME`, `IDP_PASSWORD`, `IDP_PASSWORD_BCRYPT`, `IDP_PASSWORD_FILE`)
and the single-client variables (`IDP_CLIENT_ID`, `IDP_AUDIENCE`,
`IDP_CLIENT_SECRET`, `ALLOWED_REDIRECTS`, `IDP_ALLOWED_ORIGINS`,
`IDP_USERS_FILE`, `MINIDP_MODE`) have been removed. Setting any of them
aborts startup with a migration hint — register clients and accounts in the
clients file instead.
