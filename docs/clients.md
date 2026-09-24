# Clients and accounts

minidp is built for demo and pilot deployments with a small, fixed set of
registered clients — each with its own redirect policy, audience and user
accounts, managed through a mounted JSON file. There is no user database, no
admin UI and no dynamic client registration.

Every client entry carries its own RFC 6749 profile. minidp refuses to start
on inconsistent entries — a secret on a public client is dead
configuration, and a confidential client without a secret would
authenticate every caller — so profile and secret are validated together at
startup, and on every `clientctl` save.

## Client profiles: public vs confidential

**`"type": "public"`** — the browser-SPA profile:

- PKCE (S256) is mandatory at `/authorize` and verified at `/token`.
- `/token` accepts only `client_id` identification — public clients can't
  keep secrets, so none may be configured.
- When every client is public, `/introspect` and `/revoke` are open (see
  [Accepted trade-offs](security.md#accepted-trade-offs)).

**`"type": "confidential"`** — for a client that can hold a secret
(requires `client_secret` in the entry):

- `/token` requires client authentication: `client_secret_basic` (HTTP
  Basic, RFC 6749 §2.3.1 form-urlencoded credentials) or
   `client_secret_post` (`client_id` + `client_secret` form fields). The
   `client_id` is resolved first, and the secret is compared only against
  that client's own secret, in constant time. Failures answer `401
  invalid_client` and are logged, not rate-limited — same rationale as the
  token endpoint itself.
- PKCE becomes optional: the secret is the client's proof of identity. If
  the client still sends a `code_challenge`, it's validated as strictly as
  in public mode (S256, RFC 7636 shape), and the matching `code_verifier`
  is required at `/token`. RFC 9700 §2.1.1 recommends PKCE for all clients
   — keep using it if you can.
- Failed client authentication happens before the authorization code or
  refresh token is consumed: a wrong secret can never burn a valid code.
- Client authentication is also required on the refresh token grant (RFC
   6749 §6); on success the refresh chain (rotation, family revocation on
  reuse) behaves exactly as for public clients.
- With at least one confidential client registered, discovery advertises
   `client_secret_basic` and `client_secret_post` alongside `none` for the
  token/revocation/introspection endpoints, and `/introspect`/`/revoke`
  require client authentication.

```sh
clientctl client add -file clients.json -client backend -type confidential \
   -secret "$(openssl rand -base64 32)" -redirect https://backend.example.com/cb
```

Use a cryptographically random secret of at least 128 bits — shorter
secrets trigger a startup warning.

## Connecting a client application

Every token carries the audience of the client it was issued for (the
client's `audience`, defaulting to its `client_id`). Nothing is reflected —
a token minted for, or presented at, any other audience is rejected. Point
your OIDC client library (oidc-client-ts, AppAuth, Auth.js, or any
standards-compliant library) at minidp:

| Client setting     | Value                                              |
| ------------------ | -------------------------------------------------- |
| Issuer / authority | minidp's `IDP_ISSUER`                              |
| Discovery          | `<IDP_ISSUER>/.well-known/openid-configuration`    |
| `client_id`        | a registered client's `client_id`                  |
| Redirect URI       | one of that client's `redirect_uris` (exact match) |
| Scopes             | `openid profile email`                             |
| PKCE               | `S256` (mandatory for public clients)              |

The browser SPA performs the PKCE code exchange directly against minidp
(CORS is enabled for this); a backend resource server validates the bearer
JWT against minidp's JWKS (`/jwks`) and rejects tokens whose `aud` doesn't
match its own audience. Claims are released strictly by scope: `profile`
unlocks `preferred_username`/`name` (on both tokens and `/userinfo`),
`email` unlocks the `email` claim, and a token without the `openid` scope
can't call `/userinfo`. Roles set on the account record are released as the
`roles` array claim on both tokens, independent of scopes.

A client's authorization code is bound to that client (RFC 6749 §4.1.3):
another client can't redeem it even with valid credentials — the attempt
burns the code as a theft signal, just as a client mismatch on a refresh
token revokes the whole token family.

## Machine-to-machine: the `client_credentials` grant

For service-to-service calls without an interactive user (RFC 6749 §4.4),
a confidential client can be opted in to the `client_credentials` grant:

- `grant_types` selects the grants the client may use at `/token`; the
  default (and the behaviour of every pre-existing entry) is
  `["authorization_code", "refresh_token"]`.
- `client_credentials` requires the confidential profile — the client
  authenticates with the same `client_secret_basic`/`client_secret_post`
  credentials as the interactive confidential flow. A public client or a
  client without the grant answers `400 unauthorized_client`.
- The issued token is an access token only: no `id_token` (there is no
  user session) and no `refresh_token` (RFC 6749 §4.4.3). The subject is
  the `client_id` itself — a service-account-like identity, as in other
  IdPs (Keycloak service accounts, Azure AD). No user-derived claims
  (`preferred_username`, `email`, `name`, `roles`) are released, and
  `/userinfo` is meaningless for such a token.
- The audience is the client's registered `audience` field, so a purely
  service client can mint tokens for a *different* API's audience (e.g.
  `audience: "fake-hr"`) than its own `client_id`.
- Scopes cannot be requested at token time — there is no login or consent
  step that could approve them. They come exclusively from the client's
  static `client_credentials_scopes` list, which is mandatory (non-empty)
  with the grant; a `scope` request parameter is ignored.
- `/revoke` (via the `jti` denylist) and `/introspect` work as for any
  other access token.

A purely service client needs neither `redirect_uris` nor `users`: only
clients with an interactive grant (`authorization_code` or
`refresh_token`) are required to have them. Combined with `audience`,
this makes the client a first-class API consumer in its own right:

```json
{
  "client_id": "fake-hr-mcp-service",
  "type": "confidential",
  "client_secret": "...",
  "audience": "fake-hr",
  "grant_types": ["client_credentials"],
  "client_credentials_scopes": ["fake-hr:read", "fake-hr:write"]
}
```

```sh
clientctl client add -file clients.json -client fake-hr-mcp-service \
  -type confidential -secret "$(openssl rand -base64 32)" \
  -audience fake-hr -grant-types client_credentials -cc-scopes fake-hr:read,fake-hr:write

curl -s -u fake-hr-mcp-service:SECRET -d grant_type=client_credentials \
  http://localhost:8080/token
```

Discovery advertises `client_credentials` in `grant_types_supported` when
at least one registered client is opted in, and the same metadata document
is additionally served at `/.well-known/oauth-authorization-server` (RFC
8414), the path OAuth-only (non-OIDC) libraries probe.

## The clients file

Set `IDP_CLIENTS_FILE` to a JSON file containing an array of clients. Each
client carries its own profile, redirect policy, audience and user
accounts. Passwords must be salted bcrypt hashes (the salt is embedded in
the bcrypt format) — the IdP refuses to start on a file with plaintext
passwords, duplicate usernames or malformed entries. Create and maintain
the file with the bundled tool:

```sh
# build the tool
go build -o clientctl ./cmd/clientctl

clientctl client list                                                 # overview (never prints secrets)
clientctl client show   -file clients.json -client demo-app           # one client + its users
clientctl client add    -file clients.json -client demo-app -type public \
     -redirect http://localhost:3000/callback,https://app.example.com/cb
clientctl client add    -file clients.json -client backend -type confidential \
     -secret "$(openssl rand -base64 32)" -redirect https://backend.example.com/cb \
     -post-logout https://backend.example.com/ -origin https://backend-spa.example.com
clientctl client update -file clients.json -client backend -audience my-api
clientctl client remove -file clients.json -client backend

clientctl user list    -file clients.json -client demo-app            # never prints hashes
clientctl user add     -file clients.json -client demo-app -username alice -email alice@example.com   # prompts for the password
clientctl user add     -file clients.json -client demo-app -username bob -password -                   # reads one line from stdin
clientctl user add     -file clients.json -client demo-app -username carol -roles admin,auditor       # comma-separated roles
clientctl user update  -file clients.json -client demo-app -username bob -password 'new-secret'        # rotate a password
clientctl user update  -file clients.json -client demo-app -username carol -roles admin                # replace the role set
clientctl user update  -file clients.json -client demo-app -username carol -roles ''                   # clear all roles
clientctl user remove  -file clients.json -client demo-app -username bob
clientctl hash         -password '...'                                 # print a hash for manual editing
```

**Without a Go toolchain**, run the `clientctl` bundled in the container
image via docker — same commands, executed against the clients file in the
current directory. The working directory is mounted at `/app` (the tool's
working directory, so the relative `-file` paths above work unchanged),
and the container runs as your own user so the rewritten file stays yours
(the tool rewrites the clients file atomically — temp file plus rename in
the same directory — which is why the directory is mounted, not the file):

```sh
docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD:/app" \
  --entrypoint clientctl ghcr.io/ghmer/minidp:latest \
  client add -file clients.json -client demo-app -type public \
  -redirect http://localhost:3000/callback
docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD:/app" \
  --entrypoint clientctl ghcr.io/ghmer/minidp:latest \
  user add   -file clients.json -client demo-app -username alice   # prompts for the password
```

File format (see `clients.json.example`):

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

### Field notes

- `client_id` must be unique and free of whitespace. `type` is `public` or
   `confidential`; a confidential entry requires `client_secret` (≥128
  random bits), a public entry must not have one. `audience` defaults to
  the `client_id`. Every `redirect_uri` must be an absolute http(s) URL
  without a fragment, compared by exact string match at `/authorize`.
- `grant_types` selects the OAuth grants the client may use at `/token`
  (default `["authorization_code", "refresh_token"]`; see
  [the client_credentials grant](#machine-to-machine-the-client_credentials-grant)).
  `client_credentials` requires the confidential profile and a non-empty
  `client_credentials_scopes` list; clients without an interactive grant
  need no `redirect_uris` and no `users`.
- `post_logout_redirect_uris` are the targets `/end_session` may redirect
  to for that client (resolved from the `id_token_hint`'s audience or the
   `client_id` parameter). An empty list means logout renders a confirmation
  page instead of redirecting.
- `allowed_origins` adds explicit CORS origins on top of the hosts derived
  from the redirect URIs.
- Each client's `users` are the only accounts that can sign in for that
  client — one client's users are invisible to another client's login
  form.
- The file is read once at startup; tool changes take effect on restart.
  Keep the file mode `0600` (the tool does — it holds client secrets and
  password hashes) and mount it read-only into the container. The tool may
  write transient states (a client without users yet); the IdP refuses to
  start with those and reports exactly which entry is incomplete.
- `sub`, `preferred_username` and the audit log use the username. `email`
  and `name` appear in the tokens when set in the file and the
  corresponding scope (`email` / `profile`) was granted. `roles`, when set,
  appear as the `roles` array on both the access and ID token regardless of
  granted scopes; users without roles get no `roles` claim.
- Usernames can't be probed: failed lookups burn the same bcrypt cost as a
  real hash comparison (timing equalisation, per client).
- The account backend is an interface (`idp.UserStore`); swapping the
  clients file for a database later only requires implementing `Lookup`,
   `Count` and `DummyHash`.
