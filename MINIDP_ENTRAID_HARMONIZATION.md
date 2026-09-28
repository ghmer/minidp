# MinIDP to Entra ID Harmonization

## Audience and scope

This document is for the MinIDP and application implementation teams. MinIDP is our project and can be changed to meet the local integration-test contract defined here. The target is Microsoft Entra ID, single tenant, using OIDC and OAuth 2.0. The applications in scope are `policy-service`, `agent-directory`, `sequelizer-shop`, and `fake-hr`. `fake-hr-mcp` is excluded.

The objective is workflow parity, not a claim that a local provider can reproduce every Entra feature. A successful MinIDP test must mean that our protocol usage, claims, roles, audiences, callbacks, and negative authorization cases are compatible with Entra. Tenant policy, MFA, Conditional Access, consent administration and Microsoft-specific operations still require a real Entra test tenant.

## Current MinIDP behavior in this workspace

The demo Compose files run `ghcr.io/ghmer/minidp:v0.3.0` and mount `clients.json` or `clients.ssl.json`. I checked out upstream tag `v0.3.0` at commit `b45d00e` and reviewed its source, docs, and tests. MinIDP is already a generic, multi-client OIDC/OAuth2 provider for its supported feature set; replacing it with another local provider is not required.

Upstream already implements OIDC discovery and RFC 8414 metadata, RS256-signed ID and RFC 9068 `at+jwt` access tokens, JWKS with `kid`, configurable issuer, authorization code, exact redirect allowlists, CSRF-protected login forms, state round-trip, nonce in ID tokens, PKCE S256, confidential-client secret authentication, single-use codes, refresh-token rotation, client credentials, userinfo, introspection, revocation and end-session. It also has persistent signing-key storage and configurable access-token lifetime.

The important remaining compatibility gaps are narrower: custom API delegated scopes/resources are not supported (`openid`, `profile`, and `email` are the only authorization scopes); an interactive client's configured `audience` is used for both access and ID tokens; app-only tokens intentionally contain no roles; client-credentials scopes are static per client and requested scopes are ignored; user roles are attached per client rather than modeled as Entra resource-role assignments; signing-key persistence exists but key rotation does not. The checked-in demo config also bypasses discovery by hard-coding endpoint paths and still requests only `openid`.

| Capability | Upstream `v0.3.0` status | Harmonization action |
| --- | --- | --- |
| Discovery and standard endpoint metadata | Implemented; discovery includes authorization, token, JWKS, userinfo, revocation, introspection and end-session endpoints. | Keep it; make applications discover endpoints instead of hard-coding paths. |
| RS256 JWTs and JWKS `kid` | Implemented; access tokens use `typ: at+jwt`; JWKS publishes the signing key. | Keep it; add key rotation with overlapping published keys. |
| Stable issuer and audience validation support | Configurable issuer and per-client audience are implemented. | Keep it; configure one issuer reachable from browser and containers, and separate ID-token audience from API access-token audience. |
| Authorization code, state, nonce, exact callbacks, confidential authentication and PKCE S256 | Implemented. PKCE is mandatory for public clients and optional but verified when confidential clients send it. MinIDP echoes OAuth `state`; the client must validate it. | Keep it; retain app-side state/nonce/PKCE validation and tests. |
| Separate ID/access tokens and client credentials | Both token types exist; client credentials is supported for confidential clients and produces no ID or refresh token. | Fix ID-token audience for resource clients; add app-role claims to client-credentials tokens. |
| Standard OIDC scopes | `openid`, `profile`, `email` only; unknown scopes are rejected. | Add registered, resource-specific delegated API scopes and Entra-compatible `scp` output. |
| Role claims | User roles from the client's account record appear on both interactive tokens, independent of scopes. App-only tokens have no `roles`. | Preserve user-role fixtures; add explicit per-resource application-role assignments for machine clients. |
| Key persistence/rotation | Persistent RSA key option exists; one active key and fixed `kid` are published. Replacing the key is not overlap rotation. | Implement explicit staged rotation and test JWKS rollover. |

Evidence is in upstream `README.md`, `docs/clients.md`, `docs/security.md`, `internal/idp/discovery.go`, `internal/idp/tokens.go`, `internal/idp/clients.go`, `internal/idp/handlers.go`, and the corresponding `*_test.go` files.

## Target use cases

MinIDP must support all workflows that the applications currently expose:

| Use case | Service behavior to preserve |
| --- | --- |
| Interactive browser login | Users authenticate at the provider, return to the exact app callback, and establish a secure app session. Login uses authorization code with S256 PKCE. |
| `policy-service` API | Client-credentials caller receives a token for this API with an assigned app role. Reads accept `admin`, `integration`, or `user`; provisioning writes accept `admin`/`integration`; administrative operations accept `admin`. |
| `agent-directory` SCIM API | Client-credentials caller receives a token for this API with a role. Preserve read, provisioning, membership, and catalog-admin role distinctions. Interactive UI users also need the appropriate assigned role. |
| `sequelizer-shop` UI | Authorization-code login validates an ID token; UI mutation requires the configured admin role. This service currently has no separate business API to exercise. |
| `fake-hr` UI/API | Preserve authenticated UI and API use. Today it does not enforce roles, so a valid token for this resource is sufficient; do not accidentally imply that an unassigned role is enforced. |

Role values are exact and case-sensitive: `admin`, `integration`, `user`. For `fake-hr`, MinIDP should still be able to issue role claims for claim-shape/conformance tests, but current application policy does not depend on them.

## Remaining gaps and MinIDP requirements

### 1. Discovery and issuer

**Entra:** publishes tenant-specific OIDC metadata and JWKS metadata; the issuer claim and discovery `issuer` are tenant-specific and must match exactly. Entra signing keys rotate and are selected by `kid`.

**Already implemented:** standard OIDC discovery, OAuth authorization-server metadata, JWKS with RSA `kid`, configurable `IDP_ISSUER`, and `/healthz` are present. Persistent key storage is available through `IDP_KEY_DIR` or `IDP_RSA_PEM`.

**Remaining MinIDP work:**

- Add signing-key rotation: publish old and new keys concurrently during a transition, identify each with a distinct `kid`, switch the active signing key, then retire old keys after the maximum token lifetime plus clock skew. Preserve the current persistent-key behavior when rotation is not configured.
- Add a readiness check (or Compose health check against discovery plus JWKS) for the actual endpoints applications consume. `/healthz` currently establishes liveness, not that discovery/JWKS can be retrieved through the public issuer hostname.
- Keep the configured issuer byte-for-byte identical in discovery and `iss`; use an issuer hostname resolvable from both browser and app containers. This is primarily Compose/network configuration, not a new protocol feature.

### 2. Resource scopes and audiences

**Entra:** each API is a distinct resource. A UI requests a delegated scope for that API; a technical client requests `api://<resource>/.default`. Access tokens are issued for a resource and their `aud` is not the UI client's display name. The UI's ID token has the UI client as its audience.

MinIDP already supports a per-client access-token `audience`, defaulting to `client_id`; a machine client can target another API by configuring its audience. It does not perform resource selection from a requested scope. Its authorization endpoint accepts only the three built-in scopes and rejects custom API scopes.

**Remaining MinIDP work:**

- Allow each interactive client to register a delegated API scope for its target API (for example `api://<api-id>/access_as_user`) in addition to OIDC scopes. Validate requested scopes against that client's allowlist; do not accept arbitrary resource/scope strings. Emit the granted delegated permission in the Entra-compatible access-token `scp` claim. Preserve `scope` response compatibility if existing clients depend on it.
- Correct audience separation: ID-token `aud` must identify the OIDC client (`client_id`); API access-token `aud` must use that client's configured API audience. Currently `issueTokens` supplies the configured client audience to both token types. If an app registration intentionally acts as both client and API, the values may coincide, but tests must cover the distinct-client/resource case.
- For client credentials, validate `scope=<configured-resource>/.default` against the registered client's configured audience/permissions. Continue granting permissions from server-side registration, never from an untrusted requested scope. The current static `client_credentials_scopes` mechanism is useful groundwork but does not model `.default` resource permission resolution.
- Keep the API audience explicit in the clients file; do not depend on the default audience equaling a display name or client ID by accident.

### 3. Tokens and claims

**Entra:** OIDC login returns an ID token for the client and an access token for the requested API. Claims depend on grant type and assignment. Application permissions appear as `roles`; delegated scopes appear as `scp`; app roles assigned to users/groups may also appear as `roles`. Entra access-token version and exact audience representation depend on API registration settings.

**Already implemented:** token responses contain access token, ID token for `openid`, token type, expiry and scope; MinIDP signs both tokens with `iss`, `aud`, `iat`, and `exp`; the authorization nonce is included in the ID token; access tokens have the `at+jwt` type; access-token TTL is configurable. User account roles are emitted as `roles` on both interactive tokens when configured.

**Remaining MinIDP work:**

- Ensure ID-token audience is the client ID and access-token audience is the API audience when those differ.
- Add `scp` to delegated API access tokens for custom registered API scopes. Keep app-only tokens free of `scp`.
- Add assigned application roles to client-credentials access tokens; currently they deliberately carry no user-derived or role claims.
- Keep fake-hr's current authenticated-only policy as an application policy. MinIDP need not invent roles or relax token validation to support it.
- Add clock control or short TTL configuration to tests as needed. Configurable TTL already exists; deterministic time is a test-harness enhancement, not a prerequisite for basic compatibility.

### 4. App roles and assignments

**Entra:** app roles belong to an API resource. Application-role assignment is granted to a client service principal and normally requires admin consent. User/group role assignment is distinct. A delegated scope is not a substitute for an app role.

MinIDP already supports a per-client user list and per-user `roles` values. This can represent the existing local interactive roles (`admin`, `integration`, `user`) and isolates accounts between client registrations. It does not have central role definitions, groups, or user/group assignment administration; those Entra governance features are outside the compatibility requirement unless the applications begin consuming them.

**Remaining MinIDP work:**

- Add an explicit `client_credentials_roles` (or equivalent role-assignment structure) to confidential service clients and emit those values as the access token's top-level `roles` claim. Keep role assignment per target API/audience and reject roles not configured for that API.
- Configure app-only role assignments for the client-credentials test callers used by `policy-service` and `agent-directory`. This is the important missing role path: current MinIDP client-credentials tokens intentionally omit roles, while both APIs require them.
- Keep user-role assignments per interactive client for the current UI tests. Add a separate shared-user/group model only if cross-application group assignment behavior is itself under test; Entra group membership claims are not required for current application code.
- Make a missing role a testable case. `policy-service` and `agent-directory` should continue to reject it; `sequelizer-shop` should continue to deny admin-only mutations; `fake-hr` currently requires authentication but does not enforce roles.

### 5. Authorization Code, PKCE and OIDC security

**Entra:** requires a registered redirect URI and supports authorization code with PKCE for confidential web clients. State binds the browser flow; nonce binds the ID token to the request. Authorization codes are single-use and short-lived.

MinIDP already enforces exact registered redirect URIs, single-use short-lived authorization codes, S256 PKCE (mandatory for public clients and verified whenever supplied), confidential client authentication using Basic or form credentials, and standard authorization-code token exchange. It carries `state` through the authorization flow and echoes `nonce` into the ID token. It also provides `/end_session` with per-client post-logout redirect allowlists and optional token revocation using `id_token_hint`.

**No corresponding MinIDP protocol implementation is required.** Keep upstream tests for these guarantees and add a provider/app integration test proving the applications validate state and nonce, send PKCE for confidential clients, and handle logout as intended. MinIDP's own state echo is not state validation: the relying application must bind and verify it.

Applications must implement the same validation regardless of provider: callback validates the ID token (issuer, signature, client audience, expiry and nonce); API calls validate the access token (issuer, signature, API audience and lifetime); session cookies contain no raw provider tokens.

### 6. Client Credentials and consent

**Entra:** a client obtains an app-only token for a resource using `scope=<resource>/.default`. Roles are assigned to the client service principal; admin consent may be required.

MinIDP already implements the client-credentials grant for opted-in confidential clients, supports `client_secret_basic` and `client_secret_post`, allows a client to be configured with a distinct audience, and issues an access token without an ID or refresh token. Its scopes are configured statically per client; the request-time `scope` is ignored. A client with no configured app roles receives no `roles` claim.

**Remaining MinIDP work:**

- Resolve a standard `/.default` request to the client registration's configured API audience and assigned application roles. Reject a request for an unconfigured API rather than silently issuing a token.
- Add configured app-role assignments to app-only tokens. Do not emit delegated `scp` for this grant.
- Keep assignment/pre-consent state explicit and deterministic in the clients fixture. This is a local test fixture for Entra outcomes, not a simulation of Entra's admin-consent UX.
- Certificate-based client authentication is not currently supported. It is not required to exercise the applications' current client-secret configuration; add it only if the production Entra deployment chooses certificate authentication and needs local flow-level coverage.

### 7. Browser, Docker and TLS topology

MinIDP and app URLs in Compose must use the same issuer identifier the browser sees and the token contains. The browser must resolve the issuer and app callback URLs; app containers must resolve the issuer to fetch discovery/JWKS and exchange codes. Where an ingress/reverse proxy terminates TLS, forward the original scheme/host safely and use externally registered callback URLs.

For Entra, application containers use public HTTPS endpoints and the default public root trust. Do not carry the local step-ca root-only `SSL_CERT_FILE` setting into an Entra profile. For the local provider, either use HTTP only in an explicitly local-only profile or use a local CA bundle installed as trust roots; never disable certificate verification.

Keep the existing `minidp` Compose service; no replacement `oidc-provider` image/service is needed. The applications should consume the provider-neutral OIDC contract in both the local and Entra profiles. `depends_on: minidp` belongs only in the local profile; the Entra profile must not start or require MinIDP. Keep client secrets and session secrets outside tracked Compose YAML.

## Proposed MinIDP configuration model

Extend the existing clients-file model rather than introducing an unrelated tenant configuration format. Today each client has its own audience, redirect policy, user accounts, and user roles; a client-credentials-only client can have a static audience and static scope list without users or redirects. Preserve that model where it already fits. The smallest likely additions are:

```yaml
[
  {
    "client_id": "policy-service",
    "type": "confidential",
    "client_secret": "<local-test-secret>",
    "audience": "<policy-service-api-audience>",
    "redirect_uris": ["https://policy-service.iam.test/callback"],
    "allowed_scopes": ["openid", "profile", "api://<policy-service-id>/access_as_user"],
    "users": [
      {"username": "admin", "password_hash": "<bcrypt>", "roles": ["admin"]},
      {"username": "integration", "password_hash": "<bcrypt>", "roles": ["integration"]},
      {"username": "user", "password_hash": "<bcrypt>", "roles": ["user"]}
    ]
  },
  {
    "client_id": "iam-connector-policy",
    "type": "confidential",
    "client_secret": "<local-test-secret>",
    "audience": "<policy-service-api-audience>",
    "grant_types": ["client_credentials"],
    "client_credentials_scopes": ["api://<policy-service-id>/.default"],
    "client_credentials_roles": ["integration"]
  }
]
```

Field names for `allowed_scopes`, `client_credentials_roles`, and an optional ID-token audience are proposed additions, not current MinIDP fields. The schema should validate that the requested delegated scope is allowed for the client and its API audience, that application roles are valid for that audience, and that `/.default` resolves only to preconfigured permissions. Consider `id_token_audience` only if the client ID cannot be used directly; the default must be `client_id`. Keep fixtures reviewable and local secrets/private keys out of committed or production configuration.

## Compose migration requirements

Update the OAuth Compose files so they:

1. Keep the existing MinIDP service and configure applications from its discovery issuer; stop configuring applications directly against `/authorize`, `/token`, and `/jwks` paths.
2. Declare each API's resource audience and delegated UI scope explicitly. UI scope includes `openid profile` and that API's delegated scope; client credentials use that API's `/.default` scope.
3. Give each service a distinct UI client ID, callback, client credential, audience and session secret. Test callers use separate client IDs and explicit app-role assignments.
4. Use browser-reachable issuer and callback URLs with exact registered redirect URIs; ensure the issuer hostname also resolves inside containers.
5. Keep Entra endpoint, tenant issuer and client values in an Entra-specific env file or overlay, with secrets injected by the runtime. Remove local-provider dependencies from that overlay.
6. Remove committed demo secrets and local test passwords from live-like files; rotate exposed test credentials as appropriate. Mark all local credentials as non-production.
7. Remove `SSL_CERT_FILE` local-root overrides from Entra services. For local TLS tests, use a trust bundle that contains the local CA without overriding public roots away.

## Acceptance tests for the local provider

Upstream already has unit and HTTP flow tests for discovery, client profiles, redirect policy, PKCE, nonce, refresh rotation, client credentials, JWKS and token claims. Keep those tests; do not duplicate them as new MinIDP requirements. Add focused tests for the actual gaps:

- Custom per-client delegated API scopes are allowlisted, the requested API resource is enforced, and the access token contains the expected Entra-compatible `scp` value.
- ID-token `aud` is `client_id` while API access-token `aud` is the configured API audience; wrong-client/resource combinations are rejected.
- `/.default` resolves only to configured application permissions; client-credentials tokens carry assigned `roles`, have the API audience, and omit `scp`, ID token and refresh token.
- User roles remain scoped to the relevant interactive client/resource; no role assignment means no role claim. Client application roles are separate from user roles.
- Key rotation publishes overlapping keys with unique `kid` values and old tokens remain verifiable until expiry; retired keys are eventually removed.
- Discovery and JWKS are reachable at the exact configured issuer from both browser-facing ingress and application containers.
- At the application boundary, wrong issuer/audience, expired/not-yet-valid token, bad signature, ID token presented as bearer token, missing required role, malformed role claim, and unknown `kid` fail closed. These are primarily app verifier tests, not MinIDP issuance tests.
- The current service route matrices remain unchanged: `policy-service` and `agent-directory` role checks, `sequelizer-shop` admin mutation, and `fake-hr` authenticated-only behavior.
- Run the same end-to-end application workflows against a non-production Entra tenant. MinIDP parity does not prove tenant consent or policy configuration.

## Explicit limitations

MinIDP can and should emulate the protocol and authorization contracts our applications rely on. It cannot establish compatibility with Entra Conditional Access, MFA, device claims, consent UX, tenant lifecycle, Entra-specific role assignment administration, production key behavior in every edge case, or conditional access errors. Those remain mandatory checks against a non-production Entra tenant. A local pass is necessary, not sufficient, evidence of Entra readiness.

## Implementation status (2026-09-28)

Implemented on branch `feature/entra-harmonization`, in RFC-first order per
the approved sprint plan. Every sprint shipped a clean binary, extended
tests, and went through the full gate set (`go test`, `go vet`,
`golangci-lint`, `gosec`) before its commit.

| Sprint | Scope | Commit |
| --- | --- | --- |
| 1 (RFC) | Audience split: id_token `aud` = `client_id`, access token `aud` = configured API audience; RFC 9068 REQUIRED `client_id` claim on access tokens; `/userinfo` resolves the account store via `client_id`; `/end_session` resolves hints by client-id audience; `/introspect` carries `client_id` (RFC 7662) | `0a1d517` |
| 2 (RFC) | Per-client delegated API scopes (`allowed_scopes`, `api://<audience>/<name>` referencing the client's own audience), allowlist validation at `/authorize`, discovery `scopes_supported` union, `clientctl -allowed-scopes` | `f56a7bd` |
| 3 (RFC) | Staged signing-key rotation: `keyring.json`, RFC 7638 thumbprint kids, overlapping JWKS during the transition, retention pruning at start, `minidp rotate-keys` (`IDP_KEY_RETENTION`) | `7a427a2` |
| 4 (RFC) | `/readyz` readiness probe (discovery renders + signing key published); compose healthcheck pattern probes discovery + JWKS | `76dcc40` |
| 5 (Entra) | `nbf` on every token, `azp` on both tokens, `scp` with short permission names on delegated access tokens (no `scp` on app-only tokens) | `c1ef39c` |
| 6 (Entra) | CC `/.default` resolution (absent/`<audience>/.default`/exact entry; else `invalid_scope`), `client_credentials_roles` in the `roles` claim, `idtyp` (`app`/`user`), optional per-audience role registry via the object-form clients file | `2139d08` |
| 7 | Smoke-test extensions (claim shape, `.default`, rotation overlap), example clients file, this status section | this commit |

Not covered here by design — they live in the application repositories:
the Compose migration (§ "Compose migration requirements"), the
app-verifier hardening (typ-header tolerance for Entra's `typ: JWT` access
tokens vs. MinIDP's RFC 9068 `at+jwt`), and the non-production Entra
tenant runs (§ "Acceptance tests", last bullet).
