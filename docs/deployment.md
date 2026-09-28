# Deployment

**Docker** — build the image and run it with the required files mounted:

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

The image also ships the `clientctl` clients-file manager, so the clients
file is maintained from the host with plain docker — no Go toolchain, and
nothing runs inside the deployed IdP container (details in
[docs/clients.md](clients.md); `minidp` here is the locally built image):

```sh
docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD:/app" \
  --entrypoint clientctl minidp client list
```

For a non-localhost deployment, override the public URL
(`IDP_ISSUER=https://idp.example.com`) and register the client's public
redirect URI in its clients-file entry.

**Kubernetes**: `deploy/k8s/minidp.yaml` ships a hardened Deployment
(non-root, read-only root filesystem, dropped capabilities, probes,
resource limits) plus a Service. Clients and accounts come from a
`minidp-clients` Secret mounted as the clients file. The signing key
persists to an `emptyDir` by default (a reschedule just means users log in
again) — follow the comments in the manifest to mount the key from a Secret
instead.

**TLS**: terminate at your usual edge (ingress, Traefik, Caddy). Point the
proxy at port 8080, set `IDP_ISSUER` to the public HTTPS URL, and declare
the proxy's network in `TRUSTED_PROXIES`.

## Operational limits

Worth knowing up front:

- **Single instance only.** Authorization codes, refresh tokens, replay
  history and revocation state are process-local (in-memory). Run exactly
  one replica behind `strategy: Recreate` — a restart invalidates refresh
  tokens and revocation state, and multiple replicas would diverge. This is
  a deliberate trade-off for a 10 MB container.
- **Logout is minimal, not full OIDC RP-Initiated Logout.** `/end_session`
  accepts an `id_token_hint` (verified for signature, issuer and audience —
  an expired hint still identifies the token family) and revokes that
  authorization's tokens. `post_logout_redirect_uri` must exactly match a
  post-logout target registered for the client resolved from the hint (or
  the `client_id` parameter). There's no browser session cookie to
  terminate without a hint; `logout_hint` and an independent `sid`
  parameter aren't handled, and `prompt=none` requests answer
   `login_required` since no browser session is ever kept.

## Key management & rotation

The signing key is identified by a stable `kid` published in the JWKS. A
key directory without a rotation history (`keyring.json`) keeps the classic
layout: one persisted key (`minidp-rsa.pem`) with the `kid` `minidp-1`.

For a staged, zero-downtime rotation:

1. Run `minidp rotate-keys` with `IDP_KEY_DIR` set. It marks the currently
   active key as *retiring* (still published in the JWKS, so tokens signed
   before the rotation verify until they expire), generates a fresh RSA-2048
   key with an RFC 7638 thumbprint `kid`, writes it as
   `minidp-rsa-<kid>.pem`, and persists the keyring document
   (`keyring.json`, mode 0600).
2. Restart minidp: it loads the new active key and publishes both keys in
   the JWKS. New tokens are minted by the new key; the retiring key remains
   published for verification.
3. The retiring key is removed at the next start after its retention
   horizon: `IDP_KEY_RETENTION` (seconds), defaulting to the sum of the
   configured access- and refresh-token TTLs plus a five-minute clock-skew
   margin — the maximum span over which a token signed by the retiring key
   can still be presented.

Verification is kid-driven: resource endpoints select the published key
matching a token's `kid` header and fail closed on unknown or missing kids.

The alternative to staged rotation stays available: point `IDP_RSA_PEM` at
a new key and restart minidp — all previously issued tokens become invalid
immediately and users log in again.

Keep key files and the keyring mode `0600` and never commit them — treat
them like the credentials they are.
