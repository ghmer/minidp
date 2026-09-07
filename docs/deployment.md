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

The signing key is identified by a stable `kid` (`minidp-1`) published in
the JWKS. To rotate:

1. Put a new RSA key next to the old one (a second file in the key volume,
   or a new Secret).
2. Point `IDP_RSA_PEM` at the new key and restart minidp. All previously
   issued tokens become invalid — users log in again; refresh tokens in
   flight are rejected and the SPA falls back to a fresh authorization
   request.
3. Zero-downtime dual-key JWKS (old + new key published simultaneously) is
   out of scope for a demo IdP.

Keep the key file mode `0600` and never commit it — treat it like the
credential it is.
