# Login page branding

The login page ships with the embedded "Deep Water" theme (light/dark,
following OS `prefers-color-scheme`) and an embedded logo. Both can be
replaced without rebuilding: at startup minidp checks the fixed directory
`assets/` relative to its working directory and overrides per file.

| File               | Overrides                     |
| ------------------ | ----------------------------- |
| `assets/login.css` | the `/login.css` stylesheet   |
| `assets/logo.svg`  | the `/logo.svg` logo, favicon |

- A missing file keeps the embedded default, so mounting only a logo is
  enough.
- Files are read once at startup (2 MiB limit each) and cached in memory —
  changes take effect on restart.
- The location is a compiled-in constant; there's no environment variable
  for paths. In the container the working directory is `/app`, so the mount
  point is `/app/assets` (Docker: `-v ./assets:/app/assets:ro`; Kubernetes:
  mount a ConfigMap there, see `deploy/k8s/minidp.yaml`).
- Page title and subtitle come from `IDP_TITLE` / `IDP_SUBTITLE`.

An override that exists but can't be read (e.g. wrong permissions) aborts
startup, rather than silently falling back to the default.
