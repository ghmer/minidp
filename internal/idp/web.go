package idp

import (
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"os"
)

// The static assets of the login page are embedded into the binary so the IdP
// is a single self-contained executable.
//
//go:embed web/login.html web/login.css web/logo.svg
var webFS embed.FS

// assetDir is the fixed location — relative to the process working directory —
// where operators can place files that override the embedded login page
// assets. It is a compiled-in constant, not an environment variable: there is
// no configuration surface for file paths, and mounting is the operator's one
// and only job (Docker volume, Kubernetes volume at <workdir>/assets, or a
// plain directory when running the binary directly).
const assetDir = "assets"

// assetOverrideLimit caps the size of an operator-provided asset override so
// an accidentally mounted huge file cannot exhaust memory at startup.
const assetOverrideLimit = 2 << 20 // 2 MiB

// loadAsset returns the operator-provided override for an embedded login page
// asset, or the embedded default when no override exists. Each present file in
// assetDir replaces exactly its own embedded default; everything else keeps
// the shipped version. Semantics are strict about operator intent: a missing
// asset directory or file silently falls back to the embedded default, but an
// override that exists and cannot be read (e.g. permission denied) fails the
// startup — a mount the operator meant to take effect must never degrade into
// silence.
func loadAsset(name, embedded string) ([]byte, error) {
	data, err := readAssetOverride(name)
	if err != nil {
		return nil, err
	}
	if data != nil {
		return data, nil
	}
	return webFS.ReadFile(embedded)
}

// readAssetOverride reads a single override file from assetDir through os.Root
// so the lookup is confined to that directory. It returns (nil, nil) when
// there is nothing to override.
func readAssetOverride(name string) ([]byte, error) {
	root, err := os.OpenRoot(assetDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %s: %w", assetDir, err)
	}
	defer root.Close() //nolint:errcheck // read-only handle; close error is not actionable
	data, err := root.ReadFile(name)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read asset override %s/%s: %w", assetDir, name, err)
	}
	if len(data) > assetOverrideLimit {
		return nil, fmt.Errorf("asset override %s/%s is %d bytes, the limit is %d", assetDir, name, len(data), assetOverrideLimit)
	}
	slog.Info("using login page asset override", "path", assetDir+"/"+name, "bytes", len(data))
	return data, nil
}

// loginTemplate wraps the parsed login page template together with its static
// assets.
type loginTemplate struct {
	tmpl     *template.Template
	css      []byte
	logo     []byte
	title    string
	subtitle string
}

// loginField is one hidden <input> that carries an OAuth2 parameter from the
// authorization request through the login form round-trip.
type loginField struct {
	Name  string
	Value string
}

// loginData is everything the login page template needs.
type loginData struct {
	Title    string
	Subtitle string
	// Action is the form's POST target ("/authorize" or "/login").
	Action string
	// Error is shown when a previous login attempt failed.
	Error string
	// Username is pre-filled after a failed attempt (never the password).
	Username string
	// Hidden carries the OAuth2 parameters echoed back into the form.
	Hidden []loginField
	// CSRFToken is the signed form token; rendered as a hidden input.
	CSRFToken string
	// Message, when set, replaces the form (e.g. "Signed in as alice").
	Message string
}

func newLoginTemplate(title, subtitle string) (*loginTemplate, error) {
	tmpl, err := template.ParseFS(webFS, "web/login.html")
	if err != nil {
		return nil, err
	}
	css, err := loadAsset("login.css", "web/login.css")
	if err != nil {
		return nil, err
	}
	logo, err := loadAsset("logo.svg", "web/logo.svg")
	if err != nil {
		return nil, err
	}
	return &loginTemplate{
		tmpl:     tmpl,
		css:      css,
		logo:     logo,
		title:    title,
		subtitle: subtitle,
	}, nil
}

// render writes the login page. Empty Title/Subtitle in data fall back to the
// configured defaults.
func (lt *loginTemplate) render(w io.Writer, data loginData) error {
	if data.Title == "" {
		data.Title = lt.title
	}
	if data.Subtitle == "" {
		data.Subtitle = lt.subtitle
	}
	return lt.tmpl.Execute(w, data)
}
