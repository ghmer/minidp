package idp

import (
	"embed"
	"html/template"
	"io"
)

// The static assets of the login page are embedded into the binary so the IdP
// is a single self-contained executable.
//
//go:embed web/login.html web/login.css web/logo.svg
var webFS embed.FS

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
	// Message, when set, replaces the form (e.g. "Signed in as rego").
	Message string
}

func newLoginTemplate(title, subtitle string) (*loginTemplate, error) {
	tmpl, err := template.ParseFS(webFS, "web/login.html")
	if err != nil {
		return nil, err
	}
	css, err := webFS.ReadFile("web/login.css")
	if err != nil {
		return nil, err
	}
	logo, err := webFS.ReadFile("web/logo.svg")
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
