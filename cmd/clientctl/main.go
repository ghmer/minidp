// Command clientctl manages the minidp clients file: the registered OAuth
// clients (profile, redirect policy, audience) and, per client, its user
// accounts. Passwords are never stored in plaintext: the tool writes salted
// bcrypt hashes (the salt is part of the bcrypt format), and the IdP refuses
// to start on a file that contains anything else. Client secrets are stored
// for confidential clients; list and show never print them.
//
// Usage:
//
//	clientctl client list                                          [-file clients.json]
//	clientctl client show    -client app                           [-file clients.json]
//	clientctl client add     -client app -type public|confidential [-file clients.json]
//	                         [-secret ...|-] [-audience ...] [-grant-types ...]
//	                         [-cc-scopes ...] [-redirect uri[,uri...]]
//	                         [-post-logout uri,...] [-origin uri,...]
//	clientctl client update  -client app                           [-file clients.json]
//	                         [-type ...] [-secret ...|-] [-audience ...]
//	                         [-grant-types ...] [-cc-scopes ...] [-redirect ...]
//	                         [-post-logout ...] [-origin ...]
//	clientctl client remove  -client app                           [-file clients.json]
//	clientctl user list      -client app                           [-file clients.json]
//	clientctl user add       -client app -username alice           [-file clients.json]
//	                         [-email ...] [-name ...] [-roles a,b] [-password ...|-] [-cost 10]
//	clientctl user update    -client app -username alice           [-file clients.json]
//	                         [-email ...] [-name ...] [-roles a,b] [-password ...|-] [-cost 10]
//	clientctl user remove    -client app -username alice           [-file clients.json]
//	clientctl hash           [-password ...|-] [-cost 10]
//
// A password or secret is supplied either via its flag (visible in the
// process list — prefer the interactive prompt or "-" to read one line from
// stdin) or by typing it when prompted. list and show never print secrets or
// password hashes.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/ghmer/minidp/internal/idp"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "client":
		err = clientCmd(os.Args[2:])
	case "user":
		err = userCmd(os.Args[2:])
	case "hash":
		err = hash(os.Args[2:])
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `clientctl — manage the minidp clients file (registered clients and their users)

Usage:
  clientctl client list                                          [-file clients.json]
  clientctl client show    -client app                           [-file clients.json]
  clientctl client add     -client app -type public|confidential [-file clients.json]
                           [-secret ...|-] [-audience ...] [-grant-types ...]
                           [-cc-scopes ...] [-redirect uri[,uri...]]
                           [-post-logout uri,...] [-origin uri,...]
  clientctl client update  -client app                           [-file clients.json]
                           [-type ...] [-secret ...|-] [-audience ...]
                           [-grant-types ...] [-cc-scopes ...] [-redirect ...]
                           [-post-logout ...] [-origin ...]
  clientctl client remove  -client app                           [-file clients.json]
  clientctl user list      -client app                           [-file clients.json]
  clientctl user add       -client app -username alice           [-file clients.json]
                           [-email ...] [-name ...] [-roles a,b] [-password ...|-] [-cost 10]
  clientctl user update    -client app -username alice           [-file clients.json]
                           [-email ...] [-name ...] [-roles a,b] [-password ...|-] [-cost 10]
  clientctl user remove    -client app -username alice           [-file clients.json]
  clientctl hash           [-password ...|-] [-cost 10]

Passwords are stored as salted bcrypt hashes; secrets and hashes are never
printed. "-password -"/"-secret -" read one line from stdin; without the flag
an interactive prompt (with confirmation) is used where applicable. -roles
takes a comma-separated list; updating with "-roles ''" clears all roles.
Redirect URIs, post-logout URIs and origins are comma-separated lists that
replace the previous set when provided. -grant-types and -cc-scopes are
comma-separated lists too: -grant-types picks the OAuth grants the client may
use (default: authorization_code,refresh_token); a client_credentials-only
client needs no redirect URIs and no users, but -cc-scopes (its statically
configured token scopes) and -secret (confidential profile) are required.
`)
}

func clientCmd(args []string) error {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		return clientAdd(args[1:])
	case "update":
		return clientUpdate(args[1:])
	case "remove":
		return clientRemove(args[1:])
	case "list":
		return clientList(args[1:])
	case "show":
		return clientShow(args[1:])
	default:
		return fmt.Errorf("unknown client command %q (want add, update, remove, list or show)", args[0])
	}
}

func userCmd(args []string) error {
	if len(args) < 1 {
		usage()
		os.Exit(2)
	}
	switch args[0] {
	case "add":
		return userAdd(args[1:])
	case "update":
		return userUpdate(args[1:])
	case "remove":
		return userRemove(args[1:])
	case "list":
		return userList(args[1:])
	default:
		return fmt.Errorf("unknown user command %q (want add, update, remove or list)", args[0])
	}
}

// resolveSecret returns the secret from the flag, from stdin ("-" or a piped
// non-terminal stdin), or from an interactive prompt. Shared by passwords
// and client secrets.
func resolveSecret(flagValue, what string, confirm bool) (string, error) {
	switch {
	case flagValue == "-":
		return readLineFromStdin()
	case flagValue != "":
		return flagValue, nil
	case !term.IsTerminal(int(os.Stdin.Fd())):
		return "", fmt.Errorf("no %s: use the flag (or '-<flag> -' with piped stdin)", what)
	}
	return promptSecret(what, confirm)
}

// readLineFromStdin reads the first line of stdin.
func readLineFromStdin() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("read from stdin: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// promptSecret reads a secret interactively, optionally asking for a
// confirmation.
func promptSecret(what string, confirm bool) (string, error) {
	pw, err := readSecretPrompt(what + ": ")
	if err != nil {
		return "", err
	}
	if len(pw) == 0 {
		return "", fmt.Errorf("%s must not be empty", what)
	}
	if confirm {
		again, err := readSecretPrompt("Confirm " + what + ": ")
		if err != nil {
			return "", err
		}
		if string(pw) != string(again) {
			return "", fmt.Errorf("%ss do not match", what)
		}
	}
	return string(pw), nil
}

// readSecretPrompt prompts on stderr and reads one value invisibly.
func readSecretPrompt(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return pw, nil
}

// parseList splits a comma-separated flag value into clean entries:
// whitespace around entries is trimmed and empty entries are dropped, so the
// result always satisfies the clients-file validation.
func parseList(value string) []string {
	var out []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

// parseRoles splits a comma-separated -roles value into clean entries.
func parseRoles(value string) []string { return parseList(value) }

// loadClients reads the clients file, treating a missing file as empty (so
// `client add` can create it).
func loadClients(path string) ([]idp.Client, bool, error) {
	clients, err := idp.ReadClients(path)
	switch {
	case err == nil:
		return clients, true, nil
	case errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	default:
		return nil, false, err
	}
}

// loadExistingClients reads the clients file for commands that mutate an
// existing entry: a missing file is an error, unlike `client add`.
func loadExistingClients(path string) ([]idp.Client, error) {
	clients, ok, err := loadClients(path)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("clients file %q does not exist yet", path)
	}
	return clients, nil
}

// findClient returns the index of the client with the given id, or -1.
func findClient(clients []idp.Client, id string) int {
	for i, c := range clients {
		if c.ClientID == id {
			return i
		}
	}
	return -1
}

// clientSelector bundles the flags shared by every subcommand: the clients
// file and the client to operate on.
type clientSelector struct {
	file   *string
	client *string
}

func registerClientSelector(fs *flag.FlagSet) *clientSelector {
	sel := &clientSelector{}
	sel.file = fs.String("file", "clients.json", "path to the clients JSON file")
	sel.client = fs.String("client", "", "client_id of the client to operate on (required)")
	return sel
}

// requireSelector validates the shared -client flag.
func requireSelector(sel *clientSelector) error {
	if *sel.client == "" {
		return fmt.Errorf("-client is required")
	}
	return nil
}

// clientFlags bundles the flags shared by client add and update.
type clientFlags struct {
	selector   *clientSelector
	typ        *string
	secret     *string
	audience   *string
	grantTypes *string
	ccScopes   *string
	redirect   *string
	postLogout *string
	origin     *string
}

func registerClientFlags(fs *flag.FlagSet) *clientFlags {
	f := &clientFlags{}
	f.selector = registerClientSelector(fs)
	f.typ = fs.String("type", "", "client profile: public (mandatory PKCE) or confidential (client auth at /token)")
	f.secret = fs.String("secret", "", "client secret for a confidential client; '-' reads one line from stdin")
	f.audience = fs.String("audience", "", "token audience; defaults to the client_id")
	f.grantTypes = fs.String("grant-types", "", "comma-separated OAuth grants: authorization_code, refresh_token, client_credentials (default: authorization_code,refresh_token)")
	f.ccScopes = fs.String("cc-scopes", "", "comma-separated scopes of the client_credentials access tokens (required with -grant-types client_credentials)")
	f.redirect = fs.String("redirect", "", "comma-separated registered redirect_uri values (required unless client_credentials is the only grant)")
	f.postLogout = fs.String("post-logout", "", "comma-separated post_logout_redirect_uri values for /end_session")
	f.origin = fs.String("origin", "", "comma-separated extra CORS origins granted to this client")
	return f
}

// clientChangeSpec records which of the update flags were explicitly set, so
// "absent" (keep the existing value) is distinguishable from "provided".
type clientChangeSpec struct {
	f      *clientFlags
	provid map[string]bool
}

// parseClientChangeArgs parses client update flags and records which were
// explicitly provided.
func parseClientChangeArgs(args []string) (*clientChangeSpec, error) {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	spec := &clientChangeSpec{f: registerClientFlags(fs), provid: map[string]bool{}}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if err := requireSelector(spec.f.selector); err != nil {
		return nil, err
	}
	fs.Visit(func(f *flag.Flag) { spec.provid[f.Name] = true })
	return spec, nil
}

// resolveNewSecret resolves the secret for add/update: interactive prompt
// with confirmation when the flag is absent and the type needs one.
func resolveNewSecret(flagValue string) (string, error) {
	return resolveSecret(flagValue, "client secret", true)
}

func clientAdd(args []string) error {
	fs := flag.NewFlagSet("client add", flag.ExitOnError)
	f := registerClientFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireSelector(f.selector); err != nil {
		return err
	}
	if *f.typ != string(idp.TypePublic) && *f.typ != string(idp.TypeConfidential) {
		return fmt.Errorf("-type is required and must be %q or %q", idp.TypePublic, idp.TypeConfidential)
	}
	// A redirect policy is only required for clients with an interactive
	// grant: a purely machine-to-machine client (client_credentials only)
	// never sends the browser anywhere.
	effectiveGrants := effectiveGrantTypes(*f.grantTypes)
	interactive := false
	for _, g := range effectiveGrants {
		if g == idp.GrantAuthorizationCode {
			interactive = true
		}
	}
	if *f.redirect == "" && interactive {
		return fmt.Errorf("-redirect is required: declare the registered redirect_uri values")
	}
	clients, _, err := loadClients(*f.selector.file)
	if err != nil {
		return err
	}
	if findClient(clients, *f.selector.client) >= 0 {
		return fmt.Errorf("client %q already exists (use the update command)", *f.selector.client)
	}
	client := idp.Client{
		ClientID:                *f.selector.client,
		Type:                    idp.ClientType(*f.typ),
		Audience:                *f.audience,
		GrantTypes:              parseList(*f.grantTypes),
		ClientCredentialsScopes: parseList(*f.ccScopes),
		RedirectURIs:            parseList(*f.redirect),
		PostLogoutRedirectURIs:  parseList(*f.postLogout),
		AllowedOrigins:          parseList(*f.origin),
		Users:                   []idp.User{},
	}
	if client.Confidential() {
		secret, err := resolveNewSecret(*f.secret)
		if err != nil {
			return err
		}
		client.ClientSecret = secret
	}
	clients = append(clients, client)
	// Pre-flight the new entry so an inconsistent grant/profile/scopes
	// combination is reported before the file is touched.
	if err := idp.ValidateClient(client); err != nil {
		return err
	}
	if err := idp.SaveClients(*f.selector.file, clients); err != nil {
		return err
	}
	fmt.Printf("client %q added to %s\n", client.ClientID, *f.selector.file)
	return nil
}

// applyClientChanges applies the explicitly provided flags to the client in
// place and reports whether anything changed.
func applyClientChanges(client *idp.Client, spec *clientChangeSpec) (bool, error) {
	profileChanged, err := applyClientProfileChange(client, spec)
	if err != nil {
		return false, err
	}
	endpointChanged, err := applyClientEndpointChanges(client, spec)
	if err != nil {
		return false, err
	}
	return profileChanged || endpointChanged, nil
}

// effectiveGrantTypes resolves the grant list of a client from an optional
// comma-separated flag value: parsed entries, or the historic default
// (authorization_code + refresh_token) when the flag is absent.
func effectiveGrantTypes(flagValue string) []string {
	grants := parseList(flagValue)
	if len(grants) == 0 {
		return []string{idp.GrantAuthorizationCode, idp.GrantRefreshToken}
	}
	return grants
}

// applyClientProfileChange applies the -type and -secret flags and enforces
// the resulting profile/secret combination.
func applyClientProfileChange(client *idp.Client, spec *clientChangeSpec) (bool, error) {
	changed := false
	if spec.provid["type"] {
		if *spec.f.typ != string(idp.TypePublic) && *spec.f.typ != string(idp.TypeConfidential) {
			return false, fmt.Errorf("invalid -type %q: must be %q or %q", *spec.f.typ, idp.TypePublic, idp.TypeConfidential)
		}
		previous := client.Confidential()
		client.Type = idp.ClientType(*spec.f.typ)
		if previous && !client.Confidential() {
			// Switching to public: the secret would be dead (and rejected)
			// configuration, so it is dropped.
			client.ClientSecret = ""
		}
		changed = true
	}
	if spec.provid["secret"] {
		secret, err := resolveNewSecret(*spec.f.secret)
		if err != nil {
			return false, err
		}
		client.ClientSecret = secret
		changed = true
	}
	if client.Confidential() && client.ClientSecret == "" {
		return false, fmt.Errorf("client %q is confidential and needs a secret: provide -secret", client.ClientID)
	}
	return changed, nil
}

// applyClientEndpointChanges applies the audience/grants/scopes/redirect/
// post-logout/origin flags.
func applyClientEndpointChanges(client *idp.Client, spec *clientChangeSpec) (bool, error) {
	changed := false
	if spec.provid["audience"] {
		client.Audience = *spec.f.audience
		changed = true
	}
	if spec.provid["grant-types"] {
		client.GrantTypes = effectiveGrantTypes(*spec.f.grantTypes)
		changed = true
	}
	if spec.provid["cc-scopes"] {
		client.ClientCredentialsScopes = parseList(*spec.f.ccScopes)
		changed = true
	}
	if spec.provid["redirect"] {
		client.RedirectURIs = parseList(*spec.f.redirect)
		changed = true
	}
	if spec.provid["post-logout"] {
		client.PostLogoutRedirectURIs = parseList(*spec.f.postLogout)
		changed = true
	}
	if spec.provid["origin"] {
		client.AllowedOrigins = parseList(*spec.f.origin)
		changed = true
	}
	return changed, nil
}

func clientUpdate(args []string) error {
	spec, err := parseClientChangeArgs(args)
	if err != nil {
		return err
	}
	clients, err := loadExistingClients(*spec.f.selector.file)
	if err != nil {
		return err
	}
	idx := findClient(clients, *spec.f.selector.client)
	if idx < 0 {
		return fmt.Errorf("client %q does not exist", *spec.f.selector.client)
	}
	changed, err := applyClientChanges(&clients[idx], spec)
	if err != nil {
		return err
	}
	if !changed {
		return fmt.Errorf("nothing to update: provide -type, -secret, -audience, -grant-types, -cc-scopes, -redirect, -post-logout or -origin")
	}
	// Pre-flight the mutated entry so an inconsistent combination (e.g.
	// -grant-types client_credentials without -cc-scopes) is reported
	// before the file is touched.
	if err := idp.ValidateClient(clients[idx]); err != nil {
		return err
	}
	if err := idp.SaveClients(*spec.f.selector.file, clients); err != nil {
		return err
	}
	fmt.Printf("client %q updated in %s (takes effect on IdP restart)\n", clients[idx].ClientID, *spec.f.selector.file)
	return nil
}

func clientRemove(args []string) error {
	fs := flag.NewFlagSet("client remove", flag.ExitOnError)
	sel := registerClientSelector(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireSelector(sel); err != nil {
		return err
	}
	clients, err := loadExistingClients(*sel.file)
	if err != nil {
		return err
	}
	idx := findClient(clients, *sel.client)
	if idx < 0 {
		return fmt.Errorf("client %q does not exist", *sel.client)
	}
	clients = append(clients[:idx], clients[idx+1:]...)
	if err := idp.SaveClients(*sel.file, clients); err != nil {
		return err
	}
	if len(clients) == 0 {
		fmt.Println("warning: the clients file is now empty; minidp will refuse to start with it")
	}
	fmt.Printf("client %q removed from %s (takes effect on IdP restart)\n", *sel.client, *sel.file)
	return nil
}

// describeClient renders one list/show line. Secrets and hashes are never
// printed.
func describeClient(c idp.Client) string {
	audience := c.Audience
	if audience == "" {
		audience = c.ClientID
	}
	grants := c.GrantTypes
	if len(grants) == 0 {
		grants = []string{idp.GrantAuthorizationCode, idp.GrantRefreshToken}
	}
	line := c.ClientID + "\ttype: " + string(c.Type) + "\taudience: " + audience +
		"\tgrants: " + strings.Join(grants, ",")
	if len(c.ClientCredentialsScopes) > 0 {
		line += "\tcc-scopes: " + strings.Join(c.ClientCredentialsScopes, ",")
	}
	line += "\tredirects: " + strings.Join(c.RedirectURIs, ",")
	if len(c.PostLogoutRedirectURIs) > 0 {
		line += "\tpost-logout: " + strings.Join(c.PostLogoutRedirectURIs, ",")
	}
	if len(c.AllowedOrigins) > 0 {
		line += "\torigins: " + strings.Join(c.AllowedOrigins, ",")
	}
	line += fmt.Sprintf("\tusers: %d", len(c.Users))
	return line
}

func clientList(args []string) error {
	fs := flag.NewFlagSet("client list", flag.ExitOnError)
	file := fs.String("file", "clients.json", "path to the clients JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	clients, err := idp.ReadClients(*file)
	if err != nil {
		return err
	}
	for _, c := range clients {
		fmt.Println(describeClient(c))
	}
	fmt.Fprintf(os.Stderr, "%d client(s)\n", len(clients))
	return nil
}

func clientShow(args []string) error {
	fs := flag.NewFlagSet("client show", flag.ExitOnError)
	sel := registerClientSelector(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireSelector(sel); err != nil {
		return err
	}
	clients, err := loadExistingClients(*sel.file)
	if err != nil {
		return err
	}
	idx := findClient(clients, *sel.client)
	if idx < 0 {
		return fmt.Errorf("client %q does not exist", *sel.client)
	}
	c := clients[idx]
	fmt.Println(describeClient(c))
	for _, u := range c.Users {
		line := "  user: " + u.Username
		if u.Email != "" {
			line += "\t" + u.Email
		}
		if u.Name != "" {
			line += "\t" + u.Name
		}
		if len(u.Roles) > 0 {
			line += "\troles: " + strings.Join(u.Roles, ",")
		}
		fmt.Println(line)
	}
	return nil
}

// userFlags bundles the flags shared by user add and update.
type userFlags struct {
	selector *clientSelector
	username *string
	password *string
	email    *string
	name     *string
	roles    *string
	cost     *int
}

func registerUserFlags(fs *flag.FlagSet) *userFlags {
	u := &userFlags{}
	u.selector = registerClientSelector(fs)
	u.username = fs.String("username", "", "login name (required)")
	u.password = fs.String("password", "", "password; '-' reads one line from stdin, empty prompts interactively")
	u.email = fs.String("email", "", "optional email claim")
	u.name = fs.String("name", "", "optional name claim")
	u.roles = fs.String("roles", "", "optional comma-separated roles, released as the roles claim on the user's tokens")
	u.cost = fs.Int("cost", bcrypt.DefaultCost, "bcrypt cost factor")
	return u
}

// userStoreOf returns the users slice of the selected client entry.
func userStoreOf(clients []idp.Client, sel *clientSelector) ([]idp.User, error) {
	idx := findClient(clients, *sel.client)
	if idx < 0 {
		return nil, fmt.Errorf("client %q does not exist (add it with: clientctl client add)", *sel.client)
	}
	return clients[idx].Users, nil
}

// newUserHash resolves the password from -password and hashes it with
// bcrypt, rejecting an empty password.
func newUserHash(flagValue string, cost int, confirm bool) (string, error) {
	password, err := resolveSecret(flagValue, "password", confirm)
	if err != nil {
		return "", err
	}
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	return idp.HashPassword(password, cost)
}

func findUserIndex(users []idp.User, username string) int {
	for i, u := range users {
		if u.Username == username {
			return i
		}
	}
	return -1
}

func userAdd(args []string) error {
	fs := flag.NewFlagSet("user add", flag.ExitOnError)
	u := registerUserFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireSelector(u.selector); err != nil {
		return err
	}
	if *u.username == "" {
		return fmt.Errorf("-username is required")
	}
	clients, _, err := loadClients(*u.selector.file)
	if err != nil {
		return err
	}
	users, err := userStoreOf(clients, u.selector)
	if err != nil {
		return err
	}
	if findUserIndex(users, *u.username) >= 0 {
		return fmt.Errorf("user %q already exists (use the update command)", *u.username)
	}
	hash, err := newUserHash(*u.password, *u.cost, true)
	if err != nil {
		return err
	}
	users = append(users, idp.User{
		Username:     *u.username,
		PasswordHash: hash,
		Email:        *u.email,
		Name:         *u.name,
		Roles:        parseRoles(*u.roles),
	})
	if err := saveClientUsers(clients, u.selector, users, *u.selector.file); err != nil {
		return err
	}
	fmt.Printf("user %q added to client %q in %s\n", *u.username, *u.selector.client, *u.selector.file)
	return nil
}

// saveClientUsers stores a client's updated users slice back into the
// clients file.
func saveClientUsers(clients []idp.Client, sel *clientSelector, users []idp.User, file string) error {
	idx := findClient(clients, *sel.client)
	clients[idx].Users = users
	return idp.SaveClients(file, clients)
}

// userChangeSpec bundles the parsed user update invocation: the shared flags
// plus which of them were explicitly provided.
type userChangeSpec struct {
	u                *userFlags
	passwordProvided bool
	rolesProvided    bool
}

// parseUserChangeArgs parses the user update flags and records which of
// -password and -roles were explicitly set.
func parseUserChangeArgs(args []string) (*userChangeSpec, error) {
	fs := flag.NewFlagSet("user update", flag.ExitOnError)
	spec := &userChangeSpec{u: registerUserFlags(fs)}
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if err := requireSelector(spec.u.selector); err != nil {
		return nil, err
	}
	if *spec.u.username == "" {
		return nil, fmt.Errorf("-username is required")
	}
	// fs.Visit reports which flags were actually set, so "no -password flag"
	// (keep the existing hash) is distinguishable from "-password -" (read one
	// line from stdin) and "-password ''" (prompt interactively). The same
	// applies to -roles: absent keeps the existing roles, "-roles ''" clears
	// them.
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "password":
			spec.passwordProvided = true
		case "roles":
			spec.rolesProvided = true
		}
	})
	return spec, nil
}

// applyUserUpdates applies the explicitly provided flags to the user entry in
// place and reports whether anything changed.
func applyUserUpdates(user *idp.User, spec *userChangeSpec) (bool, error) {
	changed := false
	if spec.passwordProvided {
		hash, err := newUserHash(*spec.u.password, *spec.u.cost, false)
		if err != nil {
			return false, err
		}
		user.PasswordHash = hash
		changed = true
	} else if *spec.u.cost != bcrypt.DefaultCost {
		return false, fmt.Errorf("-cost requires a new password (-password)")
	}
	if *spec.u.email != "" {
		user.Email = *spec.u.email
		changed = true
	}
	if *spec.u.name != "" {
		user.Name = *spec.u.name
		changed = true
	}
	if spec.rolesProvided {
		user.Roles = parseRoles(*spec.u.roles)
		changed = true
	}
	return changed, nil
}

func userUpdate(args []string) error {
	spec, err := parseUserChangeArgs(args)
	if err != nil {
		return err
	}
	clients, err := loadExistingClients(*spec.u.selector.file)
	if err != nil {
		return err
	}
	users, err := userStoreOf(clients, spec.u.selector)
	if err != nil {
		return err
	}
	idx := findUserIndex(users, *spec.u.username)
	if idx < 0 {
		return fmt.Errorf("user %q does not exist in client %q", *spec.u.username, *spec.u.selector.client)
	}
	changed, err := applyUserUpdates(&users[idx], spec)
	if err != nil {
		return err
	}
	if !changed {
		return fmt.Errorf("nothing to update: provide -password, -email, -name or -roles")
	}
	if err := saveClientUsers(clients, spec.u.selector, users, *spec.u.selector.file); err != nil {
		return err
	}
	fmt.Printf("user %q updated in client %q (takes effect on IdP restart)\n", *spec.u.username, *spec.u.selector.client)
	return nil
}

func userRemove(args []string) error {
	fs := flag.NewFlagSet("user remove", flag.ExitOnError)
	sel := registerClientSelector(fs)
	username := fs.String("username", "", "login name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireSelector(sel); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("-username is required")
	}
	clients, err := loadExistingClients(*sel.file)
	if err != nil {
		return err
	}
	users, err := userStoreOf(clients, sel)
	if err != nil {
		return err
	}
	idx := findUserIndex(users, *username)
	if idx < 0 {
		return fmt.Errorf("user %q does not exist in client %q", *username, *sel.client)
	}
	users = append(users[:idx], users[idx+1:]...)
	if err := saveClientUsers(clients, sel, users, *sel.file); err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println("warning: the client has no users left; minidp will refuse to start with it")
	}
	fmt.Printf("user %q removed from client %q (takes effect on IdP restart)\n", *username, *sel.client)
	return nil
}

func userList(args []string) error {
	fs := flag.NewFlagSet("user list", flag.ExitOnError)
	sel := registerClientSelector(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := requireSelector(sel); err != nil {
		return err
	}
	clients, err := idp.ReadClients(*sel.file)
	if err != nil {
		return err
	}
	users, err := userStoreOf(clients, sel)
	if err != nil {
		return err
	}
	for _, u := range users {
		line := u.Username
		if u.Email != "" {
			line += "\t" + u.Email
		}
		if u.Name != "" {
			line += "\t" + u.Name
		}
		if len(u.Roles) > 0 {
			line += "\troles: " + strings.Join(u.Roles, ",")
		}
		fmt.Println(line)
	}
	fmt.Fprintf(os.Stderr, "%d user(s) in client %s\n", len(users), *sel.client)
	return nil
}

func hash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	password := fs.String("password", "", "password; '-' reads one line from stdin, empty prompts interactively")
	cost := fs.Int("cost", bcrypt.DefaultCost, "bcrypt cost factor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	h, err := newUserHash(*password, *cost, false)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}
