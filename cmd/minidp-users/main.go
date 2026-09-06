// Command minidp-users manages the JSON users file for minidp. Passwords are
// never stored in plaintext: the tool writes salted bcrypt hashes (the salt is
// part of the bcrypt format), and the IdP refuses to start on a file that
// contains anything else.
//
// Usage:
//
//	minidp-users add    -file users.json -username alice [-email ...] [-name ...] [-roles a,b] [-password ...|-] [-cost 10]
//	minidp-users update -file users.json -username alice [-email ...] [-name ...] [-roles a,b] [-password ...|-] [-cost 10]
//	minidp-users remove -file users.json -username alice
//	minidp-users list   -file users.json
//	minidp-users hash   [-password ...|-] [-cost 10]
//
// A password is supplied either via -password (visible in the process list —
// prefer the interactive prompt or "-password -" to read one line from stdin)
// or by typing it when prompted. list never prints password hashes.
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
	case "add":
		err = add(os.Args[2:])
	case "update":
		err = update(os.Args[2:])
	case "remove":
		err = remove(os.Args[2:])
	case "list":
		err = list(os.Args[2:])
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
	fmt.Fprint(os.Stderr, `minidp-users — manage the minidp users file

Usage:
  minidp-users add    -file users.json -username alice [-email ...] [-name ...] [-roles a,b] [-password ...|-] [-cost 10]
  minidp-users update -file users.json -username alice [-email ...] [-name ...] [-roles a,b] [-password ...|-] [-cost 10]
  minidp-users remove -file users.json -username alice
  minidp-users list   -file users.json
  minidp-users hash   [-password ...|-] [-cost 10]

Passwords are stored as salted bcrypt hashes; list never prints them.
"-password -" reads one line from stdin; without -password an interactive
prompt (with confirmation) is used where applicable. -roles takes a
comma-separated list; updating with "-roles ''" clears all roles.
`)
}

// userFlags bundles the flags shared by add and update.
type userFlags struct {
	file     *string
	username *string
	password *string
	email    *string
	name     *string
	roles    *string
	cost     *int
}

func registerUserFlags(fs *flag.FlagSet) *userFlags {
	u := &userFlags{}
	u.file = fs.String("file", "users.json", "path to the users JSON file")
	u.username = fs.String("username", "", "login name (required)")
	u.password = fs.String("password", "", "password; '-' reads one line from stdin, empty prompts interactively")
	u.email = fs.String("email", "", "optional email claim")
	u.name = fs.String("name", "", "optional name claim")
	u.roles = fs.String("roles", "", "optional comma-separated roles, released as the roles claim on the user's tokens")
	u.cost = fs.Int("cost", bcrypt.DefaultCost, "bcrypt cost factor")
	return u
}

// parseRoles splits a comma-separated -roles value into clean entries:
// whitespace around entries is trimmed and empty entries are dropped, so the
// result always satisfies the users-file validation.
func parseRoles(value string) []string {
	var roles []string
	for _, r := range strings.Split(value, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, r)
		}
	}
	return roles
}

// resolvePassword returns the password from the flag, from stdin ("-" or a
// piped non-terminal stdin), or from an interactive prompt.
func resolvePassword(flagValue string, confirm bool) (string, error) {
	switch {
	case flagValue == "-":
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		return strings.TrimRight(line, "\r\n"), nil
	case flagValue != "":
		return flagValue, nil
	case !term.IsTerminal(int(os.Stdin.Fd())):
		return "", fmt.Errorf("no password: use -password (or '-password -' with piped stdin)")
	}

	fmt.Fprint(os.Stderr, "Enter password: ")
	pw, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if len(pw) == 0 {
		return "", fmt.Errorf("password must not be empty")
	}
	if !confirm {
		return string(pw), nil
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	again, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(pw) != string(again) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(pw), nil
}

// readUsersForUpdate loads the users file, treating a missing file as empty
// (so `add` can create it).
func readUsersForUpdate(path string) ([]idp.User, bool, error) {
	users, err := idp.ReadUsers(path)
	switch {
	case err == nil:
		return users, true, nil
	case errors.Is(err, os.ErrNotExist):
		return nil, false, nil
	default:
		return nil, false, err
	}
}

func findUserIndex(users []idp.User, username string) int {
	for i, u := range users {
		if u.Username == username {
			return i
		}
	}
	return -1
}

func add(args []string) error {
	fs := flag.NewFlagSet("add", flag.ExitOnError)
	u := registerUserFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *u.username == "" {
		return fmt.Errorf("-username is required")
	}
	users, _, err := readUsersForUpdate(*u.file)
	if err != nil {
		return err
	}
	if findUserIndex(users, *u.username) >= 0 {
		return fmt.Errorf("user %q already exists (use the update command)", *u.username)
	}
	password, err := resolvePassword(*u.password, true)
	if err != nil {
		return err
	}
	if password == "" {
		return fmt.Errorf("password must not be empty")
	}
	hash, err := idp.HashPassword(password, *u.cost)
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
	if err := idp.SaveUsers(*u.file, users); err != nil {
		return err
	}
	fmt.Printf("user %q added to %s\n", *u.username, *u.file)
	return nil
}

func update(args []string) error {
	fs := flag.NewFlagSet("update", flag.ExitOnError)
	u := registerUserFlags(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *u.username == "" {
		return fmt.Errorf("-username is required")
	}
	users, ok, err := readUsersForUpdate(*u.file)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("users file %q does not exist yet", *u.file)
	}
	idx := findUserIndex(users, *u.username)
	if idx < 0 {
		return fmt.Errorf("user %q does not exist", *u.username)
	}

	// fs.Visit reports which flags were actually set, so "no -password flag"
	// (keep the existing hash) is distinguishable from "-password -" (read one
	// line from stdin) and "-password ''" (prompt interactively). The same
	// applies to -roles: absent keeps the existing roles, "-roles ''" clears
	// them.
	passwordProvided := false
	rolesProvided := false
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "password":
			passwordProvided = true
		case "roles":
			rolesProvided = true
		}
	})

	changed := false
	if passwordProvided {
		password, err := resolvePassword(*u.password, false)
		if err != nil {
			return err
		}
		if password == "" {
			return fmt.Errorf("password must not be empty")
		}
		hash, err := idp.HashPassword(password, *u.cost)
		if err != nil {
			return err
		}
		users[idx].PasswordHash = hash
		changed = true
	} else if *u.cost != bcrypt.DefaultCost {
		return fmt.Errorf("-cost requires a new password (-password)")
	}
	if *u.email != "" {
		users[idx].Email = *u.email
		changed = true
	}
	if *u.name != "" {
		users[idx].Name = *u.name
		changed = true
	}
	if rolesProvided {
		users[idx].Roles = parseRoles(*u.roles)
		changed = true
	}
	if !changed {
		return fmt.Errorf("nothing to update: provide -password, -email, -name or -roles")
	}
	if err := idp.SaveUsers(*u.file, users); err != nil {
		return err
	}
	fmt.Printf("user %q updated in %s (takes effect on IdP restart)\n", *u.username, *u.file)
	return nil
}

func remove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ExitOnError)
	file := fs.String("file", "users.json", "path to the users JSON file")
	username := fs.String("username", "", "login name (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *username == "" {
		return fmt.Errorf("-username is required")
	}
	users, ok, err := readUsersForUpdate(*file)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("users file %q does not exist", *file)
	}
	idx := findUserIndex(users, *username)
	if idx < 0 {
		return fmt.Errorf("user %q does not exist", *username)
	}
	users = append(users[:idx], users[idx+1:]...)
	if err := idp.SaveUsers(*file, users); err != nil {
		return err
	}
	if len(users) == 0 {
		fmt.Println("warning: the users file is now empty; minidp will refuse to start with it")
	}
	fmt.Printf("user %q removed from %s (takes effect on IdP restart)\n", *username, *file)
	return nil
}

func list(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	file := fs.String("file", "users.json", "path to the users JSON file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	users, err := idp.ReadUsers(*file)
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
	fmt.Fprintf(os.Stderr, "%d user(s)\n", len(users))
	return nil
}

func hash(args []string) error {
	fs := flag.NewFlagSet("hash", flag.ExitOnError)
	password := fs.String("password", "", "password; '-' reads one line from stdin, empty prompts interactively")
	cost := fs.Int("cost", bcrypt.DefaultCost, "bcrypt cost factor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pw, err := resolvePassword(*password, false)
	if err != nil {
		return err
	}
	if pw == "" {
		return fmt.Errorf("password must not be empty")
	}
	h, err := idp.HashPassword(pw, *cost)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}
