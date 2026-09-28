package main

import "errors"

// Static sentinel errors for the clientctl tool. Every error value created at
// runtime wraps one of these, so messages keep their dynamic context while
// remaining classifiable with errors.Is.
var (
	errUnknownClientCmd   = errors.New("(want add, update, remove, list or show)")
	errUnknownUserCmd     = errors.New("(want add, update, remove or list)")
	errNoSecret           = errors.New("use the flag (or '-<flag> -' with piped stdin)")
	errMustBeNotEmpty     = errors.New("must not be empty")
	errValuesDoNotMatch   = errors.New("do not match")
	errClientsFileMissing = errors.New("does not exist yet")
	errClientFlagRequired = errors.New("-client is required")
	errTypeMustBe         = errors.New(`must be "public" or "confidential"`)
	errRedirectRequired   = errors.New("-redirect is required: declare the registered redirect_uri values")
	errClientExistsHint   = errors.New("already exists (use the update command)")
	errConfidentialNeeds  = errors.New("is confidential and needs a secret: provide -secret")
	errClientDoesNotExist = errors.New("does not exist")
	errClientMissingHint  = errors.New("does not exist (add it with: clientctl client add)")
	errPasswordEmpty      = errors.New("password must not be empty")
	errUsernameRequired   = errors.New("-username is required")
	errUserExistsHint     = errors.New("already exists (use the update command)")
	errCostNeedsPassword  = errors.New("-cost requires a new password (-password)")
	errUserNotInClient    = errors.New("does not exist in client")
	errNothingToUpdateCli = errors.New("nothing to update: provide -type, -secret, -audience, -grant-types, -cc-scopes, -cc-roles, -allowed-scopes, -redirect, -post-logout or -origin")
	errNothingToUpdateUsr = errors.New("nothing to update: provide -password, -email, -name or -roles")
)
