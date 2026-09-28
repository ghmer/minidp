package idp

import "errors"

// Static sentinel errors for the IdP. Every error value created at runtime
// wraps one of these (or an upstream error), so callers can classify failures
// with errors.Is while messages keep their full dynamic context.

// Clients file and client validation.
var (
	errClientIDEmpty        = errors.New("client_id must not be empty")
	errPaddedValue          = errors.New("must not have leading or trailing whitespace")
	errValueWhitespace      = errors.New("must not contain whitespace")
	errPublicClientSecret   = errors.New("a public client must not have a client_secret")
	errConfidentialNoSecret = errors.New("a confidential client requires a client_secret (generate one with: openssl rand -base64 32)")
	errClientTypeMustBe     = errors.New(`must be "public" or "confidential"`)
	errWhitespaceEntry      = errors.New("must not be empty, whitespace-padded or contain whitespace")
	errDuplicateCCRole      = errors.New("duplicate client_credentials role")
	errGrantTypesAllowed    = errors.New(`must be "authorization_code", "refresh_token" or "client_credentials"`)
	errDuplicateGrantType   = errors.New("duplicate grant type")
	errGrantNotEnabled      = errors.New("grant is not enabled")
	errGrantWantsConfident  = errors.New("grant requires the confidential profile (client authentication at the token endpoint, RFC 6749 §4.4)")
	errCCScopesRequired     = errors.New("grant requires a non-empty client_credentials_scopes list (there is no login step, so scopes cannot be requested at token time)")
	errAllowedScopeForm     = errors.New("must have the api://<audience>/<name> form")
	errAllowedScopeOwnAud   = errors.New("must reference the client's own audience")
	errRedirectURIRequired  = errors.New("at least one redirect_uri is required")
	errEmptyValue           = errors.New("must not be empty")
	errURLAbsolute          = errors.New("must be an absolute http(s) URL with a host")
	errClientsArrayMissing  = errors.New("is an object but carries no clients array")
	errClientsFileShape     = errors.New("is neither a JSON array of clients nor a clients document")
	errFreeOfWhitespace     = errors.New("must be non-empty and free of whitespace")
	errDuplicateResAudience = errors.New("duplicate resource audience")
	errAppRolesRequired     = errors.New("must define at least one app role")
	errDuplicateAppRole     = errors.New("duplicate app role")
	errCCRoleNotDefined     = errors.New("is not defined for audience")
	errUserRoleNotDefined   = errors.New("which is not defined for audience")
	errDuplicateClientID    = errors.New("duplicate client_id")
	errNoClientsRegistered  = errors.New("clients file contains no clients: register at least one client (see clientctl)")
	errNoUsersRegistered    = errors.New("has no users: add at least one account (clientctl user add)")
)

// Configuration.
var (
	errClientsFileUnset  = errors.New("IDP_CLIENTS_FILE is not set: minidp registers its clients (profiles, redirect policies, audiences and users) in a clients file; create one (see clientctl and clients.json.example) and point IDP_CLIENTS_FILE at it")
	errRemovedVariable   = errors.New("is no longer supported: register clients in the IDP_CLIENTS_FILE clients file (see clientctl and clients.json.example)")
	errIntNotWholeNumber = errors.New("must be a whole number")
	errIntNotPositive    = errors.New("must be positive")
)

// Token verification and issuance.
var (
	errTokenInvalid     = errors.New("invalid token")
	errNotAccessToken   = errors.New("invalid token: not an access token")
	errClaimsInvalid    = errors.New("invalid claims")
	errAudienceMissing  = errors.New("invalid token: missing audience")
	errAudienceRejected = errors.New("invalid token: audience not accepted here")
	errTokenRevoked     = errors.New("invalid token: revoked")
	errNotIDToken       = errors.New("invalid token: not an id token")
	errIssuerForeign    = errors.New("invalid token: foreign issuer")
	errTokensUnregCli   = errors.New("issue tokens for unregistered client")
)

// Signing keys and keyring.
var (
	errKeyringEntryIncomplete    = errors.New("entry with empty kid or file")
	errKeyringStateInvalid       = errors.New("has invalid state")
	errKeyringDuplicateKid       = errors.New("duplicate kid")
	errKeyringContainsNoKeys     = errors.New("contains no keys")
	errKeyringThumbprintMismatch = errors.New("does not match the key material's RFC 7638 thumbprint")
	errKeyringMultipleActive     = errors.New("more than one active key")
	errKeyringNoActiveKey        = errors.New("has no active key")
	errAwaitTimedOut             = errors.New("timed out after")
	errKeyDirRequired            = errors.New("key rotation requires IDP_KEY_DIR")
	errGeneratedKidExists        = errors.New("already exists")
	errNoPEMBlock                = errors.New("rsa key: no PEM block found")
	errNotAnRSAKey               = errors.New("is not an RSA key")
	errUnknownKid                = errors.New("unknown kid")
)

// User validation and password hashing.
var (
	errUsernameEmpty     = errors.New("username must not be empty")
	errPasswordHashShape = errors.New("password_hash must be a 60-character bcrypt hash like $2a$10$... (generate one with: clientctl hash)")
	errRolesEmptyEntry   = errors.New("roles must not contain empty entries")
	errDuplicateRole     = errors.New("duplicate role")
	errDuplicateUsername = errors.New("duplicate username")
	errBcryptCostRange   = errors.New("bcrypt cost must be between 4 and 31")
)

// Login page assets.
var errAssetOverrideTooLarge = errors.New("asset override exceeds the size limit")
