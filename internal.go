package gojwe

// rawCodec is implemented by the built-in JWE algorithms to expose the
// encrypt/decrypt primitives that operate directly on JSON bytes, plus the
// instance options. The typed helpers (GenerateClaims / ParseClaims) use it to
// skip the map[string]any <-> JSON round-trip and its allocations.
type rawCodec interface {
	// generate encrypts already-marshalled JSON payload bytes into a token.
	generate(payload []byte, key []byte) (string, error)
	// decrypt verifies and decrypts a token, returning the raw JSON payload
	// bytes. It does NOT unmarshal or validate time-based claims.
	decrypt(token string, key []byte) ([]byte, error)
	// getOptions returns the instance options (leeway, time validation).
	getOptions() options
}

// claimsAccessor is satisfied by RegisteredClaims (and anything embedding it),
// letting ParseClaims validate the registered claims straight from the parsed
// struct without a second unmarshal.
type claimsAccessor interface {
	GetExpirationTime() (*NumericDate, error)
	GetNotBefore() (*NumericDate, error)
	GetIssuedAt() (*NumericDate, error)
	GetIssuer() (string, error)
	GetAudience() (ClaimStrings, error)
}
