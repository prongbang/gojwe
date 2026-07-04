package gojwe

import "time"

// DefaultLeeway is the clock-skew tolerance applied when validating the
// time-based claims ("exp" and "nbf"). It absorbs small clock differences
// between the token issuer and verifier.
const DefaultLeeway = 30 * time.Second

// options holds the configurable behavior of a JWE instance.
type options struct {
	leeway       time.Duration
	validateTime bool
	validateIat  bool
	expectedIss  string
	expectedAud  string
}

func defaultOptions() options {
	return options{
		leeway:       DefaultLeeway,
		validateTime: true,
	}
}

// needsValidation reports whether any claim validation is configured.
func (o options) needsValidation() bool {
	return o.validateTime || o.expectedIss != "" || o.expectedAud != ""
}

// Option configures a JWE instance created by New / NewWithError.
type Option func(*options)

// WithLeeway overrides the default clock-skew tolerance used when validating
// the "exp" and "nbf" claims.
func WithLeeway(d time.Duration) Option {
	return func(o *options) { o.leeway = d }
}

// WithoutTimeValidation disables automatic validation of the "exp" and "nbf"
// claims during Parse/Verify. Use it when you want the raw claims back and
// intend to validate expiry yourself.
func WithoutTimeValidation() Option {
	return func(o *options) { o.validateTime = false }
}

// WithIssuedAtValidation enables rejecting tokens whose "iat" (issued at) claim
// is in the future (beyond the configured leeway). It is off by default because
// a fast issuer clock should not normally invalidate an otherwise-good token.
func WithIssuedAtValidation() Option {
	return func(o *options) { o.validateIat = true }
}

// WithIssuer requires the token's "iss" claim to equal the given issuer.
// Tokens with a different or missing issuer are rejected with ErrInvalidIssuer.
func WithIssuer(iss string) Option {
	return func(o *options) { o.expectedIss = iss }
}

// WithAudience requires the token's "aud" claim to contain the given audience.
// Tokens without it are rejected with ErrInvalidAudience.
func WithAudience(aud string) Option {
	return func(o *options) { o.expectedAud = aud }
}

func applyOptions(opts []Option) options {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
