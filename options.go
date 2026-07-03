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
}

func defaultOptions() options {
	return options{
		leeway:       DefaultLeeway,
		validateTime: true,
	}
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

func applyOptions(opts []Option) options {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return o
}
