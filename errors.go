package gojwe

import "errors"

// Sentinel errors returned by the package. Use errors.Is to check them, e.g.
//
//	if errors.Is(err, gojwe.ErrTokenExpired) { ... }
var (
	// ErrUnsupportedAlgorithm is returned when an unknown algorithm name is passed to NewWithError.
	ErrUnsupportedAlgorithm = errors.New("gojwe: unsupported algorithm")

	// ErrInvalidKeySize is returned when the key is not exactly KeySize (32) bytes.
	ErrInvalidKeySize = errors.New("gojwe: invalid key size, expected 32 bytes")

	// ErrInvalidToken is returned when the token is malformed.
	ErrInvalidToken = errors.New("gojwe: invalid token format")

	// ErrInvalidSignature is returned when the token signature does not match.
	ErrInvalidSignature = errors.New("gojwe: invalid signature")

	// ErrTokenExpired is returned when the "exp" claim is in the past.
	ErrTokenExpired = errors.New("gojwe: token has expired")

	// ErrTokenNotYetValid is returned when the "nbf" claim is in the future.
	ErrTokenNotYetValid = errors.New("gojwe: token is not valid yet")

	// ErrTokenUsedBeforeIssued is returned when the "iat" claim is in the future
	// and issued-at validation is enabled via WithIssuedAtValidation.
	ErrTokenUsedBeforeIssued = errors.New("gojwe: token used before issued")

	// ErrInvalidAudience is returned when the "aud" claim does not contain the
	// audience configured with WithAudience.
	ErrInvalidAudience = errors.New("gojwe: invalid audience")

	// ErrInvalidIssuer is returned when the "iss" claim does not match the
	// issuer configured with WithIssuer.
	ErrInvalidIssuer = errors.New("gojwe: invalid issuer")
)
