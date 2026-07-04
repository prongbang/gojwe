package gojwe

import "time"

// nowFunc is overridable in tests; defaults to time.Now.
var nowFunc = time.Now

// validateClaims validates the standard registered claims (exp, nbf, iat, iss,
// aud) of a decoded claims map according to opts. Missing claims are treated as
// "no constraint", except for iss/aud which, when required via options, must be
// present and match.
func validateClaims(claims map[string]any, opts options) error {
	now := nowFunc()

	if opts.validateTime {
		if exp, ok := toUnixTime(claims["exp"]); ok && now.After(exp.Add(opts.leeway)) {
			return ErrTokenExpired
		}
		if nbf, ok := toUnixTime(claims["nbf"]); ok && now.Add(opts.leeway).Before(nbf) {
			return ErrTokenNotYetValid
		}
		if opts.validateIat {
			if iat, ok := toUnixTime(claims["iat"]); ok && iat.After(now.Add(opts.leeway)) {
				return ErrTokenUsedBeforeIssued
			}
		}
	}

	if opts.expectedIss != "" {
		iss, _ := claims["iss"].(string)
		if iss != opts.expectedIss {
			return ErrInvalidIssuer
		}
	}
	if opts.expectedAud != "" && !audienceContains(claims["aud"], opts.expectedAud) {
		return ErrInvalidAudience
	}
	return nil
}

// audienceContains reports whether the raw "aud" claim (a string or an array of
// strings, as produced by JSON decoding) contains want.
func audienceContains(v any, want string) bool {
	switch a := v.(type) {
	case string:
		return a == want
	case []any:
		for _, item := range a {
			if s, ok := item.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, s := range a {
			if s == want {
				return true
			}
		}
	case ClaimStrings:
		for _, s := range a {
			if s == want {
				return true
			}
		}
	}
	return false
}

// toUnixTime interprets a numeric claim value as seconds since the Unix epoch.
// JSON numbers decode to float64, but int variants are handled for callers that
// build claims maps directly.
func toUnixTime(v any) (time.Time, bool) {
	switch n := v.(type) {
	case float64:
		return time.Unix(int64(n), 0), true
	case int64:
		return time.Unix(n, 0), true
	case int:
		return time.Unix(int64(n), 0), true
	case int32:
		return time.Unix(int64(n), 0), true
	default:
		return time.Time{}, false
	}
}
