package gojwe

import "time"

// nowFunc is overridable in tests; defaults to time.Now.
var nowFunc = time.Now

// validateTimeClaims validates the standard time-based claims ("exp" and
// "nbf") when they are present. Missing claims are treated as "no constraint".
func validateTimeClaims(claims map[string]any, opts options) error {
	if !opts.validateTime {
		return nil
	}
	now := nowFunc()

	if exp, ok := toUnixTime(claims["exp"]); ok {
		if now.After(exp.Add(opts.leeway)) {
			return ErrTokenExpired
		}
	}
	if nbf, ok := toUnixTime(claims["nbf"]); ok {
		if now.Add(opts.leeway).Before(nbf) {
			return ErrTokenNotYetValid
		}
	}
	return nil
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
