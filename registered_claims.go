package gojwe

import (
	"fmt"
	"math"
	"strconv"
	"time"

	"github.com/goccy/go-json"
)

// RegisteredClaims are a structured version of the JWT Claims Set,
// restricted to Registered Claim Names, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-4.1
//
// This type can be used on its own, but then additional private and
// public claims embedded in the JWT will not be parsed. The typical use-case
// therefore is to embed this in a user-defined claim type:
//
//	type MyClaims struct {
//	    gojwe.RegisteredClaims
//	    Role string `json:"role"`
//	}
type RegisteredClaims struct {
	// the `iss` (Issuer) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.1
	Issuer string `json:"iss,omitempty"`

	// the `sub` (Subject) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.2
	Subject string `json:"sub,omitempty"`

	// the `aud` (Audience) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3
	Audience ClaimStrings `json:"aud,omitempty"`

	// the `exp` (Expiration Time) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
	ExpiresAt *NumericDate `json:"exp,omitempty"`

	// the `nbf` (Not Before) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.5
	NotBefore *NumericDate `json:"nbf,omitempty"`

	// the `iat` (Issued At) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.6
	IssuedAt *NumericDate `json:"iat,omitempty"`

	// the `jti` (JWT ID) claim. See https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.7
	ID string `json:"jti,omitempty"`
}

// GetExpirationTime returns the `exp` claim.
func (c RegisteredClaims) GetExpirationTime() (*NumericDate, error) { return c.ExpiresAt, nil }

// GetNotBefore returns the `nbf` claim.
func (c RegisteredClaims) GetNotBefore() (*NumericDate, error) { return c.NotBefore, nil }

// GetIssuedAt returns the `iat` claim.
func (c RegisteredClaims) GetIssuedAt() (*NumericDate, error) { return c.IssuedAt, nil }

// GetAudience returns the `aud` claim.
func (c RegisteredClaims) GetAudience() (ClaimStrings, error) { return c.Audience, nil }

// GetIssuer returns the `iss` claim.
func (c RegisteredClaims) GetIssuer() (string, error) { return c.Issuer, nil }

// GetSubject returns the `sub` claim.
func (c RegisteredClaims) GetSubject() (string, error) { return c.Subject, nil }

// NumericDate represents a JSON numeric date value, as referenced at
// https://datatracker.ietf.org/doc/html/rfc7519#section-2. It marshals to and
// from a numeric value counting the seconds since the Unix epoch, which keeps
// it compatible with the automatic exp/nbf validation.
type NumericDate struct {
	time.Time
}

// NewNumericDate constructs a NumericDate from a standard library time.Time,
// truncated to whole seconds.
func NewNumericDate(t time.Time) *NumericDate {
	return &NumericDate{t.Truncate(time.Second)}
}

// MarshalJSON implements the json.Marshaler interface, encoding the value as
// seconds since the Unix epoch.
func (d NumericDate) MarshalJSON() ([]byte, error) {
	return []byte(strconv.FormatInt(d.Unix(), 10)), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface, accepting integer or
// fractional seconds since the Unix epoch.
func (d *NumericDate) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	f, err := strconv.ParseFloat(string(b), 64)
	if err != nil {
		return fmt.Errorf("gojwe: invalid numeric date %q: %w", string(b), err)
	}
	sec, frac := math.Modf(f)
	*d = NumericDate{time.Unix(int64(sec), int64(frac*float64(time.Second)))}
	return nil
}

// ClaimStrings is used for the `aud` claim, which per RFC 7519 may be either a
// single string or an array of strings.
type ClaimStrings []string

// MarshalJSON encodes a single value as a plain string and multiple values as
// an array, matching common JWT conventions.
func (s ClaimStrings) MarshalJSON() ([]byte, error) {
	if len(s) == 1 {
		return json.Marshal(s[0])
	}
	return json.Marshal([]string(s))
}

// UnmarshalJSON accepts either a single string or an array of strings.
func (s *ClaimStrings) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	var raw any
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	switch v := raw.(type) {
	case string:
		*s = ClaimStrings{v}
	case []any:
		out := make(ClaimStrings, 0, len(v))
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return fmt.Errorf("gojwe: invalid audience element type %T", item)
			}
			out = append(out, str)
		}
		*s = out
	default:
		return fmt.Errorf("gojwe: invalid audience type %T", raw)
	}
	return nil
}

// GenerateClaims marshals any struct (typically one embedding RegisteredClaims)
// into an encrypted token. It is a convenience wrapper around JWE.Generate that
// lets you work with typed claims instead of building a map by hand.
//
//	claims := gojwe.RegisteredClaims{
//	    Subject:   "user-1",
//	    ExpiresAt: gojwe.NewNumericDate(time.Now().Add(time.Hour)),
//	}
//	token, err := gojwe.GenerateClaims(j, claims, key)
func GenerateClaims(j JWE, claims any, key []byte) (string, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	payload := map[string]any{}
	if err := json.Unmarshal(b, &payload); err != nil {
		return "", err
	}
	return j.Generate(payload, key)
}

// ParseClaims decrypts and validates the token (including exp/nbf handling),
// then unmarshals its payload into a value of type T. Use it to pull typed data
// out of a token without manual map access:
//
//	claims, err := gojwe.ParseClaims[gojwe.RegisteredClaims](j, token, key)
//
// T may be RegisteredClaims or any struct embedding it alongside your own fields.
func ParseClaims[T any](j JWE, token string, key []byte) (T, error) {
	var claims T
	m, err := j.Parse(token, key)
	if err != nil {
		return claims, err
	}
	b, err := json.Marshal(m)
	if err != nil {
		return claims, err
	}
	if err := json.Unmarshal(b, &claims); err != nil {
		return claims, err
	}
	return claims, nil
}
