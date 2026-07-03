package gojwe

import (
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

type JweAesGcm256 struct {
	opts options
}

func (j *JweAesGcm256) Generate(payload map[string]any, key []byte) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}

	// Convert payload to string
	payloadByte, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encrypted, err := jwe.Encrypt(payloadByte, jwe.WithKey(jwa.A256GCMKW, key))
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}

func (j *JweAesGcm256) Verify(token string, key []byte) bool {
	claims, err := j.Parse(token, key)

	return claims != nil && err == nil
}

func (j *JweAesGcm256) Parse(token string, key []byte) (map[string]any, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}

	decrypted, err := jwe.Decrypt([]byte(token), jwe.WithKey(jwa.A256GCMKW, key))
	if err != nil {
		return nil, err
	}

	// Parse the decrypted payload
	claims := map[string]any{}
	if err = json.Unmarshal(decrypted, &claims); err != nil {
		return nil, err
	}

	// Validate standard time-based claims (exp/nbf)
	if err = validateTimeClaims(claims, j.opts); err != nil {
		return nil, err
	}

	return claims, nil
}
