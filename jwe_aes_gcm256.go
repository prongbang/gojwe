package gojwe

import (
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

type JweAesGcm256 struct {
}

func (j *JweAesGcm256) Generate(payload map[string]any, key []byte) (string, error) {
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
	decrypted, err := jwe.Decrypt([]byte(token), jwe.WithKey(jwa.A256GCMKW, key))
	if err != nil {
		return nil, err
	}

	// Parse the decrypted payload to check expiration time
	claims := map[string]any{}
	if err = json.Unmarshal(decrypted, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}
