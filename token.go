package gojwe

import (
	"encoding/hex"
	"github.com/goccy/go-json"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwe"
)

type Token interface {
	Generate(payload map[string]any, key string) (string, error)
	Verify(token, key string) bool
	Parse(token, key string) (map[string]any, error)
}

type JWEToken Token

type jweToken struct {
}

func (j *jweToken) Generate(payload map[string]any, key string) (string, error) {
	secretKey, err := hex.DecodeString(key)
	if err != nil {
		return "", err
	}

	// Convert payload to string
	payloadByte, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	encrypted, err := jwe.Encrypt(payloadByte, jwe.WithKey(jwa.A256GCMKW, secretKey))
	if err != nil {
		return "", err
	}

	return string(encrypted), nil
}

func (j *jweToken) Verify(token, key string) bool {
	claims, err := j.Parse(token, key)

	return claims != nil && err == nil
}

func (j *jweToken) Parse(token, key string) (map[string]any, error) {
	secretKey, err := hex.DecodeString(key)
	if err != nil {
		return nil, err
	}

	decrypted, err := jwe.Decrypt([]byte(token), jwe.WithKey(jwa.A256GCMKW, secretKey))
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

func New() JWEToken {
	return &jweToken{}
}
