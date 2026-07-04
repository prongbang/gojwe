package gojwe

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"github.com/goccy/go-json"
	"golang.org/x/crypto/chacha20poly1305"
	"strings"
)

type JweXChaCha20 struct {
	opts options
}

func (j *JweXChaCha20) encrypt(payload []byte, key []byte) (*Serialize, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	// Generate a 24-byte nonce (IV)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, err
	}

	// Encrypt and generate authentication tag
	ciphertext := aead.Seal(nil, nonce, payload, nil)

	// Extract authentication tag (last 16 bytes)
	tag := ciphertext[len(ciphertext)-16:]
	ciphertext = ciphertext[:len(ciphertext)-16]

	// Encode nonce, ciphertext, and tag as Base64
	nonceB64 := base64.RawURLEncoding.EncodeToString(nonce)
	cipherB64 := base64.RawURLEncoding.EncodeToString(ciphertext)
	tagB64 := base64.RawURLEncoding.EncodeToString(tag)

	return &Serialize{Iv: nonceB64, Cipher: cipherB64, Tag: tagB64}, nil
}

func (j *JweXChaCha20) Generate(payload map[string]any, key []byte) (string, error) {
	// Convert payload to JSON
	payloadByte, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return j.generate(payloadByte, key)
}

// generate encrypts already-marshalled JSON payload bytes into a token.
func (j *JweXChaCha20) generate(payloadByte []byte, key []byte) (string, error) {
	if err := validateKey(key); err != nil {
		return "", err
	}

	// Derive independent encryption and MAC keys (key separation)
	encKey, macKey := deriveKeys(key)

	// Encrypt payload
	serialize, err := j.encrypt(payloadByte, encKey)
	if err != nil {
		return "", err
	}

	// Build the base64url-encoded JWE header (alg=dir, enc=XC20P)
	headerB64 := encodeHeaderB64("XC20P", serialize.Iv, serialize.Tag)

	// Generate signature
	signature := HMAC(headerB64, serialize.Cipher, macKey)

	// Combine header.payload.signature
	return headerB64 + "." + serialize.Cipher + "." + signature, nil
}

func (j *JweXChaCha20) Verify(token string, key []byte) bool {
	claims, err := j.Parse(token, key)

	return claims != nil && err == nil
}

func (j *JweXChaCha20) Parse(token string, key []byte) (map[string]any, error) {
	plaintext, err := j.decrypt(token, key)
	if err != nil {
		return nil, err
	}

	// Parse the decrypted payload
	claims := map[string]any{}
	if err = json.Unmarshal(plaintext, &claims); err != nil {
		return nil, err
	}

	// Validate the registered claims (exp/nbf/iat/iss/aud)
	if err = validateClaims(claims, j.opts); err != nil {
		return nil, err
	}

	return claims, nil
}

// decrypt verifies the signature and returns the raw JSON payload bytes.
func (j *JweXChaCha20) decrypt(token string, key []byte) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if len(token) > MaxTokenBytes {
		return nil, ErrInvalidToken
	}

	encKey, macKey := deriveKeys(key)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	headerB64, cipherB64, receivedSignature := parts[0], parts[1], parts[2]

	// Decode header
	headerJSON, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return nil, ErrInvalidToken
	}
	var header Header
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		return nil, ErrInvalidToken
	}

	// Verify signature using a constant-time comparison to avoid timing attacks
	expectedSignature := HMAC(headerB64, cipherB64, macKey)
	if !hmac.Equal([]byte(receivedSignature), []byte(expectedSignature)) {
		return nil, ErrInvalidSignature
	}

	// Decode nonce, ciphertext, and tag
	nonce, err := base64.RawURLEncoding.DecodeString(header.Iv)
	if err != nil {
		return nil, ErrInvalidToken
	}
	tag, err := base64.RawURLEncoding.DecodeString(header.Tag)
	if err != nil {
		return nil, ErrInvalidToken
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(cipherB64)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Join ciphertext and tag into a single buffer for decryption
	fullCiphertext := make([]byte, 0, len(ciphertext)+len(tag))
	fullCiphertext = append(fullCiphertext, ciphertext...)
	fullCiphertext = append(fullCiphertext, tag...)

	// Decrypt payload
	aead, err := chacha20poly1305.NewX(encKey)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return nil, ErrInvalidSignature
	}

	return plaintext, nil
}

func (j *JweXChaCha20) getOptions() options { return j.opts }
