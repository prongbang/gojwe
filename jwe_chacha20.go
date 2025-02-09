package gojwe

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/goccy/go-json"
	"golang.org/x/crypto/chacha20poly1305"
	"strings"
)

type JweChaCha20 struct {
}

func (j *JweChaCha20) encrypt(payload []byte, key []byte) (*Serialize, error) {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Generate a 12-byte nonce (IV) for ChaCha20-Poly1305
	nonce := make([]byte, chacha20poly1305.NonceSize)
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

func (j *JweChaCha20) Generate(payload map[string]any, key []byte) (string, error) {
	// Convert payload to string
	payloadByte, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Encrypt payload
	serialize, err := j.encrypt(payloadByte, key)
	if err != nil {
		return "", err
	}

	// Create JWE Header (change Alg to ChaCha20-Poly1305)
	header := Header{Alg: "dir", Enc: "C20P", Iv: serialize.Iv, Tag: serialize.Tag}

	// Encode header as Base64
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Generate signature
	signature := HMAC(headerB64, serialize.Cipher, key)

	// Combine header.payload.signature
	return headerB64 + "." + serialize.Cipher + "." + signature, nil
}

func (j *JweChaCha20) Verify(token string, key []byte) bool {
	claims, err := j.Parse(token, key)
	return claims != nil && err == nil
}

func (j *JweChaCha20) Parse(token string, key []byte) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWE format")
	}

	headerB64, cipherB64, receivedSignature := parts[0], parts[1], parts[2]

	// Decode header
	headerJSON, _ := base64.RawURLEncoding.DecodeString(headerB64)
	var header Header
	err := json.Unmarshal(headerJSON, &header)
	if err != nil {
		return nil, err
	}

	// Verify signature
	expectedSignature := HMAC(headerB64, cipherB64, key)
	if receivedSignature != expectedSignature {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode nonce, ciphertext, and tag
	nonce, _ := base64.RawURLEncoding.DecodeString(header.Iv)
	tag, _ := base64.RawURLEncoding.DecodeString(header.Tag)
	ciphertext, _ := base64.RawURLEncoding.DecodeString(cipherB64)

	// Append tag back to ciphertext for decryption
	fullCiphertext := append(ciphertext, tag...)

	// Decrypt payload
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Parse the decrypted payload
	claims := map[string]any{}
	if err = json.Unmarshal(plaintext, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}
