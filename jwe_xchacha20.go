package gojwe

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"github.com/goccy/go-json"
	"golang.org/x/crypto/chacha20poly1305"
	"strings"
)

type JweXChaCha20 struct {
}

type Header struct {
	Alg string `json:"alg"`
	Enc string `json:"enc"`
	Iv  string `json:"iv"`
	Tag string `json:"tag"`
}

type Serialize struct {
	Iv     string
	Tag    string
	Cipher string
}

func (j *JweXChaCha20) signatureHMAC(header, payload string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(header + "." + payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
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

	// Create JWE Header
	header := Header{Alg: "dir", Enc: "XC20P", Iv: serialize.Iv, Tag: serialize.Tag}

	// Encode header as Base64
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Generate signature
	signature := j.signatureHMAC(headerB64, serialize.Cipher, key)

	// Combine header.payload.signature
	return headerB64 + "." + serialize.Cipher + "." + signature, nil
}

func (j *JweXChaCha20) Verify(token string, key []byte) bool {
	claims, err := j.Parse(token, key)

	return claims != nil && err == nil
}

func (j *JweXChaCha20) Parse(token string, key []byte) (map[string]any, error) {
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
	expectedSignature := j.signatureHMAC(headerB64, cipherB64, key)
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
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	plaintext, err := aead.Open(nil, nonce, fullCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %v", err)
	}

	// Parse the decrypted payload to check expiration time
	claims := map[string]any{}
	if err = json.Unmarshal(plaintext, &claims); err != nil {
		return nil, err
	}

	return claims, nil
}
