package gojwe

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

// KeySize is the required key length in bytes for every supported algorithm.
const KeySize = 32

// MaxTokenBytes is the maximum accepted token length. Larger inputs are
// rejected up front as a denial-of-service guard against pathological tokens.
const MaxTokenBytes = 1 << 20 // 1 MiB

// hkdfInfo labels the derivation and pins the scheme version. Changing this
// value changes the produced tokens and breaks compatibility.
var hkdfInfo = []byte("gojwe v2 enc+mac keys")

// deriveKeys derives independent encryption and MAC keys from the 32-byte master
// key, enforcing cryptographic key separation so the same key is never used for
// both the AEAD cipher and the HMAC signature.
//
// It performs HKDF-Expand (RFC 5869) with the master key as the PRK. The HKDF
// extract step is intentionally skipped: it is only needed to whiten weak input
// key material, and this package requires a full-length 32-byte key (see
// GenerateKey), which is already a uniformly strong key per RFC 5869 §3.3.
func deriveKeys(master []byte) (encKey, macKey []byte) {
	mac := hmac.New(sha256.New, master)

	// T(1) = HMAC(master, info | 0x01) -> encryption key
	mac.Write(hkdfInfo)
	mac.Write([]byte{0x01})
	encKey = mac.Sum(nil)

	// T(2) = HMAC(master, T(1) | info | 0x02) -> MAC key
	mac.Reset()
	mac.Write(encKey)
	mac.Write(hkdfInfo)
	mac.Write([]byte{0x02})
	macKey = mac.Sum(nil)

	return encKey, macKey
}

// GenerateKey returns a cryptographically secure random 32-byte key,
// suitable for any algorithm supported by this package. It replaces the
// need to run "openssl rand -hex 32" manually.
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// MustGenerateKey is like GenerateKey but panics on error. Handy for tests
// and one-off tooling where a failed CSPRNG read is unrecoverable anyway.
func MustGenerateKey() []byte {
	key, err := GenerateKey()
	if err != nil {
		panic(err)
	}
	return key
}

// validateKey ensures the key is exactly KeySize bytes.
func validateKey(key []byte) error {
	if len(key) != KeySize {
		return ErrInvalidKeySize
	}
	return nil
}
