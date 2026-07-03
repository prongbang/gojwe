package gojwe

import "crypto/rand"

// KeySize is the required key length in bytes for every supported algorithm.
const KeySize = 32

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
