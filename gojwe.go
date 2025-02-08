package gojwe

const (
	AESGCM256 = "AES-GCM-256"
	XChaCha20 = "XChaCha20"
)

type JWE interface {
	Generate(payload map[string]any, key []byte) (string, error)
	Verify(token string, key []byte) bool
	Parse(token string, key []byte) (map[string]any, error)
}

func New(alg string) JWE {
	switch alg {
	case AESGCM256:
		return &JweAesGcm256{}
	case XChaCha20:
		return &JweXChaCha20{}
	}
	return nil
}
