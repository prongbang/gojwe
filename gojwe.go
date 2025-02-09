package gojwe

const (
	AESGCM256 = "AES-GCM-256"
	ChaCha20  = "ChaCha20"
	XChaCha20 = "XChaCha20"
)

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

type JWE interface {
	Generate(payload map[string]any, key []byte) (string, error)
	Verify(token string, key []byte) bool
	Parse(token string, key []byte) (map[string]any, error)
}

func New(alg string) JWE {
	switch alg {
	case AESGCM256:
		return &JweAesGcm256{}
	case ChaCha20:
		return &JweChaCha20{}
	case XChaCha20:
		return &JweXChaCha20{}
	}
	return nil
}
