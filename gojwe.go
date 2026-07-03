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

// New returns a JWE implementation for the given algorithm, or nil if the
// algorithm is unknown. Optional Options tune expiry validation behavior.
//
// By default the "exp" and "nbf" claims are validated automatically during
// Parse/Verify with a DefaultLeeway tolerance. Use WithoutTimeValidation to
// opt out, or WithLeeway to change the tolerance.
func New(alg string, opts ...Option) JWE {
	o := applyOptions(opts)
	switch alg {
	case AESGCM256:
		return &JweAesGcm256{opts: o}
	case ChaCha20:
		return &JweChaCha20{opts: o}
	case XChaCha20:
		return &JweXChaCha20{opts: o}
	}
	return nil
}

// NewWithError is like New but returns ErrUnsupportedAlgorithm instead of a nil
// JWE for unknown algorithms, avoiding a later nil-pointer panic.
func NewWithError(alg string, opts ...Option) (JWE, error) {
	j := New(alg, opts...)
	if j == nil {
		return nil, ErrUnsupportedAlgorithm
	}
	return j, nil
}
