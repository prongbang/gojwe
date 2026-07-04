package gojwe_test

import (
	"errors"
	"testing"
	"time"

	"github.com/prongbang/gojwe"
)

func allAlgs() []string {
	return []string{gojwe.AESGCM256, gojwe.ChaCha20, gojwe.XChaCha20}
}

func TestGenerateKey(t *testing.T) {
	key, err := gojwe.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey() error = %v", err)
	}
	if len(key) != gojwe.KeySize {
		t.Fatalf("GenerateKey() len = %d, want %d", len(key), gojwe.KeySize)
	}

	// Two calls must not produce the same key.
	other, _ := gojwe.GenerateKey()
	if string(key) == string(other) {
		t.Fatal("GenerateKey() returned identical keys on two calls")
	}
}

func TestNewWithError_UnsupportedAlgorithm(t *testing.T) {
	if _, err := gojwe.NewWithError("nope"); !errors.Is(err, gojwe.ErrUnsupportedAlgorithm) {
		t.Fatalf("NewWithError() error = %v, want ErrUnsupportedAlgorithm", err)
	}
	if _, err := gojwe.NewWithError(gojwe.ChaCha20); err != nil {
		t.Fatalf("NewWithError() unexpected error = %v", err)
	}
}

func TestInvalidKeySize(t *testing.T) {
	shortKey := []byte("too-short")
	for _, alg := range allAlgs() {
		j := gojwe.New(alg)
		if _, err := j.Generate(map[string]any{"sub": "x"}, shortKey); !errors.Is(err, gojwe.ErrInvalidKeySize) {
			t.Fatalf("[%s] Generate() error = %v, want ErrInvalidKeySize", alg, err)
		}
		if _, err := j.Parse("a.b.c", shortKey); !errors.Is(err, gojwe.ErrInvalidKeySize) {
			t.Fatalf("[%s] Parse() error = %v, want ErrInvalidKeySize", alg, err)
		}
	}
}

func TestExpiredTokenIsRejected(t *testing.T) {
	key := gojwe.MustGenerateKey()
	for _, alg := range allAlgs() {
		j := gojwe.New(alg)
		token, err := j.Generate(map[string]any{
			"sub": "user-1",
			"exp": time.Now().Add(-time.Hour).Unix(),
		}, key)
		if err != nil {
			t.Fatalf("[%s] Generate() error = %v", alg, err)
		}

		if _, err := j.Parse(token, key); !errors.Is(err, gojwe.ErrTokenExpired) {
			t.Fatalf("[%s] Parse() error = %v, want ErrTokenExpired", alg, err)
		}
		if j.Verify(token, key) {
			t.Fatalf("[%s] Verify() = true for expired token, want false", alg)
		}
	}
}

func TestNotYetValidTokenIsRejected(t *testing.T) {
	key := gojwe.MustGenerateKey()
	for _, alg := range allAlgs() {
		j := gojwe.New(alg)
		token, _ := j.Generate(map[string]any{
			"nbf": time.Now().Add(time.Hour).Unix(),
		}, key)
		if _, err := j.Parse(token, key); !errors.Is(err, gojwe.ErrTokenNotYetValid) {
			t.Fatalf("[%s] Parse() error = %v, want ErrTokenNotYetValid", alg, err)
		}
	}
}

func TestValidTokenPasses(t *testing.T) {
	key := gojwe.MustGenerateKey()
	for _, alg := range allAlgs() {
		j := gojwe.New(alg)
		token, _ := j.Generate(map[string]any{
			"sub": "user-1",
			"exp": time.Now().Add(time.Hour).Unix(),
		}, key)
		claims, err := j.Parse(token, key)
		if err != nil {
			t.Fatalf("[%s] Parse() error = %v", alg, err)
		}
		if claims["sub"] != "user-1" {
			t.Fatalf("[%s] sub = %v, want user-1", alg, claims["sub"])
		}
		if !j.Verify(token, key) {
			t.Fatalf("[%s] Verify() = false, want true", alg)
		}
	}
}

func TestWithoutTimeValidation(t *testing.T) {
	key := gojwe.MustGenerateKey()
	for _, alg := range allAlgs() {
		gen := gojwe.New(alg)
		token, _ := gen.Generate(map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}, key)

		j := gojwe.New(alg, gojwe.WithoutTimeValidation())
		if _, err := j.Parse(token, key); err != nil {
			t.Fatalf("[%s] Parse() with WithoutTimeValidation error = %v, want nil", alg, err)
		}
	}
}

func TestWithLeeway(t *testing.T) {
	key := gojwe.MustGenerateKey()
	// Token expired 10s ago; a 30s leeway should still accept it.
	for _, alg := range allAlgs() {
		gen := gojwe.New(alg)
		token, _ := gen.Generate(map[string]any{"exp": time.Now().Add(-10 * time.Second).Unix()}, key)

		j := gojwe.New(alg, gojwe.WithLeeway(30*time.Second))
		if _, err := j.Parse(token, key); err != nil {
			t.Fatalf("[%s] Parse() with 30s leeway error = %v, want nil", alg, err)
		}
	}
}

func TestTamperedTokenIsRejected(t *testing.T) {
	key := gojwe.MustGenerateKey()
	// ChaCha20/XChaCha20 use an HMAC signature that must be rejected on tamper.
	for _, alg := range []string{gojwe.ChaCha20, gojwe.XChaCha20} {
		j := gojwe.New(alg)
		token, _ := j.Generate(map[string]any{"sub": "x", "exp": time.Now().Add(time.Hour).Unix()}, key)

		// Flip the last character of the signature.
		tampered := token[:len(token)-1]
		if token[len(token)-1] == 'A' {
			tampered += "B"
		} else {
			tampered += "A"
		}

		if _, err := j.Parse(tampered, key); !errors.Is(err, gojwe.ErrInvalidSignature) {
			t.Fatalf("[%s] Parse() error = %v, want ErrInvalidSignature", alg, err)
		}
	}
}

func TestAudienceValidation(t *testing.T) {
	key := gojwe.MustGenerateKey()
	for _, alg := range allAlgs() {
		gen := gojwe.New(alg)
		token, _ := gen.Generate(map[string]any{
			"aud": []any{"api", "web"},
			"exp": time.Now().Add(time.Hour).Unix(),
		}, key)

		// Correct audience passes.
		ok := gojwe.New(alg, gojwe.WithAudience("web"))
		if _, err := ok.Parse(token, key); err != nil {
			t.Fatalf("[%s] Parse() with matching audience error = %v", alg, err)
		}

		// Wrong audience is rejected.
		bad := gojwe.New(alg, gojwe.WithAudience("mobile"))
		if _, err := bad.Parse(token, key); !errors.Is(err, gojwe.ErrInvalidAudience) {
			t.Fatalf("[%s] Parse() error = %v, want ErrInvalidAudience", alg, err)
		}
	}
}

func TestIssuerValidation(t *testing.T) {
	key := gojwe.MustGenerateKey()
	for _, alg := range allAlgs() {
		gen := gojwe.New(alg)
		token, _ := gen.Generate(map[string]any{
			"iss": "auth.example.com",
			"exp": time.Now().Add(time.Hour).Unix(),
		}, key)

		ok := gojwe.New(alg, gojwe.WithIssuer("auth.example.com"))
		if _, err := ok.Parse(token, key); err != nil {
			t.Fatalf("[%s] Parse() with matching issuer error = %v", alg, err)
		}

		bad := gojwe.New(alg, gojwe.WithIssuer("evil.example.com"))
		if _, err := bad.Parse(token, key); !errors.Is(err, gojwe.ErrInvalidIssuer) {
			t.Fatalf("[%s] Parse() error = %v, want ErrInvalidIssuer", alg, err)
		}
	}
}

func TestIssuedAtValidation(t *testing.T) {
	key := gojwe.MustGenerateKey()
	for _, alg := range allAlgs() {
		gen := gojwe.New(alg)
		token, _ := gen.Generate(map[string]any{
			"iat": time.Now().Add(time.Hour).Unix(), // issued in the future
		}, key)

		// Off by default: future iat is tolerated.
		if _, err := gojwe.New(alg).Parse(token, key); err != nil {
			t.Fatalf("[%s] Parse() without iat validation error = %v", alg, err)
		}

		// Opt-in: future iat is rejected.
		strict := gojwe.New(alg, gojwe.WithIssuedAtValidation())
		if _, err := strict.Parse(token, key); !errors.Is(err, gojwe.ErrTokenUsedBeforeIssued) {
			t.Fatalf("[%s] Parse() error = %v, want ErrTokenUsedBeforeIssued", alg, err)
		}
	}
}

func TestWrongKeyCannotDecrypt(t *testing.T) {
	for _, alg := range allAlgs() {
		j := gojwe.New(alg)
		token, _ := j.Generate(map[string]any{"sub": "x", "exp": time.Now().Add(time.Hour).Unix()}, gojwe.MustGenerateKey())
		if _, err := j.Parse(token, gojwe.MustGenerateKey()); err == nil {
			t.Fatalf("[%s] Parse() with wrong key succeeded, want error", alg)
		}
	}
}

func TestParseClaimsAudienceValidation(t *testing.T) {
	key := gojwe.MustGenerateKey()
	j := gojwe.New(gojwe.ChaCha20, gojwe.WithAudience("api"))
	genJ := gojwe.New(gojwe.ChaCha20)

	token, _ := gojwe.GenerateClaims(genJ, gojwe.RegisteredClaims{
		Audience:  gojwe.ClaimStrings{"web"},
		ExpiresAt: gojwe.NewNumericDate(time.Now().Add(time.Hour)),
	}, key)

	if _, err := gojwe.ParseClaims[gojwe.RegisteredClaims](j, token, key); !errors.Is(err, gojwe.ErrInvalidAudience) {
		t.Fatalf("ParseClaims() error = %v, want ErrInvalidAudience", err)
	}
}
