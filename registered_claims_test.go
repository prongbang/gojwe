package gojwe_test

import (
	"errors"
	"testing"
	"time"

	"github.com/prongbang/gojwe"
)

func TestRegisteredClaimsRoundTrip(t *testing.T) {
	key := gojwe.MustGenerateKey()
	for _, alg := range allAlgs() {
		j := gojwe.New(alg)

		want := gojwe.RegisteredClaims{
			Issuer:    "auth.example.com",
			Subject:   "user-1",
			Audience:  gojwe.ClaimStrings{"api", "web"},
			ID:        "token-123",
			IssuedAt:  gojwe.NewNumericDate(time.Now()),
			ExpiresAt: gojwe.NewNumericDate(time.Now().Add(time.Hour)),
		}

		token, err := gojwe.GenerateClaims(j, want, key)
		if err != nil {
			t.Fatalf("[%s] GenerateClaims() error = %v", alg, err)
		}

		got, err := gojwe.ParseClaims[gojwe.RegisteredClaims](j, token, key)
		if err != nil {
			t.Fatalf("[%s] ParseClaims() error = %v", alg, err)
		}

		if got.Issuer != want.Issuer || got.Subject != want.Subject || got.ID != want.ID {
			t.Fatalf("[%s] string claims mismatch: got %+v", alg, got)
		}
		if len(got.Audience) != 2 || got.Audience[0] != "api" || got.Audience[1] != "web" {
			t.Fatalf("[%s] audience mismatch: got %v", alg, got.Audience)
		}
		if got.ExpiresAt == nil || !got.ExpiresAt.Equal(want.ExpiresAt.Time) {
			t.Fatalf("[%s] exp mismatch: got %v want %v", alg, got.ExpiresAt, want.ExpiresAt)
		}
	}
}

func TestParseClaimsCustomStruct(t *testing.T) {
	type MyClaims struct {
		gojwe.RegisteredClaims
		Role  string   `json:"role"`
		Scope []string `json:"scope"`
	}

	key := gojwe.MustGenerateKey()
	j := gojwe.New(gojwe.ChaCha20)

	in := MyClaims{
		RegisteredClaims: gojwe.RegisteredClaims{
			Subject:   "user-9",
			ExpiresAt: gojwe.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Role:  "admin",
		Scope: []string{"read", "write"},
	}

	token, err := gojwe.GenerateClaims(j, in, key)
	if err != nil {
		t.Fatalf("GenerateClaims() error = %v", err)
	}

	got, err := gojwe.ParseClaims[MyClaims](j, token, key)
	if err != nil {
		t.Fatalf("ParseClaims() error = %v", err)
	}
	if got.Subject != "user-9" || got.Role != "admin" {
		t.Fatalf("claims mismatch: got %+v", got)
	}
	if len(got.Scope) != 2 || got.Scope[0] != "read" {
		t.Fatalf("scope mismatch: got %v", got.Scope)
	}
}

func TestParseClaimsExpired(t *testing.T) {
	key := gojwe.MustGenerateKey()
	j := gojwe.New(gojwe.XChaCha20)

	token, _ := gojwe.GenerateClaims(j, gojwe.RegisteredClaims{
		ExpiresAt: gojwe.NewNumericDate(time.Now().Add(-time.Hour)),
	}, key)

	if _, err := gojwe.ParseClaims[gojwe.RegisteredClaims](j, token, key); !errors.Is(err, gojwe.ErrTokenExpired) {
		t.Fatalf("ParseClaims() error = %v, want ErrTokenExpired", err)
	}
}

func TestAudienceSingleString(t *testing.T) {
	key := gojwe.MustGenerateKey()
	j := gojwe.New(gojwe.ChaCha20)

	token, _ := gojwe.GenerateClaims(j, gojwe.RegisteredClaims{
		Audience:  gojwe.ClaimStrings{"only-one"},
		ExpiresAt: gojwe.NewNumericDate(time.Now().Add(time.Hour)),
	}, key)

	got, err := gojwe.ParseClaims[gojwe.RegisteredClaims](j, token, key)
	if err != nil {
		t.Fatalf("ParseClaims() error = %v", err)
	}
	if len(got.Audience) != 1 || got.Audience[0] != "only-one" {
		t.Fatalf("audience mismatch: got %v", got.Audience)
	}
}
