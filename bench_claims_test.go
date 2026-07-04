package gojwe_test

import (
	"testing"
	"time"

	"github.com/prongbang/gojwe"
)

func benchClaims() gojwe.RegisteredClaims {
	return gojwe.RegisteredClaims{
		Issuer:    "auth.example.com",
		Subject:   "user-1",
		Audience:  gojwe.ClaimStrings{"api"},
		ExpiresAt: gojwe.NewNumericDate(time.Unix(9999999999, 0)),
	}
}

func BenchmarkGenerateClaims(b *testing.B) {
	j := gojwe.New(gojwe.ChaCha20)
	key := gojwe.MustGenerateKey()
	c := benchClaims()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gojwe.GenerateClaims(j, c, key)
	}
}

func BenchmarkParseClaims(b *testing.B) {
	j := gojwe.New(gojwe.ChaCha20)
	key := gojwe.MustGenerateKey()
	token, _ := gojwe.GenerateClaims(j, benchClaims(), key)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = gojwe.ParseClaims[gojwe.RegisteredClaims](j, token, key)
	}
}
