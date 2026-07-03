# gojwe

JWE (AES/GCM A256GCM, ChaCha20-Poly1305, XChaCha20-Poly1305) wrapper for Golang.

## Install

```shell
go get github.com/prongbang/gojwe
```

## How to use

## Features

- 🔒 **Secure by default** — automatic `exp` / `nbf` claim validation (with clock-skew leeway) and constant-time signature comparison to prevent timing attacks.
- ⚡ **Easy to use** — built-in key generation, typed sentinel errors for `errors.Is`, and a safe constructor.
- 🚀 **Fast** — ChaCha20 / XChaCha20 run at ~1µs/op.

## Random Secret Key

Generate a secure 32-byte key in Go (no `openssl` needed):

```go
key, err := gojwe.GenerateKey()   // returns ([]byte, error)
// or, panic on failure (handy for tests/tooling):
key := gojwe.MustGenerateKey()
```

Or from the shell:

```shell
openssl rand -hex 32
```

- Benchmark AES GCM-256

```shell
cpu: Apple M4 Pro
BenchmarkAesGcm256Generate-12    	  184796	      5714 ns/op
BenchmarkAesGcm256Parse-12       	  197023	      6048 ns/op
BenchmarkAesGcm256Verify-12      	  198123	      6033 ns/op
```

- Benchmark ChaCha20-Poly1305

```shell
cpu: Apple M4 Pro
BenchmarkChaCha20Generate-12     	 1000000	      1124 ns/op
BenchmarkChaCha20Parse-12        	 1000000	      1018 ns/op
BenchmarkChaCha20Verify-12       	 1000000	      1004 ns/op
```

- Benchmark XChaCha20-Poly1305

```shell
cpu: Apple M4 Pro
BenchmarkXChaCha20Generate-12    	  996456	      1211 ns/op
BenchmarkXChaCha20Parse-12       	 1000000	      1085 ns/op
BenchmarkXChaCha20Verify-12      	 1000000	      1087 ns/op
```

- New instance AES GCM-256

```go
j := gojwe.New(gojwe.AESGCM256)
```

- New instance ChaCha20-Poly1305

```go
j := gojwe.New(gojwe.ChaCha20)
```

- New instance XChaCha20-Poly1305

```go
j := gojwe.New(gojwe.XChaCha20)
```

- Generate

```go
key, _ := hex.DecodeString("bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1")

payload := map[string]any{
    "exp": 99999999999,
}
accessToken, err := j.Generate(payload, key)
```

- Parse

```go
key, _ := hex.DecodeString("bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1")

accessToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTk5fQ.rMKkGe6riuLZ3boYiMZsk5xrT7S-7VK6gZmFs1_7kKtVUkpvGatudYI5ZSkwIQ-iJKp2XskCxzn_6fVkCohtUQ"
payload, err := j.Parse(accessToken, key)
```

- Verify

```go
key, _ := hex.DecodeString("bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1")

accessToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTk5fQ.rMKkGe6riuLZ3boYiMZsk5xrT7S-7VK6gZmFs1_7kKtVUkpvGatudYI5ZSkwIQ-iJKp2XskCxzn_6fVkCohtUQ"
valid := j.Verify(accessToken, key)
```

## Expiration & validation

`Parse` and `Verify` automatically validate the standard time-based claims when
they are present:

- `exp` (expiration) — rejected with `ErrTokenExpired` once past.
- `nbf` (not before) — rejected with `ErrTokenNotYetValid` until reached.

A default clock-skew tolerance of 30s (`gojwe.DefaultLeeway`) is applied. Tune or
disable it via options:

```go
// Custom clock-skew tolerance
j := gojwe.New(gojwe.ChaCha20, gojwe.WithLeeway(2*time.Minute))

// Skip time validation and get raw claims back
j := gojwe.New(gojwe.ChaCha20, gojwe.WithoutTimeValidation())
```

## Registered claims (typed)

Work with the standard JWT claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`,
`jti`) as a struct instead of poking at a `map[string]any`. Embed
`RegisteredClaims` in your own type to add custom fields:

```go
type MyClaims struct {
    gojwe.RegisteredClaims
    Role string `json:"role"`
}

j := gojwe.New(gojwe.ChaCha20)

// Generate from a typed struct
token, _ := gojwe.GenerateClaims(j, MyClaims{
    RegisteredClaims: gojwe.RegisteredClaims{
        Subject:   "user-1",
        Audience:  gojwe.ClaimStrings{"api"},
        ExpiresAt: gojwe.NewNumericDate(time.Now().Add(time.Hour)),
    },
    Role: "admin",
}, key)

// Parse straight into your struct (exp/nbf are validated automatically)
claims, err := gojwe.ParseClaims[MyClaims](j, token, key)
fmt.Println(claims.Subject, claims.Role, claims.ExpiresAt.Time)
```

- `NumericDate` marshals to/from Unix seconds — use `gojwe.NewNumericDate(t)`.
- `ClaimStrings` (used by `aud`) accepts a single string or an array of strings.

## Typed errors

Handle failures precisely with `errors.Is`:

```go
claims, err := j.Parse(token, key)
switch {
case errors.Is(err, gojwe.ErrTokenExpired):
    // token expired
case errors.Is(err, gojwe.ErrInvalidSignature):
    // tampered or wrong key
case errors.Is(err, gojwe.ErrInvalidKeySize):
    // key is not 32 bytes
}
```

Available: `ErrUnsupportedAlgorithm`, `ErrInvalidKeySize`, `ErrInvalidToken`,
`ErrInvalidSignature`, `ErrTokenExpired`, `ErrTokenNotYetValid`.

## Safe constructor

`New` returns `nil` for an unknown algorithm. Use `NewWithError` to fail fast
instead of risking a nil-pointer panic:

```go
j, err := gojwe.NewWithError(alg)
if err != nil {
    // errors.Is(err, gojwe.ErrUnsupportedAlgorithm)
}
```
