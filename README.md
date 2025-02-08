# gojwe

JWE (AES/GCM A256GCM, XChaCha20-Poly1305) wrapper for Golang.

## Install

```shell
go get github.com/prongbang/gojwe
```

## How to use

- Random Secret Key

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
