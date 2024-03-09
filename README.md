# gojwe

JWE (AES/GCM A256GCM) wrapper for Golang.

## Install

```shell
go get github.com/prongbang/gojwe
```

## How to use

- Random Secret Key

```shell
openssl rand -hex 32
```

- New instance

```go
j := gojwe.New()
```

- Generate

```go
payload := map[string]any{
    "exp": 99999999999,
}
key := "bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1"
accessToken, err := j.Generate(payload, key)
```

- Parse

```go
key := "bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1"
accessToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTk5fQ.rMKkGe6riuLZ3boYiMZsk5xrT7S-7VK6gZmFs1_7kKtVUkpvGatudYI5ZSkwIQ-iJKp2XskCxzn_6fVkCohtUQ"
payload, err := j.Parse(accessToken, key)
```

- Verify

```go
key := "bdacaf398071931518f73917cb0c6f04b3a0ab45ee9cbedc258047a8c149a3e1"
accessToken := "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjk5OTk5OTk5OTk5fQ.rMKkGe6riuLZ3boYiMZsk5xrT7S-7VK6gZmFs1_7kKtVUkpvGatudYI5ZSkwIQ-iJKp2XskCxzn_6fVkCohtUQ"
valid := j.Verify(accessToken, key)
```
