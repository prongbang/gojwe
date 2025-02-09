package gojwe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func HMAC(header, payload string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(header + "." + payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
