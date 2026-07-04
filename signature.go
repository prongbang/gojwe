package gojwe

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
)

func HMAC(header, payload string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(header))
	mac.Write([]byte{'.'})
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// encodeHeaderB64 builds the base64url-encoded JWE header directly, avoiding the
// reflection cost of json.Marshal on the fixed 4-field Header. The field order
// (alg, enc, iv, tag) matches the Header struct so Parse can still json-decode it.
func encodeHeaderB64(enc, iv, tag string) string {
	const prefixAlg = `{"alg":"dir","enc":"`
	const midIv = `","iv":"`
	const midTag = `","tag":"`
	const suffix = `"}`

	json := make([]byte, 0, len(prefixAlg)+len(enc)+len(midIv)+len(iv)+len(midTag)+len(tag)+len(suffix))
	json = append(json, prefixAlg...)
	json = append(json, enc...)
	json = append(json, midIv...)
	json = append(json, iv...)
	json = append(json, midTag...)
	json = append(json, tag...)
	json = append(json, suffix...)

	return base64.RawURLEncoding.EncodeToString(json)
}
