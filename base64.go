package rsae

import "encoding/base64"

// Base64 base64
type Base64 struct{}

// NewBase64 new base64
func NewBase64() *Base64 {
	return &Base64{}
}

// Encode base64 encode
func (b *Base64) Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Decode base64 descode
func (b *Base64) Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}
