package rsae

import (
	"crypto/md5"
	"encoding/hex"
)

// MD5 md5
type MD5 struct{}

// NewMD5 new md5
func NewMD5() *MD5 {
	return &MD5{}
}

// Encode md5 32
func (m *MD5) Encode(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}
