package rsae

import "bytes"

// PKCS7 pkcs7
type PKCS7 struct{}

// NewPKCS7 new pkcs7
func NewPKCS7() *PKCS7 {
	return &PKCS7{}
}

// Padding pkcs7 padding
func (p *PKCS7) Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// UnPadding pkcs7 unpadding
func (p *PKCS7) UnPadding(plantText []byte, blockSize int) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}
