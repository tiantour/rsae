package rsae

import (
	"crypto/aes"
	"crypto/cipher"
)

// AES aes
type AES struct{}

// NewAES new aes
func NewAES() *AES {
	return &AES{}
}

// Encrypt aes encrypt
func (a *AES) Encrypt(plantText, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plantText = NewPKCS7().Padding(plantText, block.BlockSize())
	blockModel := cipher.NewCBCEncrypter(block, iv)
	ciphertext := make([]byte, len(plantText))
	blockModel.CryptBlocks(ciphertext, plantText)
	return ciphertext, nil
}

// Decrypt aes decrypt
func (a *AES) Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockModel := cipher.NewCBCDecrypter(block, iv)
	plantText := make([]byte, len(ciphertext))
	blockModel.CryptBlocks(plantText, ciphertext)
	plantText = NewPKCS7().UnPadding(plantText, block.BlockSize())
	return plantText, nil
}

// ECBEncrypt aes encrypt ecb
func (a *AES) ECBEncrypt(plantText, key []byte) ([]byte, error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return nil, err
	}
	plantText = NewPKCS7().Padding(plantText, block.BlockSize())
	blockModel := NewECBEncrypter(block)
	ciphertext := make([]byte, len(plantText))
	blockModel.CryptBlocks(ciphertext, plantText)
	return ciphertext, nil
}

// ECBDecrypt aes decrypt ecb
func (a *AES) ECBDecrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockMode := NewECBEncrypter(block)
	plantText := make([]byte, len(ciphertext))
	blockMode.CryptBlocks(plantText, ciphertext)
	plantText = NewPKCS7().UnPadding(plantText, block.BlockSize())
	return plantText, nil
}
