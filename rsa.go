package rsae

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// RSA rsa
type RSA struct{}

// NewRSA new rsa
func NewRSA() *RSA {
	return &RSA{}
}

// Encrypt rsa entrypt
func (r *RSA) Encrypt(origdata string, publicKey []byte) (string, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return "", errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	pub := pubInterface.(*rsa.PublicKey)
	body, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(origdata))
	if err != nil {
		return "", err
	}
	return NewBase64().Encode(body), nil
}

// Decrypt rsa decarypt
func (r *RSA) Decrypt(ciphertext string, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	resultTemp, err := NewBase64().Decode(ciphertext)
	if err != nil {
		return "", err
	}
	body, err := rsa.DecryptPKCS1v15(rand.Reader, privInterface, resultTemp)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// Sign rsa sign
func (r *RSA) Sign(origdata string, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	digest := NewSHA().SHA256(origdata)
	body, err := rsa.SignPKCS1v15(rand.Reader, privInterface, crypto.SHA256, digest)
	if err != nil {
		return "", err
	}
	return NewBase64().Encode(body), nil
}

// Sign rsa sign
func (r *RSA) SignWithSha256(origdata string, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	privInterface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	digest := NewSHA().SHA256(origdata)
	body, err := rsa.SignPKCS1v15(rand.Reader, privInterface.(*rsa.PrivateKey), crypto.SHA256, digest)
	if err != nil {
		return "", err
	}
	return NewBase64().Encode(body), nil
}

// Verify rsa verify
func (r *RSA) Verify(origdata, ciphertext string, publicKey []byte) (bool, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return false, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	digest := NewSHA().SHA256(origdata)
	body, err := NewBase64().Decode(ciphertext)
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, body)
	if err != nil {
		return false, err
	}
	return true, nil
}
