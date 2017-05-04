package rsae

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/tiantour/conf"
	"github.com/tiantour/imago"
)

// RSA rsa
var RSA = &rsae{}

type rsae struct{}

// Encrypt
func (r *rsae) Encrypt(origdata string) (result string, err error) {
	publicKey, err := imago.File.Read(conf.Data.RSA.PublicKey)
	if err != nil {
		return
	}
	block, _ := pem.Decode(publicKey)
	if block == nil {
		err = errors.New("public key error")
		return
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}
	pub := pubInterface.(*rsa.PublicKey)
	resultByte, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(origdata))
	if err != nil {
		return
	}
	result = imago.Crypto.Base64Encode(resultByte)
	return
}

// Decrypt
func (r *rsae) Decrypt(ciphertext string) (result string, err error) {
	privateKey, err := imago.File.Read(conf.Data.RSA.PrivateKey)
	if err != nil {
		return
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		err = errors.New("private key error")
		return
	}
	privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	resultTemp, err := imago.Crypto.Base64Decode(ciphertext)
	if err != nil {
		return
	}
	resultByte, err := rsa.DecryptPKCS1v15(rand.Reader, privInterface, resultTemp)
	if err != nil {
		return
	}
	result = string(resultByte)
	return
}

// Sign
func (r *rsae) Sign(origdata string) (result string, err error) {
	privateKey, err := imago.File.Read(conf.Data.RSA.PrivateKey)
	if err != nil {
		return
	}
	block, _ := pem.Decode(privateKey)
	if block == nil {
		err = errors.New("private key error")
		return
	}
	privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return
	}
	digest := imago.Crypto.SHA1(origdata)
	resultByte, err := rsa.SignPKCS1v15(rand.Reader, privInterface, crypto.SHA1, digest)
	if err != nil {
		return
	}
	result = imago.Crypto.Base64Encode(resultByte)
	return
}

// Verify
func (r *rsae) Verify(origdata, ciphertext string) (status bool, err error) {
	publicKey, err := imago.File.Read(conf.Data.RSA.PublicKey)
	if err != nil {
		return
	}
	block, _ := pem.Decode(publicKey)
	if block == nil {
		err = errors.New("public key error")
		return
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return
	}
	pub := pubInterface.(*rsa.PublicKey)
	digest := imago.Crypto.SHA1(origdata)
	resultTemp, err := imago.Crypto.Base64Decode(ciphertext)
	if err != nil {
		return
	}
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA1, digest, resultTemp)
	if err != nil {
		return
	}
	status = true
	return
}
