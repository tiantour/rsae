package rsae

import (
	"crypto"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// Rsae rsae
type Rsae struct{}

// NewRsae new rsae
func NewRsae() *Rsae {
	return &Rsae{}
}

// Base64Encode base64 encode
func (r Rsae) Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

//Base64Decode base64 descode
func (r Rsae) Base64Decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// Md516 md5 16
func (r Rsae) Md516(data string) string {
	return r.Md532(data)[8:24]
}

// Md532 md5 32
func (r Rsae) Md532(data string) string {
	h := md5.New()
	h.Write([]byte(data))
	return hex.EncodeToString(h.Sum(nil))
}

// SHA1 sha1
func (r Rsae) SHA1(data string) []byte {
	h := sha1.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

// SHA256 sha256
func (r Rsae) SHA256(data string) []byte {
	h := sha256.New()
	h.Write([]byte(data))
	return h.Sum(nil)
}

// HmacSha1 hmac sha1
func (r Rsae) HmacSha1(publicKey, privateKey string) []byte {
	mac := hmac.New(sha1.New, []byte(privateKey))
	mac.Write([]byte(publicKey))
	return mac.Sum(nil)
}

// Pbkdf2Sha256 pbkdf2 sha256
func (r Rsae) Pbkdf2Sha256(data, salt string, iterations int) string {
	dk := pbkdf2.Key([]byte(data), []byte(salt), iterations, 32, sha256.New)
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", iterations, salt, base64.StdEncoding.EncodeToString(dk))
}

// Encrypt rsa entrypt
func (r Rsae) Encrypt(origdata string, publicKey []byte) (string, error) {
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
	return r.Base64Encode(body), nil
}

// Decrypt rsa decarypt
func (r Rsae) Decrypt(ciphertext string, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	resultTemp, err := r.Base64Decode(ciphertext)
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
func (r Rsae) Sign(origdata string, privateKey []byte) (string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return "", errors.New("private key error")
	}
	privInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}
	digest := r.SHA256(origdata)
	body, err := rsa.SignPKCS1v15(rand.Reader, privInterface, crypto.SHA256, digest)
	if err != nil {
		return "", err
	}
	return r.Base64Encode(body), nil
}

// Verify rsa verify
func (r Rsae) Verify(origdata, ciphertext string, publicKey []byte) (bool, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return false, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	digest := r.SHA256(origdata)
	body, err := r.Base64Decode(ciphertext)
	if err != nil {
		return false, err
	}
	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, body)
	if err != nil {
		return false, err
	}
	return true, nil
}
