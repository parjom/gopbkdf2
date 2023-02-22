package gopbkdf2

import (
	"crypto/rand"
	"encoding/base64"
	"hash"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// MinSaltSize a minimum salt size recommended by the RFC
	MinSaltSize = 8
)

type Password struct {
	HashFunc   func() hash.Hash
	SaltSize   int
	KeyLen     int
	Iterations int
}

type HashResult struct {
	CipherText string
	Salt       string
}

func NewPassword(hashFunc func() hash.Hash, saltSize int, keyLen int, iter int) *Password {
	if saltSize < MinSaltSize {
		saltSize = MinSaltSize
	}

	return &Password{
		HashFunc:   hashFunc,
		SaltSize:   saltSize,
		KeyLen:     keyLen,
		Iterations: iter,
	}
}

func (p *Password) genSalt() ([]byte, error) {
	saltBytes := make([]byte, p.SaltSize)
	_, err := rand.Read(saltBytes)
	return saltBytes, err
}

func (p *Password) GenSalt() (string, error) {
	saltBytes, err := p.genSalt()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(saltBytes), nil
}

func (p *Password) HashPassword(password string) HashResult {
	saltBytes, err := p.genSalt()
	if err != nil {
		return HashResult{CipherText: "", Salt: ""}
	}
	df := pbkdf2.Key([]byte(password), saltBytes, p.Iterations, p.KeyLen, p.HashFunc)
	cipherText := base64.StdEncoding.EncodeToString(df)
	saltString := base64.StdEncoding.EncodeToString(saltBytes)
	return HashResult{CipherText: cipherText, Salt: saltString}
}

func (p *Password) VerifyPassword(password, cipherText, salt string) bool {
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return false
	}
	df := pbkdf2.Key([]byte(password), saltBytes, p.Iterations, p.KeyLen, p.HashFunc)
	cipherText2 := base64.StdEncoding.EncodeToString(df)

	return cipherText == cipherText2
}
