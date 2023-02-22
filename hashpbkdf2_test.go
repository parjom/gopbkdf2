package gopbkdf2

import (
	"crypto/sha256"
	"testing"
)

func TestPbkdf2ReturnFalse(t *testing.T) {
	pass := NewPassword(sha256.New, 16, 64, 27500)
	hashed := pass.HashPassword("p@ssw0rd")
	cipherText := hashed.CipherText
	salt := hashed.Salt

	isValid := pass.VerifyPassword("password", cipherText, salt)

	if isValid {
		t.Error("Verify Password was expected to return false : but result is ", isValid)
	}
}

func TestPbkdf2ReturnTrue(t *testing.T) {
	pass := NewPassword(sha256.New, 16, 64, 27500)
	hashed := pass.HashPassword("p@ssw0rd")
	cipherText := hashed.CipherText
	salt := hashed.Salt

	isValid := pass.VerifyPassword("p@ssw0rd", cipherText, salt)
	if !isValid {
		t.Error("Verify Password was expected to return true : but result is ", isValid)
	}
}

func TestPBKDF2Verify(t *testing.T) {
	hashIterations := 27500
	encText := "VJ46jew27TryLor/kT+JPjlWnFbtg7dnW9K2LjPBrXmGydxwzMQhRvqGh6OOFvqDRAuepj7bZYkWziq1sp7Avg=="
	saltText := "3i1KJ7d3I6exzW8fXEaUWg=="
	pass := NewPassword(sha256.New, 16, 64, hashIterations)
	pass.VerifyPassword("p@ssw0rd", encText, saltText)
}

func BenchmarkPBKDF2HashOneThousandIterations(b *testing.B) {
	pass := NewPassword(sha256.New, 16, 64, 27500)
	for i := 0; i < b.N; i++ {
		pass.HashPassword("p@ssw0rd")
	}
}

func BenchmarkPBKDF2HashFifteenThousandIterations(b *testing.B) {
	pass := NewPassword(sha256.New, 16, 64, 27500)
	for i := 0; i < b.N; i++ {
		pass.HashPassword("p@ssw0rd")
	}
}

func BenchmarkPBKDF2Verify(b *testing.B) {
	pass := NewPassword(sha256.New, 16, 64, 27500)
	hashed := pass.HashPassword("p@ssw0rd")
	cipherText := hashed.CipherText
	salt := hashed.Salt
	for i := 0; i < b.N; i++ {
		pass.VerifyPassword("p@ssw0rd", cipherText, salt)
	}
}

