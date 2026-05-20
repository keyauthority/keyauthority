package crypto

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

const (
	pbkdf2SaltLength = 16
	pbkdf2Iterations = 100000
	pbkdf2KeyLength  = 32
)

// EncryptWithPwd takes an input byte slice and a password, and returns the encrypted data using AES-GCM.
func EncryptWithPwd(plainData, password []byte) ([]byte, error) {
	// derive key from password
	kdfSalt := make([]byte, pbkdf2SaltLength)
	if _, err := rand.Read(kdfSalt); err != nil {
		return nil, fmt.Errorf("generate random salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, string(password), kdfSalt, pbkdf2Iterations, pbkdf2KeyLength)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	cipherData, err := (&SoftwareAESGCMKey{Key: key}).Encrypt(plainData)
	if err != nil {
		return nil, fmt.Errorf("create symmetric key: %w", err)
	}

	return append(kdfSalt, cipherData...), nil
}

// DecryptWithPwd takes an encrypted byte slice and a password, and returns the decrypted data using AES-GCM.
func DecryptWithPwd(cipherData, password []byte) ([]byte, error) {
	// derive key from password
	kdfSalt := cipherData[:pbkdf2SaltLength]
	key, err := pbkdf2.Key(sha256.New, string(password), kdfSalt, pbkdf2Iterations, pbkdf2KeyLength)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	return (&SoftwareAESGCMKey{Key: key}).Decrypt(cipherData[pbkdf2SaltLength:])
}
