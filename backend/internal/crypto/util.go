/*
Copyright 2025 KeyAuthority.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

	cipherData, err := (&symmetricSoftwareKey{key: key}).Encrypt(plainData)
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

	return (&symmetricSoftwareKey{key: key}).Decrypt(cipherData[pbkdf2SaltLength:])
}
