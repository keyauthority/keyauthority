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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"

	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"
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

// GenerateKeyAndCSR generates a private key and a corresponding CSR based on the provided parameters.
func GenerateKeyAndCSR(commonName string, altNames []string,
	excludeCNFromSANs bool, privateKeyType string) ([]byte, *x509.CertificateRequest, error) {

	var privKey any
	var privKeyFinal []byte
	var err error

	switch privateKeyType {
	case "rsa":
		// Generate a new RSA private key
		privKey, err = rsa.GenerateKey(rand.Reader, 3072)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}
		privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey.(*rsa.PrivateKey))
		privKeyFinal = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		})
	case "ecdsa":
		// Generate a new ECDSA private key using the P-384 curve
		privKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}

		privKeyBytes, err := x509.MarshalECPrivateKey((privKey.(*ecdsa.PrivateKey)))
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal ECDSA key in DER format: %w", err)
		}
		privKeyFinal = pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privKeyBytes,
		})
	case "ed25519":
		// Generate a new Ed25519 private key
		_, privKey, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}
		privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal Ed25519 key in DER format: %w", err)
		}
		privKeyFinal = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privKeyBytes,
		})
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %s", privateKeyType)
	}

	// Create CSR template with the provided common name and alternative names
	keyUsage, err := cmpki.MarshalKeyUsage(
		x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal key usage: %w", err)
	}

	extendedKeyUsage, err := cmpki.MarshalExtKeyUsage([]x509.ExtKeyUsage{
		x509.ExtKeyUsageServerAuth,
		x509.ExtKeyUsageClientAuth,
	}, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal extended key usage: %w", err)
	}

	dnsNames := altNames
	if !excludeCNFromSANs {
		dnsNames = append([]string{commonName}, altNames...)
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		DNSNames:        dnsNames,
		ExtraExtensions: []pkix.Extension{keyUsage, extendedKeyUsage},
	}

	// Sign the CSR with the generated private key
	der, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	return privKeyFinal, csr, nil
}
