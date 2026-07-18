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

package signer

import (
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var (
	ErrTooShort = errors.New("SealedSecret data is too short")
)

func ParseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("pem block must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func certRequestToTemplate(cr *x509.CertificateRequest) *x509.Certificate {
	return &x509.Certificate{
		Subject:            cr.Subject,
		DNSNames:           cr.DNSNames,
		IPAddresses:        cr.IPAddresses,
		EmailAddresses:     cr.EmailAddresses,
		URIs:               cr.URIs,
		PublicKeyAlgorithm: cr.PublicKeyAlgorithm,
		PublicKey:          cr.PublicKey,
		Extensions:         cr.Extensions,
		ExtraExtensions:    cr.ExtraExtensions,
	}
}

func EllipticCurve(curve string) elliptic.Curve {
	switch curve {
	case "P224":
		return elliptic.P224()
	case "P256":
		return elliptic.P256()
	case "P384":
		return elliptic.P384()
	case "P521":
		return elliptic.P521()
	default:
		return nil
	}
}

func BigIntToString(i *big.Int) string {
	return fmt.Sprintf("%x", i) // hex encoding
}

func BigIntToStringColonSeparated(i *big.Int) string {
	hexStr := fmt.Sprintf("%x", i) // hex encoding
	if len(hexStr)%2 != 0 {
		hexStr = "0" + hexStr // pad with leading zero if odd length
	}
	var result strings.Builder
	for i := 0; i < len(hexStr); i += 2 {
		if i > 0 {
			result.WriteString(":")
		}
		result.WriteString(hexStr[i : i+2])
	}
	return result.String()
}

func StringToBigInt(s string) (*big.Int, error) {
	i := new(big.Int)
	if _, ok := i.SetString(s, 16); !ok {
		return nil, fmt.Errorf("invalid hex string: %q", s)
	}
	return i, nil
}
