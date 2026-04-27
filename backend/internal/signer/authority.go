/*
Copyright 2023 The cert-manager Authors.

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
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"time"

	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"
)

//var SerialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

// CertificateAuthority implements a certificate authority that supports policy
// based signing. It's used by the signing controller.
type CertificateAuthority struct {
	PrivateKey  crypto.Signer
	Certificate *x509.Certificate
	Backdate    time.Duration
	Now         func() time.Time
}

// Sign signs a certificate request, applying a SigningPolicy and returns a DER
// encoded x509 certificate.
func (ca *CertificateAuthority) Sign(tmpl *x509.Certificate, ttl time.Duration, policy SigningPolicy) ([]byte, error) {
	caCert := ca.Certificate
	now := time.Now()
	if ca.Now != nil {
		now = ca.Now()
	}

	nbf := now.Add(-ca.Backdate)
	if caCert != nil && !nbf.Before(caCert.NotAfter) {
		return nil, fmt.Errorf("the signer has expired: NotAfter=%v", caCert.NotAfter)
	}
	tmpl.NotBefore = nbf
	tmpl.NotAfter = nbf.Add(ttl)

	/*serialNumber, err := rand.Int(rand.Reader, SerialNumberLimit)
	if err != nil {
		return nil, err
	}
	tmpl.SerialNumber = serialNumber*/

	if err := policy.apply(tmpl); err != nil {
		return nil, err
	}

	if caCert != nil && !tmpl.NotAfter.Before(caCert.NotAfter) {
		tmpl.NotAfter = caCert.NotAfter
	}
	if caCert != nil && !now.Before(caCert.NotAfter) {
		return nil, fmt.Errorf("refusing to sign a certificate that expired in the past")
	}

	if caCert == nil {
		// it's self-signed
		caCert = tmpl
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, tmpl.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}

	return der, nil
}

func (ca *CertificateAuthority) CreateCSR(tmpl *CATemplate) (*x509.CertificateRequest, error) {
	keyUsage, err := cmpki.MarshalKeyUsage(
		x509.KeyUsageCRLSign |
			x509.KeyUsageCertSign |
			x509.KeyUsageDigitalSignature)
	if err != nil {
		return nil, err
	}

	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         tmpl.Subject.CommonName,
			Country:            tmpl.Subject.Country,
			Organization:       tmpl.Subject.Organization,
			OrganizationalUnit: tmpl.Subject.OrganizationalUnit,
			Locality:           tmpl.Subject.Locality,
			Province:           tmpl.Subject.Province,
			StreetAddress:      tmpl.Subject.StreetAddress,
			PostalCode:         tmpl.Subject.PostalCode,
		},
		ExtraExtensions: []pkix.Extension{keyUsage},
	}

	// Sign the CSR
	der, err := x509.CreateCertificateRequest(rand.Reader, &template, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificateRequest(der)
}
