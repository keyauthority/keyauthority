// Copyright 2025 KeyAuthority.

package signer

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"
	"time"

	capi "k8s.io/api/certificates/v1beta1"
)

type IgnoreCAChainErrors bool

type RevocationPair struct {
	Serial string `json:"serial"`
	Reason int    `json:"reason"`
}

type PKIXName struct {
	CommonName         string   `json:"commonName,omitempty"`
	Country            []string `json:"country,omitempty"`
	Organization       []string `json:"organization,omitempty"`
	OrganizationalUnit []string `json:"organizationalUnit,omitempty"`
	Locality           []string `json:"locality,omitempty"`
	Province           []string `json:"province,omitempty"`
	StreetAddress      []string `json:"streetAddress,omitempty"`
	PostalCode         []string `json:"postalCode,omitempty"`
}

type CATemplate struct {
	Subject *PKIXName `json:"subject"`
}

type SignerConfig struct {
	// CA Template
	CATemplate *CATemplate `json:"caTemplate"`

	// Certificate Template
	IsCA bool     `json:"isCA,omitempty"`
	CDP  []string `json:"cdp,omitempty"`
	AIA  []string `json:"aia,omitempty"`
	OCSP []string `json:"ocsp,omitempty"`

	// Signing Policy
	MaxTTL           string          `json:"maxTTL,omitempty"`
	AllowedKeyUsages []capi.KeyUsage `json:"allowedKeyUsages,omitempty"`
	AllowedDomains   []string        `json:"allowedDomains,omitempty"`
}

type Signer struct {
	CAChain    []string
	CATemplate *CATemplate
	CA         *CertificateAuthority
	Policy     *SigningPolicy
}

func NewSigner(cfg *SignerConfig, privKey crypto.Signer, caChain []byte, args ...any) (*Signer, error) {
	maxTTL, err := time.ParseDuration(cfg.MaxTTL)
	if err != nil {
		return nil, err
	}

	allowedDomains := make([]*regexp.Regexp, len(cfg.AllowedDomains))
	for i, allowedDomain := range cfg.AllowedDomains {
		if allowedDomains[i], err = regexp.Compile(allowedDomain); err != nil {
			return nil, err
		}
	}

	s := &Signer{
		CA: &CertificateAuthority{
			PrivateKey: privKey,
			Backdate:   time.Minute * 5,
			// Now:        time.Now,
		},
		CATemplate: cfg.CATemplate,
		Policy: &SigningPolicy{
			MaxTTL:         maxTTL,
			AllowedUsages:  cfg.AllowedKeyUsages,
			IsCA:           cfg.IsCA,
			CDP:            cfg.CDP,
			AIA:            cfg.AIA,
			OCSP:           cfg.OCSP,
			AllowedDomains: allowedDomains,
		},
	}

	if err := s.SetCAChain(caChain); err != nil && len(args) > 0 {
		for _, arg := range args {
			if ignoreError, ok := arg.(IgnoreCAChainErrors); ok && !bool(ignoreError) {
				return nil, fmt.Errorf("set CA chain: %w", err)
			}
		}
	}

	return s, nil
}

func (s *Signer) CreateCSR() ([]byte, error) {
	cr, err := s.CA.CreateCSR(s.CATemplate)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: cr.Raw,
	}), nil
}

func (s *Signer) ClearCAChain() {
	s.CA.Certificate = nil
	s.CAChain = nil
}

func (s *Signer) SetCAChain(data []byte) error {
	var caChain []string
	var firstCert *x509.Certificate
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse certificate in CA chain: %w", err)
		}
		if !cert.IsCA {
			return fmt.Errorf("non-CA certificate found in CA chain")
		}

		caChain = append(caChain, strings.TrimSpace(string(pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: cert.Raw,
			}))))

		if firstCert == nil {
			firstCert = cert
		}
	}
	if len(caChain) == 0 {
		return fmt.Errorf("empty chain")
	}
	if !s.ValidateCACertificate(firstCert) {
		return fmt.Errorf("certificate does not match private key")
	}

	s.CA.Certificate = firstCert
	s.CAChain = caChain
	return nil
}

func (s *Signer) ValidateCACertificate(cert *x509.Certificate) bool {
	if cert == nil || s.CA.PrivateKey == nil {
		return false
	}

	switch caKey := s.CA.PrivateKey.(type) {
	case *rsa.PrivateKey:
		pubKey, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return pubKey.N.Cmp(caKey.PublicKey.N) == 0

	case *ecdsa.PrivateKey:
		pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return pubKey.X.Cmp(caKey.PublicKey.X) == 0 && pubKey.Y.Cmp(caKey.PublicKey.Y) == 0

	case ed25519.PrivateKey:
		pubKey, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return bytes.Equal(pubKey, caKey.Public().(ed25519.PublicKey))

	default:
		return true // it's probably a valid HSM key
	}
}

func (s *Signer) Sign(cr *x509.CertificateRequest, ttl time.Duration) (*x509.Certificate, []string, error) {
	tmpl := certRequestToTemplate(cr)
	certDER, err := s.CA.Sign(tmpl, ttl, s.Policy)
	if err != nil {
		return nil, nil, fmt.Errorf("sign certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse signed certificate: %w", err)
	}

	certPEM := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})))

	return cert, append([]string{certPEM}, s.CAChain...), nil
}

func (s *Signer) SignCRL(existingCRL []byte, additional []RevocationPair) ([]byte, error) {
	if s.CA.Certificate == nil {
		return nil, errors.New("missing CA certificate")
	}
	revokedEntries := []x509.RevocationListEntry{}

	if len(existingCRL) > 0 {
		crl, err := x509.ParseRevocationList(existingCRL)
		if err != nil {
			return nil, fmt.Errorf("parse existing CRL: %w", err)
		}
		revokedEntries = crl.RevokedCertificateEntries
	}

	now := time.Now()
	for _, pair := range additional {
		i, err := StringToBigInt(pair.Serial)
		if err != nil {
			return nil, err
		}
		revokedEntries = append(revokedEntries, x509.RevocationListEntry{
			SerialNumber:   i,
			ReasonCode:     pair.Reason,
			RevocationTime: now,
		})
	}

	newCRL, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		// SignatureAlgorithm:        s.CA.Certificate.SignatureAlgorithm,
		RevokedCertificateEntries: revokedEntries,
		Number:                    big.NewInt(now.Unix()), // or track a counter
		ThisUpdate:                now,
		NextUpdate:                now.Add(72 * time.Hour),
	}, s.CA.Certificate, s.CA.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create CRL: %w", err)
	}

	return newCRL, nil
}
