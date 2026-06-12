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
	"crypto/x509"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"time"

	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	capi "k8s.io/api/certificates/v1beta1"
)

type SigningPolicy struct {
	// TTL is the certificate TTL
	MaxTTL time.Duration
	// Usages are the allowed usages of a certificate
	AllowedUsages []capi.KeyUsage
	// IsCA indicates whether the certificate is a CA certificate
	IsCA bool
	// CRL distribution points
	CDP []string
	// AIA URIs
	AIA []string
	// OCSP Servers
	OCSP []string
	// Allowed domains
	AllowedDomains []*regexp.Regexp
}

// apply applies the signing policy to the given certificate template, modifying
// it in-place. It returns an error if the template is not compliant with the
// policy.
func (p *SigningPolicy) apply(tmpl *x509.Certificate) error {
	if tmpl.NotAfter.After(tmpl.NotBefore.Add(p.MaxTTL)) {
		tmpl.NotAfter = tmpl.NotBefore.Add(p.MaxTTL)
	}
	usage, extUsages, err := keyUsagesFromStrings(p.AllowedUsages)
	if err != nil {
		return fmt.Errorf("extract key usages: %w", err)
	}
	var usageFromTemplate x509.KeyUsage
	var sortedExtUsages sortedExtKeyUsage

	for _, ext := range tmpl.Extensions {
		if u, err := cmpki.UnmarshalKeyUsage(ext.Value); err == nil {
			usageFromTemplate |= u
		}
		if eus, _, err := cmpki.UnmarshalExtKeyUsage(ext.Value); err == nil {
			for _, eu := range eus {
				if slices.Contains(extUsages, eu) && !slices.Contains(sortedExtUsages, eu) {
					sortedExtUsages = append(sortedExtUsages, eu)
				}
			}
		}
	}
	sort.Sort(sortedExtUsages)

	tmpl.KeyUsage = usage & usageFromTemplate
	tmpl.ExtKeyUsage = sortedExtUsages

	tmpl.ExtraExtensions = nil
	tmpl.Extensions = nil
	tmpl.BasicConstraintsValid = true
	tmpl.IsCA = p.IsCA
	tmpl.CRLDistributionPoints = p.CDP
	tmpl.IssuingCertificateURL = p.AIA
	tmpl.OCSPServer = p.OCSP

	for _, domain := range tmpl.DNSNames {
		allowed := false
		for _, re := range p.AllowedDomains {
			if re.MatchString(domain) {
				allowed = true
				break
			}
		}
		if len(p.AllowedDomains) > 0 && !allowed {
			return fmt.Errorf("domain not allowed: %s", domain)
		}
	}

	return nil
}

var keyUsageDict = map[capi.KeyUsage]x509.KeyUsage{
	capi.UsageSigning:           x509.KeyUsageDigitalSignature,
	capi.UsageDigitalSignature:  x509.KeyUsageDigitalSignature,
	capi.UsageContentCommitment: x509.KeyUsageContentCommitment,
	capi.UsageKeyEncipherment:   x509.KeyUsageKeyEncipherment,
	capi.UsageKeyAgreement:      x509.KeyUsageKeyAgreement,
	capi.UsageDataEncipherment:  x509.KeyUsageDataEncipherment,
	capi.UsageCertSign:          x509.KeyUsageCertSign,
	capi.UsageCRLSign:           x509.KeyUsageCRLSign,
	capi.UsageEncipherOnly:      x509.KeyUsageEncipherOnly,
	capi.UsageDecipherOnly:      x509.KeyUsageDecipherOnly,
}

var extKeyUsageDict = map[capi.KeyUsage]x509.ExtKeyUsage{
	capi.UsageAny:             x509.ExtKeyUsageAny,
	capi.UsageServerAuth:      x509.ExtKeyUsageServerAuth,
	capi.UsageClientAuth:      x509.ExtKeyUsageClientAuth,
	capi.UsageCodeSigning:     x509.ExtKeyUsageCodeSigning,
	capi.UsageEmailProtection: x509.ExtKeyUsageEmailProtection,
	capi.UsageSMIME:           x509.ExtKeyUsageEmailProtection,
	capi.UsageIPsecEndSystem:  x509.ExtKeyUsageIPSECEndSystem,
	capi.UsageIPsecTunnel:     x509.ExtKeyUsageIPSECTunnel,
	capi.UsageIPsecUser:       x509.ExtKeyUsageIPSECUser,
	capi.UsageTimestamping:    x509.ExtKeyUsageTimeStamping,
	capi.UsageOCSPSigning:     x509.ExtKeyUsageOCSPSigning,
	capi.UsageMicrosoftSGC:    x509.ExtKeyUsageMicrosoftServerGatedCrypto,
	capi.UsageNetscapeSGC:     x509.ExtKeyUsageNetscapeServerGatedCrypto,
}

// keyUsagesFromStrings will translate a slice of usage strings from the
// certificates API ("pkg/apis/certificates".KeyUsage) to x509.KeyUsage and
// x509.ExtKeyUsage types.
func keyUsagesFromStrings(usages []capi.KeyUsage) (x509.KeyUsage, []x509.ExtKeyUsage, error) {
	var keyUsage x509.KeyUsage
	var unrecognized []capi.KeyUsage
	extKeyUsages := make(map[x509.ExtKeyUsage]struct{})
	for _, usage := range usages {
		if val, ok := keyUsageDict[usage]; ok {
			keyUsage |= val
		} else if val, ok := extKeyUsageDict[usage]; ok {
			extKeyUsages[val] = struct{}{}
		} else {
			unrecognized = append(unrecognized, usage)
		}
	}

	var sorted sortedExtKeyUsage
	for eku := range extKeyUsages {
		sorted = append(sorted, eku)
	}
	sort.Sort(sorted)

	if len(unrecognized) > 0 {
		return 0, nil, fmt.Errorf("unrecognized usage values: %q", unrecognized)
	}

	return keyUsage, []x509.ExtKeyUsage(sorted), nil
}

type sortedExtKeyUsage []x509.ExtKeyUsage

func (s sortedExtKeyUsage) Len() int {
	return len(s)
}

func (s sortedExtKeyUsage) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s sortedExtKeyUsage) Less(i, j int) bool {
	return s[i] < s[j]
}
