/*
BSD 2-Clause License

Copyright (c) 2018, Digitorus
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

package signer

import (
	"crypto"
	"crypto/x509"
	"errors"
	"time"

	"github.com/digitorus/pdfsign/sign"
)

type SigningOptions struct {
	// Input/Output files
	InputFile  string `json:"inputFile"`
	OutputFile string `json:"outputFile"`

	// Signature Info
	Signer      string `json:"signer"`
	Reason      string `json:"reason,omitempty"`
	Location    string `json:"location,omitempty"`
	ContactInfo string `json:"contactInfo,omitempty"`

	// Timestamp Authority
	TSA string `json:"tsa,omitempty"`

	// Crypto Options
	HashAlgo string `json:"hashAlgo,omitempty"`
}

func SignPDF(privateKey crypto.Signer, certificate *x509.Certificate, chain []*x509.Certificate, opts SigningOptions) error {
	hash := crypto.SHA256
	switch opts.HashAlgo {
	case "SHA256", "":
		hash = crypto.SHA256
	case "SHA384":
		hash = crypto.SHA384
	case "SHA512":
		hash = crypto.SHA512
	default:
		return errors.New("unsupported hash algorithm")
	}

	return sign.SignFile(opts.InputFile, opts.OutputFile, sign.SignData{
		Signature: sign.SignDataSignature{
			Info: sign.SignDataSignatureInfo{
				Name:        opts.Signer,
				Location:    opts.Location,
				Reason:      opts.Reason,
				ContactInfo: opts.ContactInfo,
				Date:        time.Now().Local(),
			},
			CertType: sign.CertificationSignature,
			// DocMDPPerm: sign.AllowFillingExistingFormFieldsAndSignaturesPerms,
		},
		Signer:            privateKey,
		DigestAlgorithm:   hash,
		CertificateChains: [][]*x509.Certificate{chain},
		Certificate:       certificate,
		TSA: sign.TSA{
			URL: opts.TSA,
		},
	})
}
