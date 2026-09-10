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

package acme

import (
	"crypto/x509"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type Order struct {
	Cert            []*x509.Certificate
	Status          string // pending, ready, processing, valid, invalid
	NotAfter        time.Time
	ExpiresAt       time.Time
	VerifiedDomains map[string]bool
	Tokens          []string
}

type OrderStore struct {
	sync.Mutex
	orders map[string]*Order
}

type Challenge struct {
	Status           string //pending, processing, valid, invalid
	Token            string
	KeyAuthorization string
	Domain           string
	ExpiresAt        time.Time
}

type ChallengeStore struct {
	sync.Mutex
	challenges map[string]*Challenge
}

type JWSRequest struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

type JWSProtected struct {
	Algorithm string           `json:"alg"`
	Nonce     string           `json:"nonce,omitempty"`
	URL       string           `json:"url,omitempty"`
	KeyID     string           `json:"kid,omitempty"`
	JWK       *jose.JSONWebKey `json:"jwk,omitempty"`
}
