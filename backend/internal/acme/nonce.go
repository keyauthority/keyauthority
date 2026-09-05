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
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"time"

	"github.com/google/uuid"
	signerpkg "github.com/keyauthority/keyauthority/internal/signer"
)

var (
	randomLimit = new(big.Int).Lsh(big.NewInt(1), 128)
)

func randomID() (string, error) {
	r, err := rand.Int(rand.Reader, randomLimit)
	if err != nil {
		return "", err
	}
	return signerpkg.BigIntToString(r), nil
}

// self-validating nonces with expiration
func generateNonce() string {
	data := map[string]any{
		"exp": time.Now().Add(10 * time.Minute).Unix(),
		"rnd": uuid.New().String(), // actual random data
	}

	jsonData, _ := json.Marshal(data)
	return base64.RawURLEncoding.EncodeToString(jsonData)
}

func validateNonce(nonce string) bool {
	decoded, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil {
		return false
	}

	var data map[string]any
	if json.Unmarshal(decoded, &data) != nil {
		return false
	}

	exp, ok := data["exp"].(float64)
	if !ok {
		return false
	}

	return time.Now().Unix() < int64(exp)
}
