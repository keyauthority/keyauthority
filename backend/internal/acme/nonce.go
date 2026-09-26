// Copyright 2025 KeyAuthority.

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
