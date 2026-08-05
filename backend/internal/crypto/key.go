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
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	crypto11 "github.com/eclipse-keypont/crypto11"
	cachepkg "github.com/keyauthority/keyauthority/internal/cache"
	"github.com/pkg/errors"
	certstrap "github.com/square/certstrap/pkix"
	stepuri "go.step.sm/crypto/kms/uri"
)

var (
	Enterprise  bool
	p11CtxCache = cachepkg.NewCache()
)

type KeyType string

const (
	Unknown KeyType = ""
	RSA     KeyType = "RSA"
	ECDSA   KeyType = "ECDSA"
	Ed25519 KeyType = "Ed25519"
	AES     KeyType = "AES"
)

func (t KeyType) String() string { return string(t) }

type KeyConfig struct {
	Type         KeyType `json:"type,omitempty"`
	Bits         int     `json:"bits,omitempty"`
	Curve        string  `json:"curve,omitempty"`
	Mode         string  `json:"mode,omitempty"`
	PKCS11Uri    string  `json:"pkcs11URI,omitempty"`
	PKCS11KeyUri string  `json:"pkcs11KeyURI,omitempty"`
}

func (c *KeyConfig) IsSymmetric() bool {
	return c.Type == AES
}

type AssymmetricKey crypto.Signer

type SymmetricKey interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

type Key struct {
	// can be either an
	AssymmetricKey
	// or a
	SymmetricKey
}

func (k *Key) Public() crypto.PublicKey {
	if k == nil {
		return nil
	}
	if k.AssymmetricKey != nil {
		return k.AssymmetricKey.Public()
	}
	return nil
}

type symmetricSoftwareKey struct {
	key []byte
}

type symmetricHSMKey struct {
	mu        sync.RWMutex
	pkcs11URI string
	keyID     []byte
	label     []byte
	bits      int
	keyHandle *crypto11.SecretKey
}

type asymmetricHSMKey struct {
	mu        sync.RWMutex
	pkcs11URI string
	keyID     []byte
	label     []byte
	signer    crypto.Signer
}

func cloneBytes(v []byte) []byte {
	if v == nil {
		return nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out
}

func isRecoverableHSMError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	hints := []string{
		"ckr_device_error",
		"ckr_device_removed",
		"ckr_session",
		"ckr_token_not_present",
		"ckr_token_not_recognized",
		"pkcs11",
		"session",
		"token",
		"broken pipe",
		"connection reset",
		"timeout",
	}
	for _, h := range hints {
		if strings.Contains(msg, h) {
			return true
		}
	}
	return false
}

func (k *symmetricSoftwareKey) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher block: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	cipherData := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return cipherData, nil
}

func (k *symmetricSoftwareKey) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.key)
	if err != nil {
		return nil, fmt.Errorf("create cipher block: %w", err)
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:aesGCM.NonceSize()]
	cipherData := ciphertext[aesGCM.NonceSize():]

	plainData, err := aesGCM.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}

	return plainData, nil
}

func closeCachedP11Context(pkcs11URI string) error {
	value, exists := p11CtxCache.Get(pkcs11URI)
	if !exists {
		return nil
	}

	p11Ctx, ok := value.(*crypto11.Context)
	if !ok || p11Ctx == nil {
		return fmt.Errorf("invalid cached PKCS#11 context for %s", pkcs11URI)
	}

	if err := p11Ctx.Close(); err != nil {
		return fmt.Errorf("close PKCS#11 context: %w", err)
	}

	p11CtxCache.Delete(pkcs11URI)
	return nil
}

func (k *symmetricHSMKey) reloadHandle(resetCtx bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if resetCtx {
		_ = closeCachedP11Context(k.pkcs11URI)
	}

	p11Ctx, err := getP11Ctx(k.pkcs11URI)
	if err != nil {
		return fmt.Errorf("get PKCS11 context: %w", err)
	}

	keyHandle, err := p11Ctx.FindKey(k.keyID, k.label)
	if err != nil {
		return fmt.Errorf("find key: %w", err)
	}
	if keyHandle == nil {
		return fmt.Errorf("key not found")
	}

	k.keyHandle = keyHandle
	return nil
}

func (k *symmetricHSMKey) getHandle() *crypto11.SecretKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.keyHandle
}

func (k *symmetricHSMKey) Encrypt(plaintext []byte) ([]byte, error) {
	if k.getHandle() == nil {
		if err := k.reloadHandle(false); err != nil {
			return nil, err
		}
	}

	handle := k.getHandle()
	aesGCM, err := handle.NewGCM()
	if err != nil {
		if isRecoverableHSMError(err) {
			if rerr := k.reloadHandle(true); rerr != nil {
				return nil, fmt.Errorf("reload HSM key: %w", rerr)
			}
			handle = k.getHandle()
			aesGCM, err = handle.NewGCM()
		}
		if err != nil {
			return nil, err
		}
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (k *symmetricHSMKey) Decrypt(ciphertext []byte) ([]byte, error) {
	if k.getHandle() == nil {
		if err := k.reloadHandle(false); err != nil {
			return nil, err
		}
	}

	handle := k.getHandle()
	aesGCM, err := handle.NewGCM()
	if err != nil {
		if isRecoverableHSMError(err) {
			if rerr := k.reloadHandle(true); rerr != nil {
				return nil, fmt.Errorf("reload HSM key: %w", rerr)
			}
			handle = k.getHandle()
			aesGCM, err = handle.NewGCM()
		}
		if err != nil {
			return nil, err
		}
	}

	if len(ciphertext) < aesGCM.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:aesGCM.NonceSize()]
	cipherData := ciphertext[aesGCM.NonceSize():]

	plainData, err := aesGCM.Open(nil, nonce, cipherData, nil)
	if err != nil {
		if isRecoverableHSMError(err) {
			if rerr := k.reloadHandle(true); rerr != nil {
				return nil, fmt.Errorf("reload HSM key: %w", rerr)
			}
			handle = k.getHandle()
			aesGCM, err = handle.NewGCM()
			if err != nil {
				return nil, err
			}
			plainData, err = aesGCM.Open(nil, nonce, cipherData, nil)
		}
		if err != nil {
			return nil, fmt.Errorf("decrypt data: %w", err)
		}
	}

	return plainData, nil
}

func (k *asymmetricHSMKey) Public() crypto.PublicKey {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.signer == nil {
		return nil
	}
	return k.signer.Public()
}

func (k *asymmetricHSMKey) reloadSigner(resetCtx bool) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if resetCtx {
		_ = closeCachedP11Context(k.pkcs11URI)
	}

	p11Ctx, err := getP11Ctx(k.pkcs11URI)
	if err != nil {
		return fmt.Errorf("get PKCS11 context: %w", err)
	}

	keyHandle, err := p11Ctx.FindKeyPair(k.keyID, k.label)
	if err != nil {
		return fmt.Errorf("find key pair: %w", err)
	}
	if keyHandle == nil {
		return fmt.Errorf("key pair not found")
	}

	k.signer = keyHandle
	return nil
}

func (k *asymmetricHSMKey) getSigner() crypto.Signer {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.signer
}

func (k *asymmetricHSMKey) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if k.getSigner() == nil {
		if err := k.reloadSigner(false); err != nil {
			return nil, err
		}
	}

	s := k.getSigner()
	sig, err := s.Sign(r, digest, opts)

	if err != nil {
		if isRecoverableHSMError(err) {
			if rerr := k.reloadSigner(true); rerr != nil {
				return nil, fmt.Errorf("reload HSM signer: %w", rerr)
			}
			s = k.getSigner()
			sig, err = s.Sign(r, digest, opts)
		}
		if err != nil {
			return nil, err
		}
	}
	return sig, nil
}

// InferConfig attempts to infer the key configuration from the Key instance
func (k *Key) InferConfig() (*KeyConfig, error) {
	if k.SymmetricKey != nil {
		if softKey, ok := k.SymmetricKey.(*symmetricSoftwareKey); ok {
			return &KeyConfig{
				Type: AES,
				Mode: "GCM",
				Bits: len(softKey.key) * 8,
			}, nil
		}
		if hsmKey, ok := k.SymmetricKey.(*symmetricHSMKey); ok {
			bits := hsmKey.bits
			if bits == 0 {
				hsmKey.mu.RLock()
				if hsmKey.keyHandle != nil {
					bits = hsmKey.keyHandle.Cipher.BlockSize * 8
				}
				hsmKey.mu.RUnlock()
			}
			return &KeyConfig{
				Type: AES,
				Mode: "GCM",
				Bits: bits,
			}, nil
		}
		return nil, fmt.Errorf("unsupported symmetric key type")
	}

	// Assymmetric key
	pubKey := k.Public()
	switch pub := pubKey.(type) {
	case *rsa.PublicKey:
		return &KeyConfig{
			Type: RSA,
			Bits: pub.N.BitLen(),
		}, nil
	case *ecdsa.PublicKey:
		var curveName string
		switch pub.Curve {
		case elliptic.P224():
			curveName = "P-224"
		case elliptic.P256():
			curveName = "P-256"
		case elliptic.P384():
			curveName = "P-384"
		case elliptic.P521():
			curveName = "P-521"
		default:
			curveName = "unknown"
		}
		return &KeyConfig{
			Type:  ECDSA,
			Curve: curveName,
		}, nil
	case ed25519.PublicKey:
		return &KeyConfig{
			Type: Ed25519,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pubKey)
	}
}

// NewKey creates a new Key instance based on the provided configuration and key data
// It does not generate the key, it only loads the key based on the configuration and data
func NewKey(cfg *KeyConfig, data, password []byte) (*Key, error) {
	// HSM key
	if cfg.PKCS11Uri != "" {
		return newHSMKey(cfg)
	}

	// Software key
	return newSoftwareKey(cfg, data, password)
}

func newSoftwareKey(cfg *KeyConfig, data, password []byte) (*Key, error) {
	if cfg.IsSymmetric() {
		plainKey, err := DecryptWithPwd(data, password)
		if err != nil {
			return nil, fmt.Errorf("decrypt symmetric key: %w", err)
		}
		return &Key{SymmetricKey: &symmetricSoftwareKey{key: plainKey}}, nil
	}

	// Assymmetric key
	k, err := certstrap.NewKeyFromEncryptedPrivateKeyPEM(data, password)
	if err != nil {
		return nil, fmt.Errorf("parse encrypted software key PEM: %w", err)
	}
	// check if the key implements crypto.Signer
	if signer, ok := k.Private.(crypto.Signer); ok {
		return &Key{AssymmetricKey: signer}, nil
	}

	return nil, fmt.Errorf("unsupported key type")
}

func newHSMKey(cfg *KeyConfig) (*Key, error) {
	p11Ctx, err := getP11Ctx(cfg.PKCS11Uri)
	if err != nil {
		return nil, fmt.Errorf("get PKCS11 context: %w", err)
	}

	u, err := stepuri.ParseWithScheme("pkcs11", cfg.PKCS11KeyUri)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS11 Key URI: %w", err)
	}

	id, object := u.GetEncoded("id"), u.Get("object")
	if len(id) == 0 || object == "" {
		return nil, errors.Errorf("key with uri %s is not valid, id and object are required", cfg.PKCS11KeyUri)
	}

	label := []byte(object)

	if cfg.IsSymmetric() {
		keyHandle, err := p11Ctx.FindKey(id, label)
		if err != nil {
			return nil, fmt.Errorf("find key: %w", err)
		}
		if keyHandle == nil {
			return nil, fmt.Errorf("key not found")
		}
		return &Key{
			SymmetricKey: &symmetricHSMKey{
				pkcs11URI: cfg.PKCS11Uri,
				keyID:     cloneBytes(id),
				label:     cloneBytes(label),
				bits:      cfg.Bits,
				keyHandle: keyHandle,
			},
		}, nil

	}

	// Assymmetric key
	keyHandle, err := p11Ctx.FindKeyPair(id, label)
	if err != nil {
		return nil, fmt.Errorf("find key pair: %w", err)
	}
	if keyHandle == nil {
		return nil, fmt.Errorf("key pair not found")
	}

	return &Key{
		AssymmetricKey: &asymmetricHSMKey{
			pkcs11URI: cfg.PKCS11Uri,
			keyID:     cloneBytes(id),
			label:     cloneBytes(label),
			signer:    keyHandle,
		},
	}, nil
}

func GenerateKey(ctx context.Context, cfg *KeyConfig, password []byte) ([]byte, error) {
	// HSM key
	if cfg.PKCS11Uri != "" {
		p11Ctx, err := getP11Ctx(cfg.PKCS11Uri)
		if err != nil {
			return nil, fmt.Errorf("get PKCS11 context: %w", err)
		}
		return nil, generateHSMKey(p11Ctx, cfg)
	}

	// Software key
	if cfg.IsSymmetric() {
		var plainKey []byte
		var err error
		switch cfg.Type {
		case AES:
			switch cfg.Mode {
			case "GCM":
				// supported
			default:
				return nil, fmt.Errorf("unsupported symmetric key mode: %s", cfg.Mode)
			}
			// Generate a random AES key
			plainKey = make([]byte, cfg.Bits/8)
			if _, err = rand.Read(plainKey); err != nil {
				return nil, fmt.Errorf("generate random AES key: %w", err)
			}
		default:
			return nil, fmt.Errorf("unsupported symmetric key type: %s", cfg.Type)
		}
		return EncryptWithPwd(plainKey, password)
	}

	// Assymmetric key
	var key *certstrap.Key
	var err error
	switch cfg.Type {
	case RSA:
		if key, err = certstrap.CreateRSAKey(cfg.Bits); err != nil {
			return nil, fmt.Errorf("generate RSA key: %w", err)
		}
	case ECDSA:
		if key, err = certstrap.CreateECDSAKey(ellipticCurve(cfg.Curve)); err != nil {
			return nil, fmt.Errorf("generate ECDSA key: %w", err)
		}
	case Ed25519:
		if key, err = certstrap.CreateEd25519Key(); err != nil {
			return nil, fmt.Errorf("generate Ed25519 key: %w", err)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", cfg.Type)
	}
	return key.ExportEncryptedPrivate(password)
}

func CloseCachedP11Contexts() error {
	items := p11CtxCache.Snapshot()
	p11CtxCache.Clear()

	var firstErr error
	for _, value := range items {
		ctx, ok := value.(*crypto11.Context)
		if !ok || ctx == nil {
			continue
		}

		if err := ctx.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	return firstErr
}

func getP11Ctx(uriStr string) (*crypto11.Context, error) {
	if !Enterprise {
		return nil, fmt.Errorf("HSM keys are only supported in the Enterprise edition")
	}

	value, err := p11CtxCache.GetOrSetFunc(uriStr, func() (any, error) {
		u, err := stepuri.ParseWithScheme("pkcs11", uriStr)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS11 URI: %w", err)
		}

		// cfg.PKCS11Uri examples:
		//   - pkcs11:module-path=/usr/local/primus/lib/libprimusP11.so;slot-id=0?pin-source=/etc/primus/.pin
		//   - pkcs11:module-path=/usr/lib/softhsm/libsofthsm2.so;token=keyauthority?pin-source=/etc/softhsm/.pin

		// Get module-path
		modulePath := u.Get("module-path")
		if modulePath == "" {
			return nil, fmt.Errorf("module-path is required in PKCS11 URI")
		}

		// modulePath prefix must be in [/usr/lib/, /usr/local/, /usr/lib64/]
		modulePathPrefixes := []string{"/usr/lib/", "/usr/lib64/", "/usr/local/"}
		valid := false
		for _, prefix := range modulePathPrefixes {
			if strings.HasPrefix(modulePath, prefix) {
				valid = true
				break
			}
		}
		if !valid {
			return nil, fmt.Errorf("module-path must be under %v, got: %s", modulePathPrefixes, modulePath)
		}

		// Get PIN
		var pin string
		rawPin, pinPath := u.Get("pin"), u.Get("pin-source")
		if rawPin == "" && pinPath == "" {
			return nil, fmt.Errorf("pin or pin-source is required in PKCS11 URI")
		}
		if rawPin != "" {
			pin = rawPin
		} else {
			pinPath = strings.TrimPrefix(pinPath, "file://")
			// pinPath must be under /etc/
			if !strings.HasPrefix(pinPath, "/etc/") {
				return nil, fmt.Errorf("pin-source must be under /etc/, got: %s", pinPath)
			}
			pinBytes, err := os.ReadFile(pinPath)
			if err != nil {
				return nil, fmt.Errorf("read pin from %s: %w", pinPath, err)
			}
			pin = strings.TrimSpace(string(pinBytes))
		}

		p11Config := &crypto11.Config{
			Path: modulePath,
			Pin:  pin,
			// MaxSessions: 1024,
		}

		// Get slot-id and token
		slotIDStr, tokenLabel := u.Get("slot-id"), u.Get("token")
		if slotIDStr == "" && tokenLabel == "" {
			return nil, fmt.Errorf("one of slot-id or token must be specified in PKCS11 URI")
		}
		if slotIDStr != "" && tokenLabel != "" {
			return nil, fmt.Errorf("only one of slot-id or token can be specified in PKCS11 URI")
		}

		if slotIDStr != "" {
			var slotID int
			if _, err := fmt.Sscanf(slotIDStr, "%d", &slotID); err != nil {
				return nil, fmt.Errorf("invalid slot-id in PKCS11 URI: %w", err)
			}
			p11Config.SlotNumber = &slotID
		}

		if tokenLabel != "" {
			p11Config.TokenLabel = tokenLabel
		}

		p11Ctx, err := crypto11.Configure(p11Config)
		if err != nil {
			return nil, fmt.Errorf("configure PKCS11 context: %w", err)
		}

		return p11Ctx, nil
	})
	if err != nil {
		return nil, err
	}

	p11Ctx, ok := value.(*crypto11.Context)
	if !ok || p11Ctx == nil {
		return nil, fmt.Errorf("invalid cached PKCS#11 context for %s", uriStr)
	}

	return p11Ctx, nil
}

func extractIdAndLabel(uriStr string) ([]byte, []byte, error) {
	u, err := stepuri.ParseWithScheme("pkcs11", uriStr)
	if err != nil {
		return nil, nil, fmt.Errorf("parse PKCS11 Key URI: %w", err)
	}

	idStr, object := u.GetEncoded("id"), u.Get("object")
	if len(idStr) == 0 || object == "" {
		return nil, nil, errors.Errorf("key with uri %s is not valid, id and object are required", uriStr)
	}
	return idStr, []byte(object), nil
}

func generateHSMKey(p11 *crypto11.Context, cfg *KeyConfig) error {
	id, label, err := extractIdAndLabel(cfg.PKCS11KeyUri)
	if err != nil {
		return fmt.Errorf("extract id and label from PKCS11 Key URI: %w", err)
	}

	if cfg.IsSymmetric() {
		if keyHandle, _ := p11.FindKey(id, label); keyHandle != nil {
			//return fmt.Errorf("key already exists")
			return nil // don't return error if key already exists, just ignore it
		}

		if _, err := p11.GenerateSecretKeyWithLabel(id, label, cfg.Bits, crypto11.CipherAES); err != nil {
			return fmt.Errorf("generate symmetric key: %w", err)
		}
		return nil

	} else {
		if keyHandle, _ := p11.FindKeyPair(id, label); keyHandle != nil {
			//return fmt.Errorf("key pair already exists")
			return nil // don't return error if key pair already exists, just ignore it
		}

		switch cfg.Type {
		case RSA:
			if _, err := p11.GenerateRSAKeyPairWithLabel(id, label, cfg.Bits); err != nil {
				return fmt.Errorf("generate RSA key pair: %w", err)
			}
		case ECDSA:
			curve := ellipticCurve(cfg.Curve)
			if curve == nil {
				return fmt.Errorf("unsupported elliptic curve for HSM")
			}
			if _, err := p11.GenerateECDSAKeyPairWithLabel(id, label, curve); err != nil {
				return fmt.Errorf("generate ECDSA key pair: %w", err)
			}
		case Ed25519:
			return fmt.Errorf("unsupported signature algorithm for HSM")
		default:
			return fmt.Errorf("unsupported signature algorithm for HSM")
		}
		return nil
	}
}

func ellipticCurve(curve string) elliptic.Curve {
	switch curve {
	case "P224", "P-224", "secp224r1":
		return elliptic.P224()
	case "P256", "P-256", "secp256r1":
		return elliptic.P256()
	case "P384", "P-384", "secp384r1":
		return elliptic.P384()
	case "P521", "P-521", "secp521r1":
		return elliptic.P521()
	default:
		return nil
	}
}
