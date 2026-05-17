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
	"os"
	"strings"
	"sync"

	"github.com/pkg/errors"

	thalesp11 "github.com/ThalesGroup/crypto11"
	certstrap "github.com/square/certstrap/pkix"
	stepuri "go.step.sm/crypto/kms/uri"
)

type hsmConnections struct {
	sync.RWMutex
	connections map[string]*thalesp11.Context
}

var (
	Enterprise bool
	hsmConns   = &hsmConnections{
		connections: make(map[string]*thalesp11.Context),
	}
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
	AssymmetricKey
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

type SoftwareAESGCMKey struct {
	Key []byte
}

func (k *SoftwareAESGCMKey) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.Key)
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

func (k *SoftwareAESGCMKey) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.Key)
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

type HSMAESGCMKey struct {
	KeyHandle *thalesp11.SecretKey
}

func (k *HSMAESGCMKey) Encrypt(plaintext []byte) ([]byte, error) {
	aesGCM, err := k.KeyHandle.NewGCM()
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (k *HSMAESGCMKey) Decrypt(ciphertext []byte) ([]byte, error) {
	aesGCM, err := k.KeyHandle.NewGCM()
	if err != nil {
		return nil, err
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

// InferConfig attempts to infer the key configuration from the Key instance
func (k *Key) InferConfig() (*KeyConfig, error) {
	if k.SymmetricKey != nil {
		if softKey, ok := k.SymmetricKey.(*SoftwareAESGCMKey); ok {
			return &KeyConfig{
				Type: AES,
				Mode: "GCM",
				Bits: len(softKey.Key) * 8,
			}, nil
		}
		if hsmKey, ok := k.SymmetricKey.(*HSMAESGCMKey); ok {
			return &KeyConfig{
				Type: AES,
				Mode: "GCM",
				Bits: hsmKey.KeyHandle.Cipher.BlockSize * 8,
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
func NewKey(ctx context.Context, cfg *KeyConfig, data, password []byte) (*Key, error) {
	// HSM key
	if cfg.PKCS11Uri != "" {
		return NewHSMKey(cfg)
	}

	// Software key
	return NewSoftwareKey(cfg, data, password)
}

func NewSoftwareKey(cfg *KeyConfig, data, password []byte) (*Key, error) {
	if cfg.IsSymmetric() {
		plainKey, err := DecryptWithPwd(data, password)
		if err != nil {
			return nil, fmt.Errorf("decrypt symmetric key: %w", err)
		}
		return &Key{SymmetricKey: &SoftwareAESGCMKey{Key: plainKey}}, nil
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

func GenerateKey(ctx context.Context, cfg *KeyConfig, password []byte) ([]byte, error) {
	// HSM key
	if cfg.PKCS11Uri != "" {
		p11, err := getToken(cfg.PKCS11Uri)
		if err != nil {
			return nil, fmt.Errorf("get PKCS11 token: %w", err)
		}
		return nil, generateHSMKey(p11, cfg)
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

func NewHSMKey(cfg *KeyConfig) (*Key, error) {
	p11, err := getToken(cfg.PKCS11Uri)
	if err != nil {
		return nil, fmt.Errorf("get PKCS11 token: %w", err)
	}

	u, err := stepuri.ParseWithScheme("pkcs11", cfg.PKCS11KeyUri)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS11 Key URI: %w", err)
	}

	id, object := u.GetEncoded("id"), u.Get("object")
	if len(id) == 0 || object == "" {
		return nil, errors.Errorf("key with uri %s is not valid, id and object are required", cfg.PKCS11KeyUri)
	}

	if cfg.IsSymmetric() {
		keyHandle, err := p11.FindKey(id, []byte(object))
		if err != nil {
			return nil, fmt.Errorf("find key: %w", err)
		}
		if keyHandle == nil {
			return nil, fmt.Errorf("key not found")
		}
		return &Key{
			SymmetricKey: &HSMAESGCMKey{KeyHandle: keyHandle},
		}, nil

	}

	// Assymmetric key
	keyHandle, err := p11.FindKeyPair(id, []byte(object))
	if err != nil {
		return nil, fmt.Errorf("find key pair: %w", err)
	}
	if keyHandle == nil {
		return nil, fmt.Errorf("key pair not found")
	}

	return &Key{
		AssymmetricKey: keyHandle,
	}, nil
}

func createNewToken(uriStr string) (*thalesp11.Context, error) {
	if !Enterprise {
		return nil, fmt.Errorf("HSM keys are only supported in the Enterprise edition")
	}

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
		pinBytes, err := os.ReadFile(pinPath)
		if err != nil {
			return nil, fmt.Errorf("read pin from %s: %w", pinPath, err)
		}
		pin = strings.TrimSpace(string(pinBytes))
	}

	p11Config := &thalesp11.Config{
		Path:        modulePath,
		Pin:         pin,
		MaxSessions: 1024,
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

	p11, err := thalesp11.Configure(p11Config)
	if err != nil {
		return nil, fmt.Errorf("configure PKCS11: %w", err)
	}
	hsmConns.connections[uriStr] = p11
	return p11, nil
}

func getToken(uriStr string) (*thalesp11.Context, error) {
	if !Enterprise {
		return nil, fmt.Errorf("HSM keys are only supported in the Enterprise edition")
	}
	hsmConns.Lock()
	defer hsmConns.Unlock()

	if token, ok := hsmConns.connections[uriStr]; ok {
		return token, nil
	}

	token, err := createNewToken(uriStr)
	if err != nil {
		return nil, fmt.Errorf("create PKCS11 token: %w", err)
	}
	hsmConns.connections[uriStr] = token
	return token, nil
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

func generateHSMKey(p11 *thalesp11.Context, cfg *KeyConfig) error {
	id, label, err := extractIdAndLabel(cfg.PKCS11KeyUri)
	if err != nil {
		return fmt.Errorf("extract id and label from PKCS11 Key URI: %w", err)
	}

	if cfg.IsSymmetric() {
		if keyHandle, _ := p11.FindKey(id, label); keyHandle != nil {
			//return fmt.Errorf("key already exists")
			return nil // don't return error if key already exists, just ignore it
		}

		if _, err := p11.GenerateSecretKeyWithLabel(id, label, cfg.Bits, thalesp11.CipherAES); err != nil {
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
