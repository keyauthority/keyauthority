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

package internal

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	iofs "github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/keyauthority/keyauthority/migrations"

	_ "github.com/jackc/pgx/v5/stdlib"
	cachepkg "github.com/keyauthority/keyauthority/internal/cache"
	cryptopkg "github.com/keyauthority/keyauthority/internal/crypto"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
	metricspkg "github.com/keyauthority/keyauthority/internal/metrics"
	signerpkg "github.com/keyauthority/keyauthority/internal/signer"
)

const (
	// general env
	envSoftwareKeyPass string = "SOFTWARE_KEY_PASSPHRASE"

	// PostgreSQL env
	envPGHost     string = "POSTGRESQL_HOST"
	envPGPort     string = "POSTGRESQL_PORT_NUMBER"
	envPGUser     string = "POSTGRESQL_USER"
	envPGPassword string = "POSTGRESQL_PASSWORD"
	envPGDatabase string = "POSTGRESQL_DATABASE"
	envPGSSLMode  string = "POSTGRESQL_SSLMODE"
	envPGRootCert string = "POSTGRESQL_ROOT_CERT"
)

var (
	keyCache    = cachepkg.NewCache()
	crlCache    = cachepkg.NewCache()
	caCertCache = cachepkg.NewCache()
)

// actual data used for replaying pending requests upon approval
type PendingRequestPrivate struct {
	Method string
	URL    *url.URL
	Header http.Header
	Body   []byte
}

type PendingRequestPublic struct {
	ID          uuid.UUID      `json:"id"`
	CreatedAt   time.Time      `json:"createdAt"`
	PrivateBody bool           `json:"privateBody"`
	Method      string         `json:"method"`
	URL         string         `json:"url"`
	TokenInfo   map[string]any `json:"token"`
}

type Store struct {
	DB              *sql.DB
	SoftwareKeyPass []byte
}

func NewStore(ctx context.Context) (*Store, error) {
	softwareKeyPass := []byte(os.Getenv(envSoftwareKeyPass))
	if len(softwareKeyPass) == 0 {
		return nil, fmt.Errorf("missing required env var: %s", envSoftwareKeyPass)
	}

	host := os.Getenv(envPGHost)
	port := os.Getenv(envPGPort)
	user := os.Getenv(envPGUser)
	password := os.Getenv(envPGPassword)
	database := os.Getenv(envPGDatabase)
	sslMode := os.Getenv(envPGSSLMode)
	rootCert := os.Getenv(envPGRootCert)

	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s",
		user, password, host, port, database)

	if sslMode != "" {
		dsn += "?sslmode=" + sslMode
	}

	if sslMode == "verify-full" && rootCert != "" {
		dsn += "&sslrootcert=" + rootCert
	}

	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("connect to DB: %w", err)
	}

	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return &Store{DB: db, SoftwareKeyPass: softwareKeyPass}, nil
}

func (s *Store) Close() error {
	// close DB first to prevent new key loads
	var dbErr error
	if s.DB != nil {
		dbErr = s.DB.Close()
	}

	// then close any cached PKCS#11 contexts
	hsErr := cryptopkg.CloseCachedP11Contexts()

	if dbErr != nil {
		return dbErr
	}
	return hsErr
}

/*****************************************************/
/*                 Helper Functions                  */
/*****************************************************/

func runMigrations(db *sql.DB) error {
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("postgres driver: %w", err)
	}

	d, err := iofs.New(migrations.Files, ".")
	if err != nil {
		return fmt.Errorf("migration source: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", d, "postgres", driver)
	if err != nil {
		return fmt.Errorf("new migrate: %w", err)
	}

	err = m.Up()
	if err == migrate.ErrNoChange {
		return nil
	}
	return err
}

func withKeyConfigDefaults(cfg *cryptopkg.KeyConfig) (*cryptopkg.KeyConfig, error) {
	if cfg == nil {
		return nil, fmt.Errorf("key config is required")
	}

	cleanCfg := &cryptopkg.KeyConfig{}
	switch cfg.Type {
	case cryptopkg.RSA:
		bits := cfg.Bits
		if bits == 0 {
			bits = 2048
		}
		cleanCfg = &cryptopkg.KeyConfig{
			Type: cryptopkg.RSA,
			Bits: bits,
		}

	case cryptopkg.ECDSA:
		curve := cfg.Curve
		if curve == "" {
			curve = "P-256"
		}
		cleanCfg = &cryptopkg.KeyConfig{
			Type:  cryptopkg.ECDSA,
			Curve: curve,
		}

	case cryptopkg.Ed25519:
		cleanCfg = &cryptopkg.KeyConfig{
			Type: cryptopkg.Ed25519,
		}

	case cryptopkg.AES:
		bits := cfg.Bits
		if bits == 0 {
			bits = 256
		}
		mode := cfg.Mode
		if mode == "" {
			mode = "GCM"
		}
		cleanCfg = &cryptopkg.KeyConfig{
			Type: cryptopkg.AES,
			Bits: bits,
			Mode: mode,
		}

	default:
		return nil, fmt.Errorf("unsupported key type: %s", cfg.Type)
	}

	if cfg.PKCS11Uri != "" {
		cleanCfg.PKCS11Uri = cfg.PKCS11Uri
		cleanCfg.PKCS11KeyUri = cfg.PKCS11KeyUri
	}

	return cleanCfg, nil
}

func withSignerConfigDefaults(cfg *signerpkg.SignerConfig) *signerpkg.SignerConfig {
	if cfg == nil {
		cfg = &signerpkg.SignerConfig{}
	}
	if cfg.CATemplate == nil {
		cfg.CATemplate = &signerpkg.CATemplate{}
	}
	if cfg.CATemplate.Subject == nil {
		cfg.CATemplate.Subject = &signerpkg.PKIXName{}
	}
	return cfg
}

func parseTime(q url.Values, key string) *time.Time {
	val := q.Get(key)
	if val == "" {
		return nil
	}
	// value is in RFC3339 format (e.g. 2026-06-01T15:13:07.236Z)
	t, err := time.Parse(time.RFC3339, val)
	if err != nil {
		return nil
	}
	return &t
}

func parseBool(q url.Values, key string) *bool {
	val := q.Get(key)
	if val == "" {
		return nil
	}
	b, err := strconv.ParseBool(val)
	if err != nil {
		return nil
	}
	return &b
}

func applyPagination(query string, args []any, idx int, filters url.Values) (string, []any, int, int, int) {
	limit := 20
	offset := 0
	if v := filters.Get("pageSize"); v != "" {
		if l, err := strconv.Atoi(v); err == nil && l > 0 {
			limit = l
		}
	}
	if v := filters.Get("page"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 1 {
			offset = (p - 1) * limit
		}
	}
	if limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d", idx)
		args = append(args, limit)
		idx++
	}
	if offset > 0 {
		query += fmt.Sprintf(" OFFSET $%d", idx)
		args = append(args, offset)
		idx++
	}
	return query, args, idx, limit, offset
}

func applyEnvRestrictions(query string, args []any, idx int, hasAccessToAllEnvs bool, accessibleEnvs []string) (string, []any, int) {
	if hasAccessToAllEnvs {
		return query, args, idx
	}

	if len(accessibleEnvs) == 0 {
		// if user doesn't have access to any envs, add a condition that will always be false
		query += " AND 1=0"
		return query, args, idx
	}

	placeholders := make([]string, len(accessibleEnvs))
	for i, e := range accessibleEnvs {
		placeholders[i] = fmt.Sprintf("$%d", idx)
		args = append(args, e)
		idx++
	}
	query += fmt.Sprintf(" AND keys.environment IN (%s)", strings.Join(placeholders, ", "))

	return query, args, idx
}

/*****************************************************/
/*             Key Management Functions              */
/*****************************************************/

func applyKeyFilters(query string, args []any, idx int, filters url.Values) (string, []any, int) {
	if idFilter := filters.Get("id"); idFilter != "" {
		query += fmt.Sprintf(" AND id::text ILIKE $%d", idx)
		args = append(args, "%"+idFilter+"%")
		idx++
	}

	if typeFilter := filters.Get("type"); typeFilter != "" {
		query += fmt.Sprintf(" AND config->>'type' ILIKE $%d", idx)
		args = append(args, "%"+typeFilter+"%")
		idx++
	}

	if storageFilter := filters.Get("storage"); storageFilter != "" {
		query += fmt.Sprintf(" AND (CASE WHEN config ? 'pkcs11URI' THEN 'HSM' ELSE 'Software' END) ILIKE $%d", idx)
		args = append(args, "%"+storageFilter+"%")
		idx++
	}

	if envFilter := filters.Get("environment"); envFilter != "" {
		query += fmt.Sprintf(" AND environment ILIKE $%d", idx)
		args = append(args, "%"+envFilter+"%")
		idx++
	}
	return query, args, idx
}

func (s *Store) GetKeys(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) ([]map[string]any, int, int, error) {
	query := `SELECT id, environment, config, created_at FROM keys WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyEnvRestrictions(query, args, idx, hasAccessToAllEnvs, accessibleEnvs)
	query, args, idx = applyKeyFilters(query, args, idx, filters)

	query += " ORDER BY created_at DESC"

	query, args, idx, limit, offset := applyPagination(query, args, idx, filters)

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("query keys: %w", err)
	}
	defer rows.Close()

	keys := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var env string
		var cfgJSON []byte
		var createdAt time.Time
		if err := rows.Scan(&id, &env, &cfgJSON, &createdAt); err != nil {
			return nil, 0, 0, fmt.Errorf("scan key: %w", err)
		}
		var cfg cryptopkg.KeyConfig
		if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
			return nil, 0, 0, fmt.Errorf("unmarshal key config: %w", err)
		}

		keys = append(keys, map[string]any{
			// metadata
			"id":          id,
			"environment": env,
			"createdAt":   createdAt,
			// data
			"config": &cfg,
		})
	}
	return keys, limit, offset, nil
}

func (s *Store) CountKeys(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) (int, error) {
	query := `SELECT COUNT(id) FROM keys WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyEnvRestrictions(query, args, idx, hasAccessToAllEnvs, accessibleEnvs)
	query, args, idx = applyKeyFilters(query, args, idx, filters)

	var count int
	err := s.DB.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count keys: %w", err)
	}
	return count, nil
}

func (s *Store) CreateKey(ctx context.Context, env string, cfg *cryptopkg.KeyConfig, createdBy string) (uuid.UUID, error) {
	// marshal config
	if cleanCfg, err := withKeyConfigDefaults(cfg); err != nil {
		return uuid.Nil, fmt.Errorf("apply key config defaults: %w", err)
	} else {
		cfg = cleanCfg
	}

	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal key config: %w", err)
	}

	softwareKey, err := cryptopkg.GenerateKey(ctx, cfg, s.SoftwareKeyPass)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create key: %w", err)
	}

	var id uuid.UUID
	if err := s.DB.QueryRowContext(ctx, `
    INSERT INTO keys (environment, config, software_key, created_by)
    VALUES ($1, $2, $3, $4)
    RETURNING id
`, env, cfgJSON, softwareKey, createdBy).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("insert key: %w", err)
	}
	return id, nil
}

func (s *Store) GetKey(ctx context.Context, id uuid.UUID) (map[string]any, error) {
	var cfgJSON []byte
	var createdAt time.Time
	var env string
	if err := s.DB.QueryRowContext(ctx, `
		SELECT environment, config, created_at
		FROM keys
		WHERE id = $1
	`, id).Scan(&env, &cfgJSON, &createdAt); err != nil {
		return nil, fmt.Errorf("get key config: %w", err)
	}
	var cfg cryptopkg.KeyConfig
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal key config: %w", err)
	}
	return map[string]any{
		"id":          id,
		"environment": env,
		"config":      &cfg,
		"createdAt":   createdAt,
	}, nil
}

func (s *Store) LoadKey(ctx context.Context, id uuid.UUID) (*cryptopkg.Key, error) {
	if cachedKey, found := keyCache.Get(id.String()); found {
		return cachedKey.(*cryptopkg.Key), nil
	}

	var cfgJSON []byte
	var softwareKey []byte
	if err := s.DB.QueryRowContext(ctx, `
		SELECT config, software_key
		FROM keys
		WHERE id = $1
	`, id).Scan(&cfgJSON, &softwareKey); err != nil {
		return nil, fmt.Errorf("get key: %w", err)
	}
	var cfg cryptopkg.KeyConfig
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		return nil, fmt.Errorf("invalid key config: %w", err)
	}
	key, err := cryptopkg.NewKey(&cfg, softwareKey, s.SoftwareKeyPass)
	if err != nil {
		return nil, err
	}

	//keyCache.SetWithTTL(id.String(), key, 30*time.Minute)
	keyCache.Set(id.String(), key)
	return key, nil
}

func (s *Store) CheckKeyReadiness(ctx context.Context, id uuid.UUID) error {
	key, err := s.LoadKey(ctx, id)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	if key.AssymmetricKey != nil {
		// key is assymetric, try to create a CSR
		if _, err := x509.CreateCertificateRequest(rand.Reader,
			&x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "test",
				},
			},
			key.AssymmetricKey); err != nil {
			return fmt.Errorf("create CSR with key: %w", err)
		}
	} else if key.SymmetricKey != nil {
		// key is symmetric, try to encrypt some test data
		if _, err := key.Encrypt([]byte("test")); err != nil {
			return fmt.Errorf("encrypt with key: %w", err)
		}
	} else {
		return fmt.Errorf("key has no usable material")
	}

	return nil
}

func (s *Store) GetKeyEnvironment(ctx context.Context, id uuid.UUID) (string, error) {
	var env string
	if err := s.DB.QueryRowContext(ctx, `
		SELECT environment
		FROM keys
		WHERE id = $1
	`, id).Scan(&env); err != nil {
		return "", fmt.Errorf("get key environment: %w", err)
	}
	return env, nil
}

func (s *Store) DeleteKey(ctx context.Context, id uuid.UUID) error {
	_, err := s.DB.ExecContext(ctx, `
		DELETE FROM keys
		WHERE id = $1
	`, id)
	if err == nil {
		keyCache.Delete(id.String())
	}
	return err
}

/*****************************************************/
/*            Signer Management Functions            */
/*****************************************************/

func applySignerFilters(query string, args []any, idx int, filters url.Values) (string, []any, int) {
	if nameFilter := filters.Get("name"); nameFilter != "" {
		query += fmt.Sprintf(" AND signers.name ILIKE $%d", idx)
		args = append(args, "%"+nameFilter+"%")
		idx++
	}
	if envFilter := filters.Get("environment"); envFilter != "" {
		query += fmt.Sprintf(" AND keys.environment ILIKE $%d", idx)
		args = append(args, "%"+envFilter+"%")
		idx++
	}
	if privateKeyID := filters.Get("privateKeyID"); privateKeyID != "" {
		query += fmt.Sprintf(" AND signers.private_key_id::text ILIKE $%d", idx)
		args = append(args, "%"+privateKeyID+"%")
		idx++
	}
	if isRoot := parseBool(filters, "isRoot"); isRoot != nil {
		// isRoot is either true or false, which we determine based on whether the signer has a CA template with a subject defined
		if *isRoot {
			query += " AND (signers.config->'isCA' = 'true')"
		} else {
			query += " AND (signers.config->'isCA' = 'false' OR signers.config->'isCA' IS NULL)"
		}
	}
	return query, args, idx
}

func (s *Store) GetSigners(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) ([]map[string]any, int, int, error) {
	query := `SELECT keys.environment, signers.name, signers.private_key_id, signers.config, signers.updated_at FROM signers JOIN keys ON signers.private_key_id = keys.id WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyEnvRestrictions(query, args, idx, hasAccessToAllEnvs, accessibleEnvs)
	query, args, idx = applySignerFilters(query, args, idx, filters)

	query += " ORDER BY signers.name ASC"

	query, args, idx, limit, offset := applyPagination(query, args, idx, filters)

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("query signers: %w", err)
	}
	defer rows.Close()
	signers := []map[string]any{}
	for rows.Next() {
		var environment string
		var name string
		var kid uuid.UUID
		var cfgJSON []byte
		var updatedAt time.Time
		if err := rows.Scan(&environment, &name, &kid, &cfgJSON, &updatedAt); err != nil {
			return nil, 0, 0, fmt.Errorf("scan signer: %w", err)
		}
		var cfg signerpkg.SignerConfig
		if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
			return nil, 0, 0, fmt.Errorf("unmarshal signer config: %w", err)
		}
		signers = append(signers, map[string]any{
			// metadata
			"name":         name,
			"environment":  environment,
			"privateKeyID": kid,
			"updatedAt":    updatedAt,
			// data (partially, excluding CA chain and CRL which are loaded separately)
			"config": &cfg,
		})
	}
	return signers, limit, offset, nil
}

func (s *Store) CountSigners(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) (int, error) {
	query := `SELECT COUNT(signers.name) FROM signers JOIN keys ON signers.private_key_id = keys.id WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyEnvRestrictions(query, args, idx, hasAccessToAllEnvs, accessibleEnvs)
	query, args, idx = applySignerFilters(query, args, idx, filters)

	var count int
	err := s.DB.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count signers: %w", err)
	}
	return count, nil
}

func (s *Store) CreateSigner(ctx context.Context, name string, keyID uuid.UUID, cfg *signerpkg.SignerConfig) error {
	// check if signer already exists
	var exists bool
	if err := s.DB.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM signers
			WHERE name = $1
		)
	`, name).Scan(&exists); err != nil {
		return fmt.Errorf("check if signer exists: %w", err)
	}
	if exists {
		return fmt.Errorf("signer already exists: %s", name)
	}

	// verify key exists and loads
	_, err := s.LoadKey(ctx, keyID)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	// marshal config
	cfgJSON, err := json.Marshal(withSignerConfigDefaults(cfg))
	if err != nil {
		return fmt.Errorf("marshal signer config: %w", err)
	}

	// insert signer
	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO signers (name, private_key_id, config)
		VALUES ($1, $2, $3)
	`, name, keyID, cfgJSON)
	return err
}

func (s *Store) DeleteSigner(ctx context.Context, name string) error {
	_, err := s.DB.ExecContext(ctx, `
		DELETE FROM signers
		WHERE name = $1
	`, name)
	return err
}

func (s *Store) GetPrivateKeyID(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	if err := s.DB.QueryRowContext(ctx, `
		SELECT private_key_id
		FROM signers
		WHERE name = $1
	`, name).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("get private key ID for signer: %w", err)
	}
	return id, nil
}

func (s *Store) GetSignerConfig(ctx context.Context, name string) (*signerpkg.SignerConfig, error) {
	var cfgJSON []byte
	if err := s.DB.QueryRowContext(ctx, `
		SELECT config
		FROM signers
		WHERE name = $1
	`, name).Scan(&cfgJSON); err != nil {
		return nil, fmt.Errorf("get signer config: %w", err)
	}
	var cfg signerpkg.SignerConfig
	if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshal signer config: %w", err)
	}
	return &cfg, nil
}

func (s *Store) SetSignerConfig(ctx context.Context, name string, cfg *signerpkg.SignerConfig) error {
	// marshal config
	cfgJSON, err := json.Marshal(withSignerConfigDefaults(cfg))
	if err != nil {
		return err
	}

	_, err = s.DB.ExecContext(ctx, `
		UPDATE signers
		SET config = $2, updated_at = now()
		WHERE name = $1
	`, name, cfgJSON)
	return err
}

func (s *Store) GetSignerCAChain(ctx context.Context, name string) ([]byte, error) {
	var caChain []byte
	if err := s.DB.QueryRowContext(ctx, `
		SELECT ca_chain
		FROM signers
		WHERE name = $1
	`, name).Scan(&caChain); err != nil {
		return nil, fmt.Errorf("get signer CA chain: %w", err)
	}
	return caChain, nil
}

func (s *Store) GetSignerCACertByHash(ctx context.Context, hash string) ([]byte, error) {
	if cachedCACert, found := caCertCache.Get(hash); found {
		return cachedCACert.([]byte), nil
	}

	var caChain []byte
	if err := s.DB.QueryRowContext(ctx, `
		SELECT ca_chain
		FROM signers
		WHERE name_hash = $1
	`, hash).Scan(&caChain); err != nil {
		return nil, fmt.Errorf("get signer CA chain: %w", err)
	}

	var block *pem.Block
	block, _ = pem.Decode(caChain)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM in CA chain")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate in CA chain: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	caCertCache.SetWithTTL(hash, caCertPEM, 1*time.Hour)
	return caCertPEM, nil
}

func (s *Store) SetSignerCAChain(ctx context.Context, name string, caChain []byte) error {
	var hash string
	if err := s.DB.QueryRowContext(ctx, `
		UPDATE signers
		SET ca_chain = $2, updated_at = now()
		WHERE name = $1
		RETURNING name_hash
	`, name, caChain).Scan(&hash); err != nil {
		return err
	}

	caCertCache.Delete(hash)
	return nil
}

func (s *Store) GetSignerCRL(ctx context.Context, name string) ([]byte, error) {
	var crl []byte
	if err := s.DB.QueryRowContext(ctx, `
		SELECT crl
		FROM signers
		WHERE name = $1
	`, name).Scan(&crl); err != nil {
		return nil, fmt.Errorf("get signer CRL: %w", err)
	}
	return crl, nil
}

func (s *Store) GetSignerCRLByHash(ctx context.Context, hash string) ([]byte, error) {
	if cachedCRL, found := crlCache.Get(hash); found {
		return cachedCRL.([]byte), nil
	}

	var crl []byte
	if err := s.DB.QueryRowContext(ctx, `
		SELECT crl
		FROM signers
		WHERE name_hash = $1
  `, hash).Scan(&crl); err != nil {
		return nil, fmt.Errorf("get signer CRL: %w", err)
	}

	crlCache.SetWithTTL(hash, crl, 1*time.Hour)
	return crl, nil
}

func (s *Store) SetSignerCRL(ctx context.Context, name string, der []byte) error {
	var hash string
	if err := s.DB.QueryRowContext(ctx, `
		UPDATE signers
		SET crl = $2
		WHERE name = $1
		RETURNING name_hash
  `, name, der).Scan(&hash); err != nil {
		return fmt.Errorf("set signer CRL: %w", err)
	}

	crlCache.Delete(hash)
	return nil
}

func (s *Store) LoadSigner(ctx context.Context, name string, args ...any) (*signerpkg.Signer, error) {
	pvkID, err := s.GetPrivateKeyID(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get signer private key ID: %w", err)
	}
	pvk, err := s.LoadKey(ctx, pvkID)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}

	cfg, err := s.GetSignerConfig(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get signer config: %w", err)
	}

	caChain, err := s.GetSignerCAChain(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get signer CA chain: %w", err)
	}

	// create signer object
	signer, err := signerpkg.NewSigner(cfg, pvk.AssymmetricKey, caChain, args...)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	// assign CA chain
	if len(caChain) > 0 {
		signer.SetCAChain(caChain)
	}
	return signer, nil
}

/*****************************************************/
/*             Cert Management Functions             */
/*****************************************************/

func applyCertFilters(query string, args []any, idx int, filters url.Values) (string, []any, int) {
	if serial := filters.Get("serial"); serial != "" {
		query += fmt.Sprintf(" AND certs.serial ILIKE $%d", idx)
		args = append(args, "%"+serial+"%")
		idx++
	}
	if signerName := filters.Get("signerName"); signerName != "" {
		query += fmt.Sprintf(" AND certs.signer_name ILIKE $%d", idx)
		args = append(args, "%"+signerName+"%")
		idx++
	}
	if cn := filters.Get("cn"); cn != "" {
		query += fmt.Sprintf(" AND certs.cn ILIKE $%d", idx)
		args = append(args, "%"+cn+"%")
		idx++
	}
	if san := filters.Get("san"); san != "" {
		query += fmt.Sprintf(" AND EXISTS (SELECT 1 FROM unnest(certs.sans) AS s WHERE s ILIKE $%d)", idx)
		args = append(args, "%"+san+"%")
		idx++
	}
	if comment := filters.Get("comment"); comment != "" {
		query += fmt.Sprintf(" AND certs.comment ILIKE $%d", idx)
		args = append(args, "%"+comment+"%")
		idx++
	}
	if notBeforeFrom := parseTime(filters, "notBeforeFrom"); notBeforeFrom != nil {
		query += fmt.Sprintf(" AND certs.not_before >= $%d", idx)
		args = append(args, *notBeforeFrom)
		idx++
	}
	if notBeforeTo := parseTime(filters, "notBeforeTo"); notBeforeTo != nil {
		query += fmt.Sprintf(" AND certs.not_before <= $%d", idx)
		args = append(args, *notBeforeTo)
		idx++
	}
	if notAfterFrom := parseTime(filters, "notAfterFrom"); notAfterFrom != nil {
		query += fmt.Sprintf(" AND certs.not_after >= $%d", idx)
		args = append(args, *notAfterFrom)
		idx++
	}
	if notAfterTo := parseTime(filters, "notAfterTo"); notAfterTo != nil {
		query += fmt.Sprintf(" AND certs.not_after <= $%d", idx)
		args = append(args, *notAfterTo)
		idx++
	}
	if revoked := parseBool(filters, "revoked"); revoked != nil {
		query += fmt.Sprintf(" AND certs.revoked = $%d", idx)
		args = append(args, *revoked)
		idx++
	}
	return query, args, idx
}

func (s *Store) GetCerts(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) ([]map[string]any, int, int, error) {
	query := `SELECT certs.serial, certs.signer_name, certs.cn, certs.sans, certs.not_before, certs.not_after, certs.revoked, certs.comment, keys.environment
        FROM certs
        JOIN signers ON certs.signer_name = signers.name
        JOIN keys ON signers.private_key_id = keys.id
        WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyEnvRestrictions(query, args, idx, hasAccessToAllEnvs, accessibleEnvs)
	query, args, idx = applyCertFilters(query, args, idx, filters)

	query += " ORDER BY certs.not_before DESC"

	query, args, idx, limit, offset := applyPagination(query, args, idx, filters)

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()

	certs := []map[string]any{}
	for rows.Next() {
		var serial string
		var signerName string
		var cn string
		var sans pq.StringArray
		var notBefore time.Time
		var notAfter time.Time
		var revoked bool
		var comment string
		var environment string

		if err := rows.Scan(&serial, &signerName, &cn, &sans, &notBefore, &notAfter, &revoked, &comment, &environment); err != nil {
			return nil, 0, 0, err
		}

		certs = append(certs, map[string]any{
			"serial":      serial,
			"signerName":  signerName,
			"cn":          cn,
			"sans":        sans,
			"notBefore":   notBefore,
			"notAfter":    notAfter,
			"revoked":     revoked,
			"comment":     comment,
			"environment": environment,
		})
	}
	return certs, limit, offset, nil
}

func (s *Store) CountCerts(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) (int, error) {
	query := `SELECT COUNT(certs.serial)
        FROM certs
        JOIN signers ON certs.signer_name = signers.name
        JOIN keys ON signers.private_key_id = keys.id
        WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyEnvRestrictions(query, args, idx, hasAccessToAllEnvs, accessibleEnvs)
	query, args, idx = applyCertFilters(query, args, idx, filters)

	var count int
	err := s.DB.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) InsertCert(ctx context.Context, signerName string, cert *x509.Certificate, comment string) error {
	cn := cert.Subject.CommonName
	sans := append(cert.DNSNames, cert.EmailAddresses...)
	der := cert.Raw
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	serial := signerpkg.BigIntToString(cert.SerialNumber)

	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO certs (
			serial, signer_name, cn, sans, der, not_before, not_after, revoked, comment
		) VALUES ($1, $2, $3, $4, $5, $6, $7, false, $8)
	`, serial, signerName, cn, sans, der, notBefore, notAfter, comment)
	return err
}

func (s *Store) SetCertAsRevoked(ctx context.Context, serial string) error {
	res, err := s.DB.ExecContext(ctx, `
		UPDATE certs
		SET revoked = true
		WHERE serial = $1
	`, serial)
	if err != nil {
		return err
	}

	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("could not set certificate as revoked: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("certificate not found: %q", serial)
	}
	return nil
}

func (s *Store) GetCertPEM(ctx context.Context, serial string) ([]byte, error) {
	var der []byte
	if err := s.DB.QueryRowContext(ctx, `
		SELECT der FROM certs WHERE serial = $1
	`, serial).Scan(&der); err != nil {
		return nil, err
	}
	// convert to PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: der,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

/*****************************************************/
/*             Secret Management Functions           */
/*****************************************************/

func applySecretFilters(query string, args []any, idx int, filters url.Values) (string, []any, int) {
	if name := filters.Get("name"); name != "" {
		query += fmt.Sprintf(" AND secrets.name ILIKE $%d", idx)
		args = append(args, "%"+name+"%")
		idx++
	}
	if environment := filters.Get("environment"); environment != "" {
		query += fmt.Sprintf(" AND keys.environment ILIKE $%d", idx)
		args = append(args, "%"+environment+"%")
		idx++
	}
	if keyID := filters.Get("encryptionKeyID"); keyID != "" {
		query += fmt.Sprintf(" AND secrets.encryption_key_id::text ILIKE $%d", idx)
		args = append(args, "%"+keyID+"%")
		idx++
	}
	if updatedFrom := parseTime(filters, "updatedFrom"); updatedFrom != nil {
		query += fmt.Sprintf(" AND secrets.updated_at >= $%d", idx)
		args = append(args, *updatedFrom)
		idx++
	}
	return query, args, idx
}

func (s *Store) GetEncryptionKeyID(ctx context.Context, name string) (uuid.UUID, error) {
	var id uuid.UUID
	err := s.DB.QueryRowContext(ctx, `
		SELECT encryption_key_id
		FROM secrets
		WHERE name = $1
	`, name).Scan(&id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("get encryption key ID for secret: %w", err)
	}
	return id, nil
}

func (s *Store) GetSecrets(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) ([]map[string]any, int, int, error) {
	query := "SELECT keys.environment, secrets.name, secrets.encryption_key_id, secrets.updated_at FROM secrets JOIN keys ON secrets.encryption_key_id = keys.id WHERE 1=1"
	args := []any{}
	idx := 1

	query, args, idx = applyEnvRestrictions(query, args, idx, hasAccessToAllEnvs, accessibleEnvs)
	query, args, idx = applySecretFilters(query, args, idx, filters)

	query += " ORDER BY secrets.updated_at DESC"

	query, args, idx, limit, offset := applyPagination(query, args, idx, filters)

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()

	secrets := []map[string]any{}
	for rows.Next() {
		var environment string
		var name string
		var kid uuid.UUID
		var updatedAt time.Time
		if err := rows.Scan(&environment, &name, &kid, &updatedAt); err != nil {
			return nil, 0, 0, err
		}
		secrets = append(secrets, map[string]any{
			// metadata
			"name":            name,
			"environment":     environment,
			"encryptionKeyID": kid,
			"updatedAt":       updatedAt,
			// data (not including encrypted data which is loaded separately)
		})
	}
	return secrets, limit, offset, nil
}

func (s *Store) CountSecrets(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) (int, error) {
	query := "SELECT COUNT(secrets.name) FROM secrets JOIN keys ON secrets.encryption_key_id = keys.id WHERE 1=1"
	args := []any{}
	idx := 1

	query, args, idx = applyEnvRestrictions(query, args, idx, hasAccessToAllEnvs, accessibleEnvs)
	query, args, idx = applySecretFilters(query, args, idx, filters)

	var count int
	if err := s.DB.QueryRowContext(ctx, query, args...).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) InsertSecret(ctx context.Context, name string, encryptionKeyID uuid.UUID, data map[string]string) error {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal secret data: %w", err)
	}

	key, err := s.LoadKey(ctx, encryptionKeyID)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	ct, err := key.Encrypt(dataBytes)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	_, err = s.DB.ExecContext(ctx, `
		INSERT INTO secrets (name, encryption_key_id, data)
		VALUES ($1, $2, $3)
	`, name, encryptionKeyID, ct)
	return err
}

func (s *Store) GetSecret(ctx context.Context, name string) (map[string]any, error) {
	var ct []byte
	var environment string
	var keyID uuid.UUID
	var updatedAt time.Time
	if err := s.DB.QueryRowContext(ctx, `
		SELECT keys.environment, secrets.encryption_key_id, secrets.data, secrets.updated_at 
		FROM secrets 
		JOIN keys ON secrets.encryption_key_id = keys.id
		WHERE secrets.name = $1
	`, name).Scan(&environment, &keyID, &ct, &updatedAt); err != nil {
		return nil, fmt.Errorf("get secret: %w", err)
	}

	key, err := s.LoadKey(ctx, keyID)
	if err != nil {
		return nil, fmt.Errorf("load key: %w", err)
	}

	pt, err := key.Decrypt(ct)
	if err != nil {
		return nil, fmt.Errorf("decrypt secret: %w", err)
	}

	var data map[string]string
	if err := json.Unmarshal(pt, &data); err != nil {
		return nil, fmt.Errorf("unmarshal secret data: %w", err)
	}

	resp := map[string]any{
		// metadata
		"name":            name,
		"environment":     environment,
		"encryptionKeyID": keyID,
		"updatedAt":       updatedAt,
		// data
		"data": data,
	}

	return resp, nil
}

func (s *Store) UpdateSecret(ctx context.Context, name string, newData map[string]string, patch bool) error {
	secret, err := s.GetSecret(ctx, name)
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}
	data, ok := secret["data"].(map[string]string)
	if !ok {
		return fmt.Errorf("invalid secret data type")
	}
	encryptionKeyID, ok := secret["encryptionKeyID"].(uuid.UUID)
	if !ok {
		return fmt.Errorf("invalid encryption key ID type")
	}
	if patch {
		// merge existing data with new data (new data takes precedence)
		for k, v := range data {
			if _, ok := newData[k]; !ok {
				newData[k] = v
			}
		}
	}
	dataBytes, err := json.Marshal(newData)
	if err != nil {
		return fmt.Errorf("marshal secret data: %w", err)
	}

	key, err := s.LoadKey(ctx, encryptionKeyID)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}

	ct, err := key.Encrypt(dataBytes)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}

	res, err := s.DB.ExecContext(ctx, `
		UPDATE secrets
		SET data = $1, updated_at = now()
		WHERE name = $2
	`, ct, name)
	if err != nil {
		return fmt.Errorf("update secret: %w", err)
	}

	rowsAffected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return fmt.Errorf("no rows affected: %s", name)
	}

	return nil
}

func (s *Store) DeleteSecret(ctx context.Context, name string) error {
	_, err := s.DB.ExecContext(ctx, `
		DELETE FROM secrets
		WHERE name = $1
	`, name)
	if err != nil {
		return err
	}

	return nil
}

/*****************************************************/
/*             Application Log Functions             */
/*****************************************************/

func applyLogFilters(query string, args []any, idx int, filters url.Values) (string, []any, int) {
	if level := filters.Get("level"); level != "" {
		query += fmt.Sprintf(" AND entry->>'level' ILIKE $%d", idx)
		args = append(args, "%"+level+"%")
		idx++
	}
	if user := filters.Get("user"); user != "" {
		query += fmt.Sprintf(" AND entry->'token'->>'user' ILIKE $%d", idx)
		args = append(args, "%"+user+"%")
		idx++
	}
	if msg := filters.Get("msg"); msg != "" {
		query += fmt.Sprintf(" AND entry->>'msg' ILIKE $%d", idx)
		args = append(args, "%"+msg+"%")
		idx++
	}
	if url := filters.Get("url"); url != "" {
		query += fmt.Sprintf(" AND entry->>'url' ILIKE $%d", idx)
		args = append(args, "%"+url+"%")
		idx++
	}
	if env := filters.Get("environment"); env != "" {
		query += fmt.Sprintf(" AND entry->>'environment' ILIKE $%d", idx)
		args = append(args, "%"+env+"%")
		idx++
	}
	if timeFrom := parseTime(filters, "from"); timeFrom != nil {
		query += fmt.Sprintf(" AND (entry->>'time')::timestamptz >= $%d", idx)
		args = append(args, *timeFrom)
		idx++
	}
	if timeTo := parseTime(filters, "to"); timeTo != nil {
		query += fmt.Sprintf(" AND (entry->>'time')::timestamptz <= $%d", idx)
		args = append(args, *timeTo)
		idx++
	}
	return query, args, idx
}

func (s *Store) GetLogs(ctx context.Context, filters url.Values) ([]map[string]any, int, int, error) {
	query := `SELECT entry FROM logs WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyLogFilters(query, args, idx, filters)

	query += " ORDER BY entry->>'time' DESC"

	query, args, idx, limit, offset := applyPagination(query, args, idx, filters)

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()

	logs := []map[string]any{}
	for rows.Next() {
		var entryJSON []byte

		if err := rows.Scan(&entryJSON); err != nil {
			return nil, 0, 0, err
		}

		var entry map[string]any
		if err := json.Unmarshal(entryJSON, &entry); err != nil {
			return nil, 0, 0, fmt.Errorf("unmarshal log entry: %w", err)
		}
		logs = append(logs, entry)
	}
	return logs, limit, offset, nil
}

func (s *Store) CountLogs(ctx context.Context, filters url.Values) (int, error) {
	query := `SELECT COUNT(id) FROM logs WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyLogFilters(query, args, idx, filters)

	var count int
	err := s.DB.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

/*****************************************************/
/*                 ACME Functions                    */
/*****************************************************/

func (s *Store) InsertACMEAccount(uri string, jwk *jose.JSONWebKey) error {
	jwkJSON, _ := jwk.MarshalJSON()
	_, err := s.DB.Exec(`
		INSERT INTO acme_accounts (uri, public_key_jwk) 
		VALUES ($1, $2)
    ON CONFLICT (uri) DO NOTHING
		`, uri, jwkJSON)
	return err
}

func (s *Store) GetACMEAccount(uri string) (*jose.JSONWebKey, error) {
	var jwkJSON []byte
	err := s.DB.QueryRow(`
        SELECT public_key_jwk FROM acme_accounts WHERE uri = $1`,
		uri).Scan(&jwkJSON)
	if err != nil {
		return nil, err
	}

	var jwk jose.JSONWebKey
	err = jwk.UnmarshalJSON(jwkJSON)
	return &jwk, err
}

/*****************************************************/
/*           Pending Request Functions              */
/*****************************************************/
func applyPendingRequestFilters(query string, args []any, idx int, filters url.Values) (string, []any, int) {
	if id := filters.Get("id"); id != "" {
		query += fmt.Sprintf(" AND id::text ILIKE $%d", idx)
		args = append(args, "%"+id+"%")
		idx++
	}
	if user := filters.Get("user"); user != "" {
		query += fmt.Sprintf(" AND (token_info->'user')::text ILIKE $%d", idx)
		args = append(args, "%"+user+"%")
		idx++
	}
	if url := filters.Get("url"); url != "" {
		query += fmt.Sprintf(" AND url ILIKE $%d", idx)
		args = append(args, "%"+url+"%")
		idx++
	}
	if from := parseTime(filters, "from"); from != nil {
		query += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *from)
		idx++
	}
	if to := parseTime(filters, "to"); to != nil {
		query += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *to)
		idx++
	}
	return query, args, idx
}

func (s *Store) GetPendingRequests(ctx context.Context, filters url.Values) ([]map[string]any, int, int, error) {
	query := `SELECT id, created_at, token_info, private_body, method, url FROM pending_requests WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyPendingRequestFilters(query, args, idx, filters)

	query += " ORDER BY created_at DESC"

	query, args, idx, limit, offset := applyPagination(query, args, idx, filters)

	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, 0, err
	}
	defer rows.Close()

	requests := []map[string]any{}
	for rows.Next() {
		var id uuid.UUID
		var createdAt time.Time
		var tokenInfoBytes []byte
		var privateBody bool
		var method string
		var url sql.NullString

		if err := rows.Scan(&id, &createdAt, &tokenInfoBytes, &privateBody, &method, &url); err != nil {
			return nil, 0, 0, err
		}
		var tokenInfo map[string]any
		if err := json.Unmarshal(tokenInfoBytes, &tokenInfo); err != nil {
			return nil, 0, 0, fmt.Errorf("unmarshal token info: %w", err)
		}

		requests = append(requests, map[string]any{
			"id":          id,
			"createdAt":   createdAt,
			"tokenInfo":   tokenInfo,
			"privateBody": privateBody,
			"method":      method,
			"url":         url.String,
		})
	}
	return requests, limit, offset, nil
}

func (s *Store) CountPendingRequests(ctx context.Context, filters url.Values) (int, error) {
	query := `SELECT COUNT(*) FROM pending_requests WHERE 1=1`
	args := []any{}
	idx := 1

	query, args, idx = applyPendingRequestFilters(query, args, idx, filters)

	var count int
	err := s.DB.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, err
	}
	return count, nil
}

func (s *Store) InsertPendingRequest(ctx context.Context, p *PendingRequestPrivate, token *oidc.IDToken) (uuid.UUID, error) {
	// Store a pending HTTP request in the database
	// Encrypt the Authorization header and body using the software key password before storing

	var urlStr string
	if p.URL != nil {
		urlStr = p.URL.String()
	}
	isPrivateBody := true
	if strings.HasPrefix(p.URL.Path, "/v1/signers") {
		isPrivateBody = false
	}

	user, ok := ctx.Value(loggingpkg.CtxKeyUser).(string)
	if !ok {
		user = "unknown"
	}

	tokenInfo := map[string]any{
		"issuer": token.Issuer,
		"user":   user,
	}
	tokenInfoBytes, err := json.Marshal(tokenInfo)
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal token info: %w", err)
	}

	// encrypt token
	var encryptedToken []byte
	if authTokens, ok := p.Header["Authorization"]; ok && len(authTokens) > 0 {
		var err error
		encryptedToken, err = cryptopkg.EncryptWithPwd([]byte(strings.TrimPrefix(authTokens[0], "Bearer ")), s.SoftwareKeyPass)
		if err != nil {
			return uuid.Nil, fmt.Errorf("encrypt Authorization header: %w", err)
		}
	}
	// encrypt body
	var encryptedBody []byte
	if len(p.Body) > 0 {
		var err error
		encryptedBody, err = cryptopkg.EncryptWithPwd(p.Body, s.SoftwareKeyPass)
		if err != nil {
			return uuid.Nil, fmt.Errorf("encrypt body: %w", err)
		}
	}

	var id uuid.UUID
	if err = s.DB.QueryRowContext(ctx, `
		INSERT INTO pending_requests (token_info, private_body, method, url, encrypted_token, encrypted_body)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id
	`, tokenInfoBytes, isPrivateBody, p.Method, urlStr, encryptedToken, encryptedBody).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("insert pending request: %w", err)
	}

	return id, nil
}

func (s *Store) GetPendingRequestBody(ctx context.Context, id uuid.UUID) ([]byte, error) {
	var isPrivateBody bool
	var encryptedBody []byte
	if err := s.DB.QueryRowContext(ctx, `
		SELECT private_body, encrypted_body
		FROM pending_requests
		WHERE id = $1
	`, id).Scan(&isPrivateBody, &encryptedBody); err != nil {
		return nil, fmt.Errorf("get pending request body: %w", err)
	}

	if len(encryptedBody) == 0 {
		return nil, nil
	}

	if isPrivateBody {
		return nil, fmt.Errorf("body is private")
	}

	return cryptopkg.DecryptWithPwd(encryptedBody, s.SoftwareKeyPass)
}

func (s *Store) GetPendingRequest(ctx context.Context, id uuid.UUID) (*PendingRequestPrivate, error) {
	var method string
	var urlStr sql.NullString
	var encryptedToken []byte
	var encryptedBody []byte
	if err := s.DB.QueryRowContext(ctx, `
		SELECT method, url, encrypted_token, encrypted_body
		FROM pending_requests
		WHERE id = $1
	`, id).Scan(&method, &urlStr, &encryptedToken, &encryptedBody); err != nil {
		return nil, fmt.Errorf("get pending request: %w", err)
	}

	var urlObj *url.URL
	if urlStr.Valid && urlStr.String != "" {
		parsedURL, err := url.Parse(urlStr.String)
		if err != nil {
			return nil, fmt.Errorf("parse URL: %w", err)
		}
		urlObj = parsedURL
	}

	// decrypt token
	header := http.Header{}
	var token []byte
	if len(encryptedToken) > 0 {
		var err error
		token, err = cryptopkg.DecryptWithPwd(encryptedToken, s.SoftwareKeyPass)
		if err != nil {
			return nil, fmt.Errorf("decrypt Authorization header: %w", err)
		}
		header.Set("Authorization", "Bearer "+string(token))
	}

	// decrypt body
	var body []byte
	if len(encryptedBody) > 0 {
		var err error
		body, err = cryptopkg.DecryptWithPwd(encryptedBody, s.SoftwareKeyPass)
		if err != nil {
			return nil, fmt.Errorf("decrypt body: %w", err)
		}
	}

	return &PendingRequestPrivate{
		Method: method,
		URL:    urlObj,
		Header: header,
		Body:   body,
	}, nil
}

func (s *Store) DeletePendingRequest(ctx context.Context, id uuid.UUID) error {
	_, err := s.DB.ExecContext(ctx, `
		DELETE FROM pending_requests
		WHERE id = $1
	`, id)
	return err
}

/**********************************************************************/
/*   One-Time & Periodic Tasks (Cleanup, Inventory, Metrics, etc...)  */
/**********************************************************************/

func (s *Store) RunCleanupTasks(ctx context.Context) error {
	// clean up certs that expired more than 30 days ago
	if _, err := s.DB.ExecContext(ctx, `
		DELETE FROM certs
		WHERE not_after < now() - INTERVAL '30 days'
	`); err != nil {
		return fmt.Errorf("cleanup expired certs: %w", err)
	}

	// clean up pending requests older than 7 days
	if _, err := s.DB.ExecContext(ctx, `
		DELETE FROM pending_requests
		WHERE created_at < now() - INTERVAL '7 days'
	`); err != nil {
		return fmt.Errorf("cleanup old pending requests: %w", err)
	}

	// delete unused software keys
	if _, err := s.DB.ExecContext(ctx, `
		DELETE FROM keys
		WHERE (config->>'pkcs11URI' IS NULL OR config->>'pkcs11URI' = '')
		AND id NOT IN (SELECT private_key_id FROM signers)
		AND id NOT IN (SELECT encryption_key_id FROM secrets)
	`); err != nil {
		return fmt.Errorf("cleanup keys: %w", err)
	}

	return nil
}

func ecdsaBitsFromCurve(curve string) int {
	switch strings.ToUpper(strings.TrimSpace(curve)) {
	case "P-224":
		return 224
	case "P-256":
		return 256
	case "P-384":
		return 384
	case "P-521":
		return 521
	default:
		return 0
	}
}

func (s *Store) collectKeyInventoryMetrics(ctx context.Context) (map[metricspkg.KeyInventoryBucket]float64, error) {
	keysTotalAgg := map[metricspkg.KeyInventoryBucket]float64{}

	rows, err := s.DB.QueryContext(ctx, `SELECT id, environment, config FROM keys`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id uuid.UUID
		var env string
		var cfgJSON []byte
		if err := rows.Scan(&id, &env, &cfgJSON); err != nil {
			continue
		}
		var cfg cryptopkg.KeyConfig
		if err := json.Unmarshal(cfgJSON, &cfg); err != nil {
			continue
		}

		bits := cfg.Bits
		if bits == 0 {
			switch cfg.Type {
			case cryptopkg.ECDSA:
				bits = ecdsaBitsFromCurve(cfg.Curve)
			case cryptopkg.Ed25519:
				bits = 256
			}
		}

		storage := "Software"
		if strings.TrimSpace(cfg.PKCS11Uri) != "" {
			storage = "HSM"
		}

		ready := false
		if err := s.CheckKeyReadiness(ctx, id); err == nil {
			ready = true
		}

		keysTotalAgg[metricspkg.KeyInventoryBucket{
			Environment: env,
			KeyType:     string(cfg.Type),
			Bits:        bits,
			Curve:       cfg.Curve,
			Storage:     storage,
			Ready:       ready,
		}]++
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return keysTotalAgg, nil
}

func (s *Store) collectCertInventoryMetrics(ctx context.Context) ([]metricspkg.CertInventoryItem, error) {
	var inventory []metricspkg.CertInventoryItem

	// query all CA chains from signers
	rows, err := s.DB.QueryContext(ctx, `
		SELECT signers.ca_chain, keys.environment FROM signers
		JOIN keys ON signers.private_key_id = keys.id
		WHERE ca_chain IS NOT NULL
	`)
	if err != nil {
		return nil, fmt.Errorf("query CA certificates: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var caChainBytes []byte
		var env string
		if err := rows.Scan(&caChainBytes, &env); err != nil {
			continue // skip if we can't read the CA chain
		}

		for {
			var block *pem.Block
			block, caChainBytes = pem.Decode(caChainBytes)
			if block == nil {
				break
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			inventory = append(inventory, metricspkg.NewCertInventoryItem(cert, env))
		}
	}

	// close first result set before running next query
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close CA certificates rows: %w", err)
	}

	// query deduped certs by (environment, cn, sorted sans, signer_name),
	// taking latest by not_before DESC, serial DESC
	rows, err = s.DB.QueryContext(ctx, `
	  WITH normalized AS (
	    SELECT
	      c.der,
	      k.environment,
	      c.cn,
	      c.signer_name,
	      COALESCE(
	        ARRAY(
	          SELECT s
	          FROM unnest(c.sans) AS s
	          ORDER BY s
	        ),
	        ARRAY[]::text[]
	      ) AS sans_sorted,
	      c.not_before,
	      c.serial
	    FROM certs c
	    JOIN signers s ON s.name = c.signer_name
	    JOIN keys k ON k.id = s.private_key_id
	  )
	  SELECT DISTINCT ON (environment, cn, sans_sorted, signer_name)
	    der,
	    environment
	  FROM normalized
	  ORDER BY
	    environment,
	    cn,
	    sans_sorted,
	    signer_name,
	    not_before DESC NULLS LAST,
	    serial DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("query certificates: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var der []byte
		var env string
		if err := rows.Scan(&der, &env); err != nil {
			continue // skip if we can't read the cert
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			continue // skip if we can't parse the cert
		}

		inventory = append(inventory, metricspkg.NewCertInventoryItem(cert, env))
	}

	return inventory, rows.Err()
}

func (s *Store) RefreshInventoryMetrics(ctx context.Context) error {
	start := time.Now()
	defer func() {
		metricspkg.ObserveInventoryRefreshDuration(time.Since(start))
	}()

	keys, err := s.collectKeyInventoryMetrics(ctx)
	if err != nil {
		metricspkg.IncInventoryRefreshErrors()
		return fmt.Errorf("collect key inventory metrics: %w", err)
	}

	certs, err := s.collectCertInventoryMetrics(ctx)
	if err != nil {
		metricspkg.IncInventoryRefreshErrors()
		return fmt.Errorf("collect cert inventory metrics: %w", err)
	}

	metricspkg.ResetInventorySnapshotMetrics()

	for k, v := range keys {
		metricspkg.SetKeysTotal(k, v)
	}
	for _, cert := range certs {
		metricspkg.SetCertificateMetrics(cert)
	}

	metricspkg.SetInventoryRefreshTimestamp(time.Now())
	return nil
}
