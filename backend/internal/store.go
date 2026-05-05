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
	"crypto/x509"
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
	cryptopkg "github.com/keyauthority/keyauthority/internal/crypto"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
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
	secretsCache = NewCache(make(map[string]any))
)

// actual data used for replaying pending requests upon authorization
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

func withKeyConfigDefaults(cfg *cryptopkg.KeyConfig) *cryptopkg.KeyConfig {
	if cfg == nil {
		cfg = &cryptopkg.KeyConfig{}
	}
	if cfg.Type == cryptopkg.Unknown {
		cfg.Type = cryptopkg.RSA
	}
	if cfg.Type == cryptopkg.RSA && cfg.Bits == 0 {
		cfg.Bits = 2048
	}
	if cfg.Type == cryptopkg.ECDSA && cfg.Curve == "" {
		cfg.Curve = "P-256"
	}
	return cfg
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

/*****************************************************/
/*                 General Functions                 */
/*****************************************************/
func parseTime(q url.Values, key string) *time.Time {
	val := q.Get(key)
	if val == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", val)
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

func (s *Store) CreateKey(ctx context.Context, env string, cfg *cryptopkg.KeyConfig) (uuid.UUID, error) {
	// marshal config
	cfgJSON, err := json.Marshal(withKeyConfigDefaults(cfg))
	if err != nil {
		return uuid.Nil, fmt.Errorf("marshal key config: %w", err)
	}

	softwareKey, err := cryptopkg.GenerateKey(ctx, cfg, s.SoftwareKeyPass)
	if err != nil {
		return uuid.Nil, fmt.Errorf("create key: %w", err)
	}

	var id uuid.UUID
	if err := s.DB.QueryRowContext(ctx, `
    INSERT INTO keys (environment, config, software_key)
    VALUES ($1, $2, $3)
    RETURNING id
`, env, cfgJSON, softwareKey).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("insert key: %w", err)
	}

	if err := s.ConsolidateKey(ctx, id); err != nil {
		// delete DB entry
		s.DB.ExecContext(ctx, `
			DELETE FROM keys
			WHERE id = $1
		`, id)
		return uuid.Nil, fmt.Errorf("consolidate key: %w", err)
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
	return err
}

func (s *Store) ConsolidateKey(ctx context.Context, id uuid.UUID) error {
	key, err := s.LoadKey(ctx, id)
	if err != nil {
		return fmt.Errorf("load key: %w", err)
	}
	// create config from key
	keyCfg, err := key.InferConfig()
	if err != nil {
		return fmt.Errorf("get key config from key object: %w", err)
	}

	// retrieve config from DB to get PKCS11 URIs
	keyFromDB, err := s.GetKey(ctx, id)
	if err != nil {
		return fmt.Errorf("get key from DB: %w", err)
	}
	dbCfg := keyFromDB["config"].(*cryptopkg.KeyConfig)
	if err != nil {
		return fmt.Errorf("get key info: %w", err)
	}

	// add PKCS11 URIs if present in DB config
	keyCfg.PKCS11Uri = dbCfg.PKCS11Uri
	keyCfg.PKCS11KeyUri = dbCfg.PKCS11KeyUri

	// update DB entry
	cfgJSON, err := json.Marshal(keyCfg)
	if err != nil {
		return fmt.Errorf("marshal key config: %w", err)
	}
	_, err = s.DB.ExecContext(ctx, `
		UPDATE keys
		SET config = $2
		WHERE id = $1
	`, id, cfgJSON)
	if err != nil {
		return fmt.Errorf("update key config in DB: %w", err)
	}

	return nil
}

func (s *Store) LoadKey(ctx context.Context, id uuid.UUID) (*cryptopkg.Key, error) {
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
	return cryptopkg.NewKey(ctx, &cfg, softwareKey, s.SoftwareKeyPass)
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

func (s *Store) SetSignerCAChain(ctx context.Context, name string, caChain []byte) error {
	_, err := s.DB.ExecContext(ctx, `
		UPDATE signers
		SET ca_chain = $2, updated_at = now()
		WHERE name = $1
	`, name, caChain)
	return err
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

func (s *Store) SetSignerCRL(ctx context.Context, name string, der []byte) error {
	_, err := s.DB.ExecContext(ctx, `
		UPDATE signers
		SET crl = $2
		WHERE name = $1
	`, name, der)
	return err
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

	crl, err := s.GetSignerCRL(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("get signer CRL: %w", err)
	}

	// create signer object
	signer, err := signerpkg.NewSigner(cfg, pvk.AssymmetricKey, caChain, crl, args...)
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
	query := `SELECT certs.serial, certs.signer_name, certs.cn, certs.sans, certs.not_before, certs.not_after, certs.revoked, keys.environment FROM keys,signers,certs WHERE certs.signer_name = signers.name AND signers.private_key_id = keys.id`
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
		var environment string

		if err := rows.Scan(&serial, &signerName, &cn, &sans, &notBefore, &notAfter, &revoked, &environment); err != nil {
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
			"environment": environment,
		})
	}
	return certs, limit, offset, nil
}

func (s *Store) CountCerts(ctx context.Context, hasAccessToAllEnvs bool, accessibleEnvs []string, filters url.Values) (int, error) {
	query := `SELECT COUNT(certs.serial) FROM keys,signers,certs WHERE certs.signer_name = signers.name AND signers.private_key_id = keys.id`
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

func (s *Store) InsertCert(ctx context.Context, signerName string, cert *x509.Certificate) error {
	cn := cert.Subject.CommonName
	sans := append(cert.DNSNames, cert.EmailAddresses...)
	der := cert.Raw
	notBefore := cert.NotBefore
	notAfter := cert.NotAfter
	serial := signerpkg.BigIntToString(cert.SerialNumber)

	_, err := s.DB.ExecContext(ctx, `
		INSERT INTO certs (
			serial, signer_name, cn, sans, der, not_before, not_after, revoked
		) VALUES ($1, $2, $3, $4, $5, $6, $7, false)
	`, serial, signerName, cn, sans, der, notBefore, notAfter)
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
	if cachedSecret, exists := secretsCache.Get(name); exists {
		return cachedSecret.(map[string]any), nil
	}

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

	secretsCache.Set(name, resp)
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
	secretsCache.Delete(name)
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

	secretsCache.Delete(name)
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

	tokenInfo := map[string]any{
		"issuer": token.Issuer,
		"user":   loggingpkg.ExtractUser(token),
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

	return cryptopkg.DecryptData(encryptedBody, s.SoftwareKeyPass)
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
		token, err = cryptopkg.DecryptData(encryptedToken, s.SoftwareKeyPass)
		if err != nil {
			return nil, fmt.Errorf("decrypt Authorization header: %w", err)
		}
		header.Set("Authorization", "Bearer "+string(token))
	}

	// decrypt body
	var body []byte
	if len(encryptedBody) > 0 {
		var err error
		body, err = cryptopkg.DecryptData(encryptedBody, s.SoftwareKeyPass)
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

/*****************************************************/
/*               Periodic Ops Functions               */
/*****************************************************/

func (s *Store) PeriodicOps(ctx context.Context) error {
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
