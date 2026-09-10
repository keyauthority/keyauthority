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

package events

import (
	"context"
	"crypto/x509"
	"log/slog"
	"net/http"

	"github.com/gorilla/mux"
	databasepkg "github.com/keyauthority/keyauthority/internal/database"
	loggingpkg "github.com/keyauthority/keyauthority/internal/logging"
	signerpkg "github.com/keyauthority/keyauthority/internal/signer"
)

func OnCertificateSigned(
	r *http.Request,
	log *loggingpkg.Logger,
	db *databasepkg.Database,
	cert *x509.Certificate,
	comment string) {

	signerName := mux.Vars(r)["name"]

	// Log the certificate signing event
	log.Info(r, "certificate signed",
		slog.String("serial", signerpkg.BigIntToString(cert.SerialNumber)),
		slog.String("signerName", signerName),
		slog.String("cn", cert.Subject.CommonName),
		slog.Any("dns", cert.DNSNames),
		slog.Any("notBefore", cert.NotBefore),
		slog.Any("notAfter", cert.NotAfter),
		slog.String("comment", comment),
	)

	// Insert cert in DB asynchronously, to avoid delaying the response to the client
	go func() {
		err := db.InsertCert(context.Background(), signerName, cert, comment)
		if err != nil {
			log.Warn(r, "couldn't insert certificate", "error", err)
		}
	}()
}
