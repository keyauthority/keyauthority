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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	metricsOnce sync.Once

	httpRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "keyauthority_http_requests_total",
			Help: "Total HTTP requests by endpoint, method and status code.",
		},
		[]string{"endpoint", "method", "status"},
	)

	httpRequestDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "keyauthority_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds by endpoint and method.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint", "method"},
	)

	httpRequestTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyauthority_http_request_timestamp_seconds",
			Help: "The Unix epoch timestamp (in seconds) of the most recent HTTP request for each endpoint and method.",
		},
		[]string{"endpoint", "method"},
	)

	certificateNotBeforeTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyauthority_certificate_not_before_timestamp_seconds",
			Help: "The Unix epoch timestamp (in seconds) at which the certificate becomes valid.",
		},
		[]string{"cn", "dns", "issuer_cn", "is_ca", "environment", "key_algorithm", "key_bits"},
	)

	certificateNotAfterTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyauthority_certificate_not_after_timestamp_seconds",
			Help: "The Unix epoch timestamp (in seconds) at which the certificate expires.",
		},
		[]string{"cn", "dns", "issuer_cn", "is_ca", "environment", "key_algorithm", "key_bits"},
	)

	keyReadiness = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyauthority_key_readiness",
			Help: "Indicates whether a key is ready for use (1 for ready, 0 for not ready).",
		},
		[]string{"id", "environment", "storage"},
	)
)

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func SetupMetrics() {
	metricsOnce.Do(func() {
		prometheus.MustRegister(
			httpRequestsTotal,
			httpRequestDurationSeconds,
			httpRequestTimestampSeconds,
			certificateNotBeforeTimestampSeconds,
			certificateNotAfterTimestampSeconds,
			keyReadiness,
		)
	})
}

func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

func WithHttpMetrics(endpoint string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		httpRequestsTotal.WithLabelValues(
			endpoint,
			r.Method,
			strconv.Itoa(rec.status),
		).Inc()

		httpRequestDurationSeconds.WithLabelValues(
			endpoint,
			r.Method,
		).Observe(time.Since(start).Seconds())

		httpRequestTimestampSeconds.WithLabelValues(
			endpoint,
			r.Method,
		).Set(float64(time.Now().Unix()))
	})
}

func SetCertificateMetrics(cert *x509.Certificate, environment string) {
	cn := cert.Subject.CommonName
	issuerCN := cert.Issuer.CommonName
	isCA := strconv.FormatBool(cert.IsCA)
	alg := cert.PublicKeyAlgorithm.String()
	bits := getBitsFromCertificate(cert)
	dns := ""
	if len(cert.DNSNames) > 0 {
		sortedDNSNames := make([]string, len(cert.DNSNames))
		copy(sortedDNSNames, cert.DNSNames)
		sort.Strings(sortedDNSNames)
		dns = strings.Join(sortedDNSNames, ",")
	}

	certificateNotBeforeTimestampSeconds.WithLabelValues(
		cn, dns, issuerCN, isCA, environment, alg, strconv.Itoa(bits),
	).Set(float64(cert.NotBefore.Unix()))

	certificateNotAfterTimestampSeconds.WithLabelValues(
		cn, dns, issuerCN, isCA, environment, alg, strconv.Itoa(bits),
	).Set(float64(cert.NotAfter.Unix()))
}

func SetKeyReadiness(keyID uuid.UUID, environment string, isHSM bool, ready bool) {
	value := 0.0
	if ready {
		value = 1.0
	}
	storage := "Software"
	if isHSM {
		storage = "HSM"
	}
	keyReadiness.WithLabelValues(keyID.String(), environment, storage).Set(value)
}

func getBitsFromCertificate(cert *x509.Certificate) int {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return pub.N.BitLen()
	case *ecdsa.PublicKey:
		return pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return 256
	default:
		return 0
	}
}
