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

package metrics

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

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

	keysTotal = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyauthority_keys_total",
			Help: "Total keys in inventory by environment, type, size, curve and storage.",
		},
		[]string{"environment", "key_type", "bits", "curve", "storage", "ready"},
	)

	certNotBeforeTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyauthority_certificate_not_before_timestamp_seconds",
			Help: "The Unix epoch timestamp (in seconds) at which the certificate becomes valid.",
		},
		[]string{"environment", "cn", "dns", "issuer_cn", "is_ca", "key_algorithm", "key_bits"},
	)

	certNotAfterTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyauthority_certificate_not_after_timestamp_seconds",
			Help: "The Unix epoch timestamp (in seconds) at which the certificate expires.",
		},
		[]string{"environment", "cn", "dns", "issuer_cn", "is_ca", "key_algorithm", "key_bits"},
	)

	inventoryRefreshTimestampSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "keyauthority_inventory_refresh_timestamp_seconds",
			Help: "Unix epoch timestamp in seconds for the last successful inventory refresh.",
		},
	)

	inventoryRefreshDurationSeconds = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "keyauthority_inventory_refresh_duration_seconds",
			Help:    "Inventory refresh duration in seconds.",
			Buckets: prometheus.DefBuckets,
		},
	)

	inventoryRefreshErrorsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "keyauthority_inventory_refresh_errors_total",
			Help: "Total number of inventory refresh failures.",
		},
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
			keysTotal,
			certNotBeforeTimestampSeconds,
			certNotAfterTimestampSeconds,
			inventoryRefreshTimestampSeconds,
			inventoryRefreshDurationSeconds,
			inventoryRefreshErrorsTotal,
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

func ResetInventorySnapshotMetrics() {
	keysTotal.Reset()
	certNotBeforeTimestampSeconds.Reset()
	certNotAfterTimestampSeconds.Reset()
}

type KeyInventoryBucket struct {
	Environment string
	KeyType     string
	Bits        int
	Curve       string
	Storage     string
	Ready       bool
}

type CertInventoryItem struct {
	Environment        string
	CommonName         string
	DNSNames           string
	Issuer             string
	IsCA               bool
	PublicKeyAlgorithm string
	KeyBits            int
	NotBefore          time.Time
	NotAfter           time.Time
}

func NewCertInventoryItem(cert *x509.Certificate, env string) CertInventoryItem {
	return CertInventoryItem{
		Environment:        env,
		CommonName:         cert.Subject.CommonName,
		DNSNames:           strings.Join(cert.DNSNames, ","),
		Issuer:             cert.Issuer.CommonName,
		IsCA:               cert.IsCA,
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		KeyBits:            getBitsFromCertificate(cert),
		NotBefore:          cert.NotBefore,
		NotAfter:           cert.NotAfter,
	}
}

func SetKeysTotal(bucket KeyInventoryBucket, total float64) {
	keysTotal.WithLabelValues(
		bucket.Environment,
		bucket.KeyType,
		strconv.Itoa(bucket.Bits),
		bucket.Curve,
		bucket.Storage,
		strconv.FormatBool(bucket.Ready)).Set(total)
}

func SetCertificateMetrics(item CertInventoryItem) {
	labels := []string{
		item.Environment,
		item.CommonName,
		item.DNSNames,
		item.Issuer,
		strconv.FormatBool(item.IsCA),
		item.PublicKeyAlgorithm,
		strconv.Itoa(item.KeyBits),
	}

	certNotBeforeTimestampSeconds.WithLabelValues(
		labels...).Set(float64(item.NotBefore.Unix()))

	certNotAfterTimestampSeconds.WithLabelValues(
		labels...).Set(float64(item.NotAfter.Unix()))
}

func ObserveInventoryRefreshDuration(d time.Duration) {
	inventoryRefreshDurationSeconds.Observe(d.Seconds())
}

func SetInventoryRefreshTimestamp(t time.Time) {
	inventoryRefreshTimestampSeconds.Set(float64(t.Unix()))
}

func IncInventoryRefreshErrors() {
	inventoryRefreshErrorsTotal.Inc()
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
