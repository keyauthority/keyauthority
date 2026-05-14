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
	"crypto/x509"
	"net/http"
	"sort"
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

	certExpirationTimestampSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "keyauthority_cert_expiration_timestamp_seconds",
			Help: "The Unix epoch timestamp (in seconds) at which the certificate expires.",
		},
		[]string{"dns_names", "issuer_cn"},
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
			certExpirationTimestampSeconds,
		)
	})
}

func MetricsHandler() http.Handler {
	return promhttp.Handler()
}

func WithMetrics(endpoint string, next http.Handler) http.Handler {
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
	})
}

func SetCertMetrics(cert *x509.Certificate) {
	dnsNamesLabel := "none"
	if len(cert.DNSNames) > 0 {
		sortedDNSNames := make([]string, len(cert.DNSNames))
		copy(sortedDNSNames, cert.DNSNames)
		sort.Strings(sortedDNSNames)
		dnsNamesLabel = strings.Join(sortedDNSNames, ",")
	}
	certExpirationTimestampSeconds.WithLabelValues(
		dnsNamesLabel,
		cert.Issuer.CommonName,
	).Set(float64(cert.NotAfter.Unix()))
}
