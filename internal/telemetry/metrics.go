package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Registry is the Prometheus registry shared by api-server and controller.
var Registry = prometheus.NewRegistry()

var (
	MessagesTotal = promauto.With(Registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "sigillum_messages_total",
			Help: "Total number of messages processed, labelled by outcome.",
		},
		[]string{"namespace", "policy", "backend", "result"},
	)

	MessageSizeBytes = promauto.With(Registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sigillum_message_size_bytes",
			Help:    "Distribution of accepted message sizes in bytes.",
			Buckets: prometheus.ExponentialBuckets(1024, 4, 8),
		},
		[]string{"namespace", "policy", "backend"},
	)

	BackendDurationSeconds = promauto.With(Registry).NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "sigillum_backend_duration_seconds",
			Help:    "Latency of upstream backend send calls.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"namespace", "policy", "backend", "result"},
	)

	RatelimitRejectedTotal = promauto.With(Registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "sigillum_ratelimit_rejected_total",
			Help: "Number of requests rejected by the rate limiter.",
		},
		[]string{"namespace", "policy"},
	)

	PolicyDeniedTotal = promauto.With(Registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "sigillum_policy_denied_total",
			Help: "Number of requests denied by policy evaluation.",
		},
		[]string{"namespace", "policy", "reason"},
	)
)
