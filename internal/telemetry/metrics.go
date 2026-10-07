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

	AuthFailuresTotal = promauto.With(Registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "sigillum_auth_failures_total",
			Help: "Failed authentication attempts, by transport, auth method and reason.",
		},
		[]string{"transport", "auth_method", "reason"},
	)

	// SMTPMessagesInFlight is the number of messages a tenant is relaying
	// through the SMTP proxy right now, bounded per namespace so one tenant
	// cannot take every relay slot (#73).
	SMTPMessagesInFlight = promauto.With(Registry).NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "sigillum_smtp_messages_in_flight",
			Help: "Messages currently being relayed through the SMTP proxy, by tenant namespace.",
		},
		[]string{"namespace"},
	)

	// UpstreamAuthFailuresTotal counts failures to authenticate to an
	// upstream relay (a rotated or wrong password, an unsupported
	// mechanism). A backend whose probe is Ready but whose sends fail here
	// shows up as a rising count. Labelled by backend only; the mechanism
	// is a backend property.
	UpstreamAuthFailuresTotal = promauto.With(Registry).NewCounterVec(
		prometheus.CounterOpts{
			Name: "sigillum_upstream_auth_failures_total",
			Help: "Failures to authenticate to an upstream relay, by backend.",
		},
		[]string{"backend"},
	)
)
