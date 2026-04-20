package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BackendType is the discriminator for MailBackendSpec / ClusterMailBackendSpec.
// v1 only implements `smtp`. Future values are reserved per spec §1.5/§4.5
// so adding a Microsoft Graph or SendGrid driver does not require a CRD migration.
// +kubebuilder:validation:Enum=smtp;microsoftGraph;sendgrid;gmail
type BackendType string

const (
	BackendSMTP           BackendType = "smtp"
	BackendMicrosoftGraph BackendType = "microsoftGraph"
	BackendSendGrid       BackendType = "sendgrid"
	BackendGmail          BackendType = "gmail"
)

// Capability is a feature flag advertised by a Driver and surfaced in
// Backend.status.capabilities. v1 only emits `send`.
// +kubebuilder:validation:Enum=send;read;subscribeEvents;folders
type Capability string

const (
	CapabilitySend            Capability = "send"
	CapabilityRead            Capability = "read"
	CapabilitySubscribeEvents Capability = "subscribeEvents"
	CapabilityFolders         Capability = "folders"
)

// SMTPTLSMode controls how Sigillum negotiates TLS with the upstream relay.
// +kubebuilder:validation:Enum=none;starttls;tls
type SMTPTLSMode string

const (
	SMTPTLSNone     SMTPTLSMode = "none"
	SMTPTLSStartTLS SMTPTLSMode = "starttls"
	SMTPTLSImplicit SMTPTLSMode = "tls"
)

// SMTPAuthType is the SASL mechanism used by the SMTP driver.
// +kubebuilder:validation:Enum=NONE;PLAIN;LOGIN;CRAM-MD5
type SMTPAuthType string

const (
	SMTPAuthNone    SMTPAuthType = "NONE"
	SMTPAuthPlain   SMTPAuthType = "PLAIN"
	SMTPAuthLogin   SMTPAuthType = "LOGIN"
	SMTPAuthCRAMMD5 SMTPAuthType = "CRAM-MD5"
)

// SMTPEndpoint is one host:port pair in a backend's failover list.
// The driver tries endpoints in declared order and uses the first Ready one.
type SMTPEndpoint struct {
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// +kubebuilder:default=starttls
	TLS SMTPTLSMode `json:"tls,omitempty"`
	// InsecureSkipVerify disables TLS certificate verification. Off by default.
	// +optional
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

// SMTPBackendSpec is the SMTP-specific shape of a backend spec.
type SMTPBackendSpec struct {
	// Endpoints is an ordered failover list. At least one entry is required.
	// +kubebuilder:validation:MinItems=1
	Endpoints []SMTPEndpoint `json:"endpoints"`

	// AuthType chooses the SASL mechanism for upstream auth. Defaults to NONE.
	// +kubebuilder:default=NONE
	AuthType SMTPAuthType `json:"authType,omitempty"`

	// CredentialsRef points at the secret holding upstream credentials.
	// Required unless AuthType is NONE.
	// +optional
	CredentialsRef *SecretReference `json:"credentialsRef,omitempty"`

	// ConnectionTimeoutSeconds caps each dial / handshake attempt.
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=120
	ConnectionTimeoutSeconds int32 `json:"connectionTimeoutSeconds,omitempty"`

	// HeloDomain is sent in the SMTP HELO/EHLO command. Defaults to "sigillum".
	// +optional
	HeloDomain string `json:"heloDomain,omitempty"`
}

// SecretReference is a name (and optional namespace) reference to a
// Kubernetes secret. ClusterMailBackend always sets Namespace; MailBackend
// implicitly resolves to its own namespace if Namespace is empty.
type SecretReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// HealthCheckSpec controls the controller-driven backend probe.
type HealthCheckSpec struct {
	// +kubebuilder:default=true
	Enabled bool `json:"enabled,omitempty"`
	// +kubebuilder:default=60
	// +kubebuilder:validation:Minimum=10
	IntervalSeconds int32 `json:"intervalSeconds,omitempty"`
}

// EndpointStatus captures the last probe result for one endpoint.
type EndpointStatus struct {
	Host    string `json:"host"`
	Port    int32  `json:"port"`
	Ready   bool   `json:"ready"`
	Message string `json:"message,omitempty"`
}

// BackendSpec is the shared shape of MailBackend.spec and ClusterMailBackend.spec.
type BackendSpec struct {
	// Type discriminates which backend-specific block (smtp, ...) is read.
	Type BackendType `json:"type"`

	// SMTP is required when type == smtp.
	// +optional
	SMTP *SMTPBackendSpec `json:"smtp,omitempty"`

	// HealthCheck controls periodic probing.
	// +optional
	HealthCheck *HealthCheckSpec `json:"healthCheck,omitempty"`
}

// BackendStatus is the shared status of MailBackend and ClusterMailBackend.
type BackendStatus struct {
	// Capabilities advertised by the active driver.
	// +optional
	Capabilities []Capability `json:"capabilities,omitempty"`

	// EndpointStatus mirrors spec.smtp.endpoints in order.
	// +optional
	EndpointStatus []EndpointStatus `json:"endpointStatus,omitempty"`

	// Conditions follows the standard Kubernetes pattern. Always includes "Ready".
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// LastProbeTime is the wall-clock time of the most recent health check.
	// +optional
	LastProbeTime *metav1.Time `json:"lastProbeTime,omitempty"`

	// ObservedGeneration is the spec generation reflected by this status.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// ConditionTypes used across CRDs.
const (
	ConditionReady           = "Ready"
	ConditionUsingLegacyAuth = "UsingLegacyAuth"
)

// Reasons used in conditions.
const (
	ReasonAtLeastOneEndpointReady = "AtLeastOneEndpointReady"
	ReasonAllEndpointsDown        = "AllEndpointsDown"
	ReasonUnsupportedBackendType  = "UnsupportedBackendType"
	ReasonInvalidConfiguration    = "InvalidConfiguration"
	ReasonProbeError              = "ProbeError"
	ReasonBackendNotFound         = "BackendNotFound"
	ReasonBackendNotReady         = "BackendNotReady"
	ReasonReady                   = "Ready"
)

// SecretKey is a structured reference for the credentials secret keys.
// Standardised per SPEC §4.3.1: SMTP uses keys `username` and `password`.
const (
	SMTPSecretUsernameKey = "username"
	SMTPSecretPasswordKey = "password"
)

// avoid unused import warning in some builds
var _ = corev1.ConditionTrue
