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
// Sends try endpoints in declared order, those the last probe found unready
// last, and use the first one that completes the handshake.
type SMTPEndpoint struct {
	// +kubebuilder:validation:MinLength=1
	Host string `json:"host"`
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
	// +kubebuilder:default=starttls
	TLS SMTPTLSMode `json:"tls,omitempty"`
	// InsecureSkipVerify is rejected when true: TLS certificate verification
	// cannot be disabled. To trust a relay certificate from a private CA, set
	// spec.smtp.caSecretRef.
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

	// ConnectionTimeoutSeconds caps the dial and the handshake (banner, EHLO,
	// STARTTLS, AUTH) of each endpoint; then the next endpoint is tried.
	// +kubebuilder:default=10
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=120
	ConnectionTimeoutSeconds int32 `json:"connectionTimeoutSeconds,omitempty"`

	// HeloDomain is sent in the SMTP HELO/EHLO command. Defaults to "sigillum".
	// +optional
	HeloDomain string `json:"heloDomain,omitempty"`

	// CASecretRef names PEM CA certificates that are trusted, in addition to
	// the system roots, when verifying this backend's relays (STARTTLS and
	// implicit TLS): for relays with a certificate from a private CA. The
	// namespace rules of credentialsRef apply.
	// +optional
	CASecretRef *CASecretReference `json:"caSecretRef,omitempty"`
}

// CASecretReference names a Secret key that holds PEM CA certificates.
type CASecretReference struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// Namespace of the Secret. Required on ClusterMailBackend; a MailBackend
	// always uses its own namespace.
	// +optional
	Namespace string `json:"namespace,omitempty"`
	// Key holding the certificates. Defaults to ca.crt.
	// +kubebuilder:default=ca.crt
	// +optional
	Key string `json:"key,omitempty"`
}

// MicrosoftGraphBackendSpec is the shape of a microsoftGraph backend (SPEC
// US-6.1 stage 1): an Entra ID application with the Mail.Send application
// permission. It sends as the From mailbox of each message, bounded by the
// backend's allowedSenders, which is required for this type.
type MicrosoftGraphBackendSpec struct {
	// TenantID is the directory (tenant) ID or a verified domain of the
	// tenant, in lower case.
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	TenantID string `json:"tenantID"`
	// ClientID is the application (client) ID of the app registration.
	// +kubebuilder:validation:MinLength=1
	ClientID string `json:"clientID"`
	// CredentialsRef points at the Secret holding the client secret under
	// the key client_secret.
	CredentialsRef SecretReference `json:"credentialsRef"`
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

	// MicrosoftGraph is required when type == microsoftGraph.
	// +optional
	MicrosoftGraph *MicrosoftGraphBackendSpec `json:"microsoftGraph,omitempty"`

	// HealthCheck controls periodic probing.
	// +optional
	HealthCheck *HealthCheckSpec `json:"healthCheck,omitempty"`

	// No omitempty on AllowedSenders: an empty list must survive a round
	// trip through Go, since it denies every sender while an omitted list
	// allows all. A nil list encodes as null, which the API server prunes.

	// AllowedSenders lists the sender addresses this backend sends for:
	// exact addresses or glob patterns anchored on a bare domain
	// ("me@outlook.com", "*@example.com"), matched case-insensitively like
	// a policy's allowedSenders. Checked on every send in addition to the
	// policy's senderRestrictions, against From, the envelope sender and
	// Sender, so a policy can narrow the list but never widen it. Omitted:
	// no restriction by the backend. An empty list denies every sender.
	// +optional
	AllowedSenders []string `json:"allowedSenders"`
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

// Labels, annotations and keys of the Secret in which the controller keeps a
// delegated backend's OAuth tokens (US-6.3). The credential Secret guard
// (SPEC §4.10) lets the controller write such Secrets only with this label,
// the backend's UID in the annotation, a controller owner reference to that
// backend and these keys.
const (
	// OAuthTokenLabel's value is the name of the owning MailBackend or
	// ClusterMailBackend.
	OAuthTokenLabel = "sigillum.dev/oauth-token"
	// OAuthTokenUIDAnnotation holds the owning backend's UID.
	OAuthTokenUIDAnnotation = "sigillum.dev/oauth-token-uid"

	OAuthSecretRefreshTokenKey = "refresh_token"
	OAuthSecretAccessTokenKey  = "access_token"
	OAuthSecretExpiresAtKey    = "expires_at"

	// OAuthSeedAnnotation on the token Secret identifies the refresh token
	// from the credentials Secret the stored one descends from (a hash),
	// so a new sign-in there replaces the stored chain.
	OAuthSeedAnnotation = "sigillum.dev/oauth-seed"
	// OAuthRefreshAtAnnotation is when the controller next refreshes the
	// access token (RFC 3339): at half its lifetime.
	OAuthRefreshAtAnnotation = "sigillum.dev/oauth-refresh-at"
)

// ConditionAuthorized is set on delegated backends (US-6.3): True while the
// controller holds a refresh token the provider accepts.
const ConditionAuthorized = "Authorized"

// Condition reasons of delegated backends.
const (
	ReasonAuthorized = "Authorized"
	// ReasonAuthorizationRequired: there is no refresh token, or the
	// provider rejected it (revoked consent, expiry); a person has to sign
	// in again.
	ReasonAuthorizationRequired = "AuthorizationRequired"
	// ReasonTokenRefreshFailed: the provider could not be reached or
	// answered with a temporary error; the controller retries.
	ReasonTokenRefreshFailed = "TokenRefreshFailed"
)

// SecretKey is a structured reference for the credentials secret keys.
// Standardised per SPEC §4.3.1: SMTP uses keys `username` and `password`.
const (
	SMTPSecretUsernameKey = "username"
	SMTPSecretPasswordKey = "password"
	// GraphSecretClientSecretKey holds a microsoftGraph backend's client
	// secret.
	GraphSecretClientSecretKey = "client_secret"
)

// avoid unused import warning in some builds
var _ = corev1.ConditionTrue
