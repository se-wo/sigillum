package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BackendKind discriminates between namespace-scoped MailBackend and
// cluster-scoped ClusterMailBackend.
// +kubebuilder:validation:Enum=MailBackend;ClusterMailBackend
type BackendKind string

const (
	KindMailBackend        BackendKind = "MailBackend"
	KindClusterMailBackend BackendKind = "ClusterMailBackend"
)

// BackendRef is the cross-resource reference used by MailPolicy.spec.backendRef.
type BackendRef struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +kubebuilder:default=ClusterMailBackend
	Kind BackendKind `json:"kind,omitempty"`
}

// ServiceAccountSubject is the strictest subject type — exact SA name match
// in the policy's own namespace (Namespace is informational only).
type ServiceAccountSubject struct {
	// +kubebuilder:validation:MinLength=1
	Name string `json:"name"`
	// +optional
	Namespace string `json:"namespace,omitempty"`
}

// LabelSelectorSubject wraps a metav1.LabelSelector to keep schema explicit.
type LabelSelectorSubject struct {
	// +optional
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
	// +optional
	MatchExpressions []metav1.LabelSelectorRequirement `json:"matchExpressions,omitempty"`
}

// PolicySubject is one of three matcher types — explicit SA, SA selector, or pod
// selector. Match precedence (US-3.2): explicit SA > SA selector > pod selector.
type PolicySubject struct {
	// +optional
	ServiceAccount *ServiceAccountSubject `json:"serviceAccount,omitempty"`
	// +optional
	ServiceAccountSelector *LabelSelectorSubject `json:"serviceAccountSelector,omitempty"`
	// +optional
	PodSelector *LabelSelectorSubject `json:"podSelector,omitempty"`
}

// SenderRestrictions restrict the From address of accepted messages.
type SenderRestrictions struct {
	// AllowedSenders is a list of exact addresses or glob patterns
	// (e.g. "*@noreply.example.com"). Empty list means "deny all".
	// +optional
	AllowedSenders []string `json:"allowedSenders,omitempty"`
}

// RecipientRestrictions are reserved for v0.2; included so a future driver
// release can populate them without a CRD migration.
type RecipientRestrictions struct {
	// +optional
	AllowedDomains []string `json:"allowedDomains,omitempty"`
	// +optional
	BlockedDomains []string `json:"blockedDomains,omitempty"`
}

// RateLimitsSpec configures the sliding-window rate limiter.
type RateLimitsSpec struct {
	// +kubebuilder:validation:Minimum=0
	// +optional
	MessagesPerMinute int32 `json:"messagesPerMinute,omitempty"`
	// +kubebuilder:validation:Minimum=0
	// +optional
	MessagesPerHour int32 `json:"messagesPerHour,omitempty"`
}

// MessageLimitsSpec bounds individual message dimensions.
type MessageLimitsSpec struct {
	// +kubebuilder:default=10485760
	// +kubebuilder:validation:Minimum=1
	MaxSizeBytes int64 `json:"maxSizeBytes,omitempty"`
	// +kubebuilder:default=50
	// +kubebuilder:validation:Minimum=1
	MaxRecipients int32 `json:"maxRecipients,omitempty"`
}

// LegacyAuthSpec opts a policy into weak fallback auth modes.
type LegacyAuthSpec struct {
	// PodIPFallback enables pod-IP-based identification for the SMTP path
	// when SASL auth is unavailable. Off by default per US-3.5.
	// +kubebuilder:default=false
	PodIPFallback bool `json:"podIPFallback,omitempty"`
}

// MailPolicySpec is the desired state of MailPolicy.
type MailPolicySpec struct {
	// Priority breaks ties between matching policies — higher wins.
	// Tie-break: alphabetical by name (US-2.6).
	// +kubebuilder:default=0
	Priority int32 `json:"priority,omitempty"`

	// Subjects matches the calling identity. At least one subject is required.
	// +kubebuilder:validation:MinItems=1
	Subjects []PolicySubject `json:"subjects"`

	// BackendRef is the target backend; required, no default backend.
	BackendRef BackendRef `json:"backendRef"`

	// +optional
	SenderRestrictions *SenderRestrictions `json:"senderRestrictions,omitempty"`
	// +optional
	RecipientRestrictions *RecipientRestrictions `json:"recipientRestrictions,omitempty"`
	// +optional
	RateLimits *RateLimitsSpec `json:"rateLimits,omitempty"`
	// +optional
	MessageLimits *MessageLimitsSpec `json:"messageLimits,omitempty"`
	// +optional
	LegacyAuth *LegacyAuthSpec `json:"legacyAuth,omitempty"`
}

// MailPolicyStatus is the observed state of MailPolicy.
type MailPolicyStatus struct {
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +optional
	MatchedSubjects int32 `json:"matchedSubjects,omitempty"`
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=mp,categories=sigillum
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=Priority,type=integer,JSONPath=`.spec.priority`
// +kubebuilder:printcolumn:name=Backend,type=string,JSONPath=`.spec.backendRef.name`
// +kubebuilder:printcolumn:name=Ready,type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name=Age,type=date,JSONPath=`.metadata.creationTimestamp`

// MailPolicy is a namespace-scoped allow/restrict rule that binds a calling
// subject to a backend, with optional rate limits and sender restrictions.
type MailPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MailPolicySpec   `json:"spec,omitempty"`
	Status MailPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MailPolicyList contains a list of MailPolicy.
type MailPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MailPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MailPolicy{}, &MailPolicyList{})
}
