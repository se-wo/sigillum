package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=mb,categories=sigillum
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=Type,type=string,JSONPath=`.spec.type`
// +kubebuilder:printcolumn:name=Ready,type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name=Age,type=date,JSONPath=`.metadata.creationTimestamp`

// MailBackend is a namespace-scoped backend referenced from MailPolicies in
// the same namespace. Credentials referenced via spec.smtp.credentialsRef
// resolve to the MailBackend's own namespace when no explicit namespace is set.
type MailBackend struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BackendSpec   `json:"spec,omitempty"`
	Status BackendStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// MailBackendList contains a list of MailBackend.
type MailBackendList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MailBackend `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MailBackend{}, &MailBackendList{})
}
