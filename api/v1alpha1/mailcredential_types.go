package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Labels and annotations used by MailCredential (US-3.7).
const (
	// CredentialLabel marks a Secret generated for a MailCredential; the
	// value is the MailCredential's name. The credential Secret guard
	// (SPEC §4.10) only lets the controller write Secrets carrying it.
	CredentialLabel = "sigillum.dev/credential"
	// CredentialUIDAnnotation holds the UID of the owning MailCredential on
	// a generated Secret, so the controller can refuse to overwrite a Secret
	// it does not own without having to read it.
	CredentialUIDAnnotation = "sigillum.dev/credential-uid"
	// RotateAnnotation requests an on-demand rotation of a generated
	// credential. Any new value (for example a timestamp) triggers one.
	RotateAnnotation = "sigillum.dev/rotate"
)

// Keys of a generated credential Secret.
const (
	CredentialSecretUsernameKey = "username"
	CredentialSecretPasswordKey = "password"
	CredentialSecretHostKey     = "host"
	CredentialSecretPortKey     = "port"
)

// ConditionSecretsManaged is set on generated-mode MailCredentials: False
// while the controller refuses to write Secrets because the credential
// Secret guard is missing or changed (SPEC §4.10).
const ConditionSecretsManaged = "SecretsManaged"

// Condition reasons specific to MailCredential.
const (
	ReasonServiceAccountNotFound = "ServiceAccountNotFound"
	ReasonNamespaceExcluded      = "NamespaceExcluded"
	ReasonSecretConflict         = "SecretConflict"
	ReasonSecretWriteFailed      = "SecretWriteFailed"
	ReasonGuardMissing           = "GuardMissing"
	ReasonGeneratedModeDisabled  = "GeneratedModeDisabled"
	ReasonBringYourOwnHash       = "BringYourOwnHash"
)

// CredentialRotation configures password rotation in generated mode.
type CredentialRotation struct {
	// Interval rotates the password periodically. A Go duration or a number
	// of days such as "90d". Unset: rotate only on demand (annotation
	// sigillum.dev/rotate).
	// +optional
	Interval string `json:"interval,omitempty"`
	// GracePeriod keeps the previous password valid after a rotation, so
	// apps can pick up the new one. A Go duration or a number of days.
	// +kubebuilder:default="24h"
	// +optional
	GracePeriod string `json:"gracePeriod,omitempty"`
}

// MailCredentialSpec is the desired state of MailCredential.
//
// Exactly one mode applies:
//   - generated (secretName set): the controller generates a 256-bit random
//     password, writes it to the Secret and keeps only a hash in status;
//   - bring your own hash (passwordHash set): the user supplies an argon2id
//     hash and delivers the Secret themselves.
type MailCredentialSpec struct {
	// ServiceAccountName is the identity the credential authenticates as,
	// in the credential's own namespace.
	// +kubebuilder:validation:MinLength=1
	ServiceAccountName string `json:"serviceAccountName"`
	// SecretName is the Secret the controller creates and owns (generated
	// mode). Mutually exclusive with passwordHash.
	// +optional
	SecretName string `json:"secretName,omitempty"`
	// Rotation configures rotation of the generated password.
	// +optional
	Rotation *CredentialRotation `json:"rotation,omitempty"`
	// PasswordHash is an argon2id hash in PHC string format
	// ($argon2id$v=19$m=...,t=...,p=...$salt$hash), for bring-your-own-hash
	// mode. Mutually exclusive with secretName and rotation.
	// +optional
	PasswordHash string `json:"passwordHash,omitempty"`
}

// CredentialHash is the hash of the current generated password.
type CredentialHash struct {
	// Hash is "sha256:<hex>" of the password; never the plaintext.
	Hash      string      `json:"hash"`
	CreatedAt metav1.Time `json:"createdAt"`
}

// PreviousCredentialHash is the hash of the password replaced by the last
// rotation, valid until ValidUntil.
type PreviousCredentialHash struct {
	Hash       string      `json:"hash"`
	ValidUntil metav1.Time `json:"validUntil"`
}

// MailCredentialStatus is the observed state of MailCredential.
type MailCredentialStatus struct {
	// Username is the SMTP username, "<name>.<namespace>".
	// +optional
	Username string `json:"username,omitempty"`
	// SecretName is the Secret that holds the current password (generated
	// mode).
	// +optional
	SecretName string `json:"secretName,omitempty"`
	// ServiceAccountName is the ServiceAccount the controller accepted.
	// Until it matches spec.serviceAccountName, logins are refused.
	// +optional
	ServiceAccountName string `json:"serviceAccountName,omitempty"`
	// Current is the hash of the current password: the SHA-256 of the
	// password in the Secret (generated mode), or the accepted
	// spec.passwordHash (bring your own hash).
	// +optional
	Current *CredentialHash `json:"current,omitempty"`
	// Previous is present only during a rotation's grace period.
	// +optional
	Previous *PreviousCredentialHash `json:"previous,omitempty"`
	// LastRotateRequest is the last value of the sigillum.dev/rotate
	// annotation that was acted upon.
	// +optional
	LastRotateRequest string `json:"lastRotateRequest,omitempty"`
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Namespaced,shortName=mc,categories=sigillum
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name=ServiceAccount,type=string,JSONPath=`.spec.serviceAccountName`
// +kubebuilder:printcolumn:name=Username,type=string,JSONPath=`.status.username`
// +kubebuilder:printcolumn:name=Secret,type=string,JSONPath=`.spec.secretName`
// +kubebuilder:printcolumn:name=Ready,type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name=Age,type=date,JSONPath=`.metadata.creationTimestamp`

// MailCredential is a Sigillum-issued SMTP username and password bound to
// one ServiceAccount in its namespace, for SMTP clients that only support
// AUTH PLAIN or LOGIN (US-3.7).
type MailCredential struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   MailCredentialSpec   `json:"spec,omitempty"`
	Status MailCredentialStatus `json:"status,omitempty"`
}

// Generated reports whether the credential uses generated mode.
func (c *MailCredential) Generated() bool {
	return c.Spec.PasswordHash == ""
}

// +kubebuilder:object:root=true

// MailCredentialList contains a list of MailCredential.
type MailCredentialList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []MailCredential `json:"items"`
}

func init() {
	SchemeBuilder.Register(&MailCredential{}, &MailCredentialList{})
}
