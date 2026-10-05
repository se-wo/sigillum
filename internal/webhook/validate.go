package webhook

import (
	"fmt"

	"k8s.io/apimachinery/pkg/runtime"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

// ValidateMailPolicy and ValidateBackend apply the admission rules outside
// admission. Without the webhook (webhook.enabled=false), or for an object
// admitted by an older version with laxer rules, they are the only check:
// the controller reports a violation as Ready=False, and the gateway
// refuses to use the object rather than enforce whatever its malformed
// entries happen to match.

// ValidateMailPolicy returns the error the webhook would reject mp with.
func ValidateMailPolicy(mp *sigv1.MailPolicy) error {
	_, err := (&MailPolicyValidator{}).validate(mp)
	return err
}

// ValidateBackend returns the error the webhook would reject a MailBackend
// or ClusterMailBackend with. Warnings are not errors.
func ValidateBackend(obj runtime.Object) error {
	var err error
	switch obj.(type) {
	case *sigv1.MailBackend:
		_, err = NewMailBackendValidator().validate(obj)
	case *sigv1.ClusterMailBackend:
		_, err = NewClusterMailBackendValidator().validate(obj)
	default:
		err = fmt.Errorf("unexpected object type %T", obj)
	}
	return err
}
