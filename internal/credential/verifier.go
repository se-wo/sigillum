package credential

import (
	"context"
	"crypto/sha256"
	"errors"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
)

// ErrInvalid is returned for an unknown username, a wrong password, or a
// credential that is not Ready. Callers answer all of them the same way so
// the reply does not reveal which one it was.
var ErrInvalid = errors.New("invalid credentials")

// Result is a successful verification.
type Result struct {
	Namespace      string
	ServiceAccount string
	Username       string
	// Previous is set when the previous password of a rotation (still in
	// its grace period) was used.
	Previous bool

	uid  types.UID
	hash string // the hash that matched (generated) or spec.passwordHash
}

// Verifier checks SMTP credentials against MailCredential objects from the
// informer cache. It never reads Secrets.
type Verifier struct {
	Reader client.Reader
	now    func() time.Time
	// slots bounds concurrent argon2id verifications (each may allocate up
	// to Argon2MaxMemoryKiB).
	slots chan struct{}
	// argonOK caches successful argon2id verifications for a short time, so
	// clients that open one connection per message do not pay (and make the
	// proxy pay) the full hash cost every time. Keyed by a SHA-256 over
	// username, stored hash and password; failures are never cached.
	argonOK *lru.Cache[[32]byte, time.Time]
}

// argonCacheTTL bounds how long a cached argon2id success is reused. A
// changed or deleted MailCredential invalidates it immediately (the key
// includes the stored hash and every lookup re-reads the object).
const argonCacheTTL = 5 * time.Minute

// NewVerifier builds a Verifier; maxArgon2 bounds concurrent argon2id
// verifications (at least 1).
func NewVerifier(r client.Reader, maxArgon2 int) *Verifier {
	if maxArgon2 < 1 {
		maxArgon2 = 1
	}
	c, _ := lru.New[[32]byte, time.Time](1024)
	return &Verifier{Reader: r, now: time.Now, slots: make(chan struct{}, maxArgon2), argonOK: c}
}

// Verify authenticates username and password (Lookup, then Check).
func (v *Verifier) Verify(ctx context.Context, username, password string) (*Result, error) {
	mc, err := v.Lookup(ctx, username)
	if err != nil {
		return nil, err
	}
	return v.Check(ctx, mc, password)
}

// Lookup returns the usable MailCredential that username names. It returns
// ErrInvalid for a malformed or unknown username and for a credential that
// is not usable, and other errors for failed lookups.
func (v *Verifier) Lookup(ctx context.Context, username string) (*sigv1.MailCredential, error) {
	ns, name, ok := ParseUsername(username)
	if !ok {
		return nil, ErrInvalid
	}
	var mc sigv1.MailCredential
	if err := v.Reader.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, &mc); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, ErrInvalid
		}
		return nil, err
	}
	if !Usable(&mc) || mc.Status.Username != username {
		return nil, ErrInvalid
	}
	return &mc, nil
}

// Check verifies password against mc, as returned by Lookup.
func (v *Verifier) Check(ctx context.Context, mc *sigv1.MailCredential, password string) (*Result, error) {
	if password == "" {
		return nil, ErrInvalid
	}
	res := &Result{Namespace: mc.Namespace, ServiceAccount: mc.Spec.ServiceAccountName, Username: mc.Status.Username, uid: mc.UID}
	if !mc.Generated() {
		ok, err := v.verifyArgon2id(ctx, res.Username, mc.Spec.PasswordHash, password)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrInvalid
		}
		res.hash = mc.Spec.PasswordHash
		return res, nil
	}
	if cur := mc.Status.Current; cur != nil && VerifyGenerated(cur.Hash, password) {
		res.hash = cur.Hash
		return res, nil
	}
	if prev := mc.Status.Previous; prev != nil && v.now().Before(prev.ValidUntil.Time) && VerifyGenerated(prev.Hash, password) {
		res.hash, res.Previous = prev.Hash, true
		return res, nil
	}
	return nil, ErrInvalid
}

// StillValid reports whether an earlier Result still holds: the same
// MailCredential exists, is usable, and the password that matched has not
// been rotated out. previous reports that the password is now the previous
// one of a rotation. It returns ErrInvalid when the credential was revoked
// and other errors when the lookup failed. The SMTP proxy calls it for
// every message of a session, so deleting a MailCredential also cuts off
// open connections.
func (v *Verifier) StillValid(ctx context.Context, r *Result) (previous bool, err error) {
	var mc sigv1.MailCredential
	if err := v.Reader.Get(ctx, types.NamespacedName{Namespace: r.Namespace, Name: nameOf(r.Username)}, &mc); err != nil {
		if apierrors.IsNotFound(err) {
			return false, ErrInvalid
		}
		return false, err
	}
	if mc.UID != r.uid || !Usable(&mc) || mc.Spec.ServiceAccountName != r.ServiceAccount {
		return false, ErrInvalid
	}
	if !mc.Generated() {
		if mc.Spec.PasswordHash == r.hash {
			return false, nil
		}
		return false, ErrInvalid
	}
	// Generated mode accepts only generated hashes: after a switch from
	// bring your own hash, status.current still holds the argon2id hash
	// until the controller issues a password.
	if !IsGeneratedHash(r.hash) {
		return false, ErrInvalid
	}
	if cur := mc.Status.Current; cur != nil && cur.Hash == r.hash {
		return false, nil
	}
	if prev := mc.Status.Previous; prev != nil && prev.Hash == r.hash && v.now().Before(prev.ValidUntil.Time) {
		return true, nil
	}
	return false, ErrInvalid
}

func nameOf(username string) string {
	_, name, _ := ParseUsername(username)
	return name
}

func (v *Verifier) verifyArgon2id(ctx context.Context, username, phc, password string) (bool, error) {
	// Lookup key of the in-memory cache of argon2id successes; it is never
	// stored or logged, and only entries whose password argon2id accepted
	// are added. A fast hash is appropriate here: the password's stored
	// form is the argon2id hash (CodeQL's go/weak-sensitive-data-hashing
	// alert on this line is a false positive).
	key := sha256.Sum256([]byte(username + "\x00" + phc + "\x00" + password))
	if exp, ok := v.argonOK.Get(key); ok && v.now().Before(exp) {
		return true, nil
	}
	select {
	case v.slots <- struct{}{}:
		defer func() { <-v.slots }()
	case <-ctx.Done():
		return false, ctx.Err()
	}
	ok, err := VerifyArgon2id(phc, password)
	if err != nil {
		// The webhook rejects malformed hashes; one that slipped through
		// (webhook disabled) simply never matches.
		return false, nil
	}
	if ok {
		v.argonOK.Add(key, v.now().Add(argonCacheTTL))
	}
	return ok, nil
}

// Usable reports whether the controller accepted mc: Ready=True, and the
// fields that decide who the credential authenticates as, and with which
// password, are the ones it accepted. Other spec edits do not suspend the
// credential while the controller has not caught up (it may be down); a
// changed ServiceAccount or bring-your-own hash does, so a replaced hash is
// revoked at once. The controller sets Ready=False for excluded
// namespaces, missing ServiceAccounts and similar problems, and status can
// only be written by the controller.
func Usable(mc *sigv1.MailCredential) bool {
	ready := meta.FindStatusCondition(mc.Status.Conditions, sigv1.ConditionReady)
	if ready == nil || ready.Status != metav1.ConditionTrue ||
		mc.Status.ServiceAccountName != mc.Spec.ServiceAccountName {
		return false
	}
	if !mc.Generated() {
		return mc.Status.Current != nil && mc.Status.Current.Hash == mc.Spec.PasswordHash
	}
	return true
}
