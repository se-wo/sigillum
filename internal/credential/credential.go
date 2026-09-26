// Package credential implements Sigillum-issued SMTP credentials
// (MailCredential, US-3.7): usernames, password generation and hashing, the
// namespace exclusion list, and verification on the SMTP proxy.
//
// Generated passwords carry 256 bits of entropy, so a single SHA-256 is a
// safe and cheap hash for them. User-supplied passwords (bring-your-own-hash
// mode) may be weak and are hashed with argon2id instead.
package credential

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"k8s.io/apimachinery/pkg/util/validation"
)

// Username returns the SMTP username of a MailCredential. Namespace names
// cannot contain dots, so the last dot separates name and namespace and the
// username is unique cluster-wide.
func Username(name, namespace string) string {
	return name + "." + namespace
}

// ParseUsername splits a username into namespace and name.
func ParseUsername(u string) (namespace, name string, ok bool) {
	i := strings.LastIndexByte(u, '.')
	if i <= 0 || i == len(u)-1 {
		return "", "", false
	}
	return u[i+1:], u[:i], true
}

// GeneratePassword returns a 256-bit random password, base64url-encoded
// without padding (43 characters, safe in URLs, env vars and config files).
func GeneratePassword() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

const sha256Prefix = "sha256:"

// HashGenerated returns the status hash of a generated password.
//
// A fast hash is deliberate (SPEC Q-11): these passwords are 256 bits from
// crypto/rand, never chosen by a person, so a preimage search over 2^256 is
// infeasible regardless of hash speed, and a slow hash would only make every
// SMTP login expensive for the proxy. User-chosen passwords use argon2id
// (VerifyArgon2id). CodeQL's go/weak-sensitive-data-hashing alerts on this
// function and VerifyGenerated are false positives for that reason.
func HashGenerated(password string) string {
	sum := sha256.Sum256([]byte(password))
	return sha256Prefix + hex.EncodeToString(sum[:])
}

// VerifyGenerated reports whether password matches hash (constant time).
// SHA-256 is deliberate; see HashGenerated.
// IsGeneratedHash reports whether hash is the hash of a generated
// password, as opposed to a bring-your-own argon2id hash.
func IsGeneratedHash(hash string) bool { return strings.HasPrefix(hash, sha256Prefix) }

func VerifyGenerated(hash, password string) bool {
	if !strings.HasPrefix(hash, sha256Prefix) {
		return false
	}
	want, err := hex.DecodeString(strings.TrimPrefix(hash, sha256Prefix))
	if err != nil || len(want) != sha256.Size {
		return false
	}
	got := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(want, got[:]) == 1
}

// Bounds for bring-your-own argon2id hashes. The upper bounds cap what one
// AUTH attempt can cost the proxy (memory is allocated per verification);
// the lower bound follows the OWASP password storage recommendations
// (19 MiB x 2 passes, 7 MiB x 5 passes, ...: memory x passes >= 35 MiB).
const (
	Argon2MinMemoryKiB     = 7 * 1024
	Argon2MaxMemoryKiB     = 64 * 1024
	Argon2MinMemoryTimeKiB = 35 * 1024
	Argon2MaxTime          = 10
	Argon2MaxThreads       = 16
	argon2MinSaltLen       = 8
	argon2MinKeyLen        = 16
	argon2MaxKeyLen        = 64
)

// Argon2Params is a parsed argon2id PHC string.
type Argon2Params struct {
	MemoryKiB uint32
	Time      uint32
	Threads   uint8
	Salt      []byte
	Key       []byte
}

// ParseArgon2id parses "$argon2id$v=19$m=<KiB>,t=<n>,p=<n>$<salt>$<hash>"
// (salt and hash in unpadded standard base64) and enforces the bounds above.
func ParseArgon2id(phc string) (*Argon2Params, error) {
	parts := strings.Split(phc, "$")
	if len(parts) != 6 || parts[0] != "" {
		if !strings.HasPrefix(phc, "$") {
			return nil, errors.New("not a PHC hash string; expected $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash> (never the plaintext password)")
		}
		return nil, errors.New("malformed PHC string; expected $argon2id$v=19$m=...,t=...,p=...$<salt>$<hash>")
	}
	if parts[1] != "argon2id" {
		return nil, fmt.Errorf("unsupported hash algorithm %q, only argon2id is accepted", parts[1])
	}
	if parts[2] != "v=19" {
		return nil, fmt.Errorf("unsupported argon2 version %q, want v=19", parts[2])
	}
	p := &Argon2Params{}
	seen := map[string]bool{}
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || seen[k] {
			return nil, fmt.Errorf("malformed argon2 parameters %q", parts[3])
		}
		seen[k] = true
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed argon2 parameter %q", kv)
		}
		switch k {
		case "m":
			p.MemoryKiB = uint32(n)
		case "t":
			p.Time = uint32(n)
		case "p":
			if n > 255 {
				return nil, fmt.Errorf("argon2 parallelism %d out of range", n)
			}
			p.Threads = uint8(n)
		default:
			return nil, fmt.Errorf("unknown argon2 parameter %q", k)
		}
	}
	if !seen["m"] || !seen["t"] || !seen["p"] {
		return nil, errors.New("argon2 parameters m, t and p are required")
	}
	switch {
	case p.MemoryKiB < Argon2MinMemoryKiB || p.MemoryKiB > Argon2MaxMemoryKiB:
		return nil, fmt.Errorf("argon2 memory m=%d KiB out of range [%d, %d]", p.MemoryKiB, Argon2MinMemoryKiB, Argon2MaxMemoryKiB)
	case p.Time < 1 || p.Time > Argon2MaxTime:
		return nil, fmt.Errorf("argon2 iterations t=%d out of range [1, %d]", p.Time, Argon2MaxTime)
	case uint64(p.MemoryKiB)*uint64(p.Time) < Argon2MinMemoryTimeKiB:
		return nil, fmt.Errorf("argon2 parameters too weak: m x t must be at least %d KiB (for example m=19456,t=2)", Argon2MinMemoryTimeKiB)
	case p.Threads < 1 || p.Threads > Argon2MaxThreads:
		return nil, fmt.Errorf("argon2 parallelism p=%d out of range [1, %d]", p.Threads, Argon2MaxThreads)
	}
	var err error
	if p.Salt, err = decodeB64(parts[4]); err != nil || len(p.Salt) < argon2MinSaltLen {
		return nil, fmt.Errorf("argon2 salt must be base64 and at least %d bytes", argon2MinSaltLen)
	}
	if p.Key, err = decodeB64(parts[5]); err != nil || len(p.Key) < argon2MinKeyLen || len(p.Key) > argon2MaxKeyLen {
		return nil, fmt.Errorf("argon2 hash must be base64 and %d to %d bytes", argon2MinKeyLen, argon2MaxKeyLen)
	}
	return p, nil
}

// decodeB64 accepts unpadded (PHC) and padded standard base64.
func decodeB64(s string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(strings.TrimRight(s, "="))
}

// VerifyArgon2id reports whether password matches the PHC string. It costs
// up to Argon2MaxMemoryKiB of memory and noticeable CPU; callers bound
// concurrency.
func VerifyArgon2id(phc, password string) (bool, error) {
	p, err := ParseArgon2id(phc)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), p.Salt, p.Time, p.MemoryKiB, p.Threads, uint32(len(p.Key)))
	return subtle.ConstantTimeCompare(got, p.Key) == 1, nil
}

// HashArgon2id returns a PHC string for password (tests and tooling).
func HashArgon2id(password string, salt []byte, memoryKiB, t uint32, threads uint8) string {
	key := argon2.IDKey([]byte(password), salt, t, memoryKiB, threads, 32)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memoryKiB, t, threads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// ParseDuration parses a Go duration ("24h", "90m") or a whole number of
// days ("90d"). Negative values are rejected.
func ParseDuration(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseUint(days, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		d = time.Duration(n) * 24 * time.Hour
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil {
			return 0, fmt.Errorf("invalid duration %q (use a Go duration such as 24h, or days such as 90d)", s)
		}
	}
	if d < 0 {
		return 0, fmt.Errorf("duration %q must not be negative", s)
	}
	return d, nil
}

// DefaultGracePeriod applies when spec.rotation.gracePeriod is unset.
const DefaultGracePeriod = 24 * time.Hour

// Exclusions decides which namespaces may hold generated credentials.
type Exclusions struct {
	// Patterns are exact namespace names, or prefixes ending in "*".
	Patterns []string
	// ReleaseNamespace holds the relay credentials and is always excluded.
	ReleaseNamespace string
}

// ParseExclusions splits a comma-separated pattern list.
func ParseExclusions(list, releaseNamespace string) Exclusions {
	e := Exclusions{ReleaseNamespace: releaseNamespace}
	for _, p := range strings.Split(list, ",") {
		if p = strings.TrimSpace(p); p != "" {
			e.Patterns = append(e.Patterns, p)
		}
	}
	return e
}

// Excluded reports whether namespace ns may not hold credentials.
func (e Exclusions) Excluded(ns string) bool {
	if e.ReleaseNamespace != "" && ns == e.ReleaseNamespace {
		return true
	}
	for _, p := range e.Patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			if strings.HasPrefix(ns, prefix) {
				return true
			}
		} else if ns == p {
			return true
		}
	}
	return false
}

// split returns the exact names and the prefixes (without "*").
func (e Exclusions) split() (exact, prefixes []string) {
	exact, prefixes = []string{}, []string{}
	for _, p := range e.Patterns {
		if prefix, ok := strings.CutSuffix(p, "*"); ok {
			prefixes = append(prefixes, prefix)
		} else {
			exact = append(exact, p)
		}
	}
	return exact, prefixes
}

// GeneratedNameError reports why name cannot be the name of a generated
// MailCredential, or "" if it can. The generated Secret carries the name in
// the sigillum.dev/credential label, and label values have at most 63
// characters.
func GeneratedNameError(name string) string {
	if msgs := validation.IsValidLabelValue(name); len(msgs) > 0 {
		return "the name of a generated MailCredential becomes a label value of its Secret: " + strings.Join(msgs, "; ")
	}
	return ""
}
