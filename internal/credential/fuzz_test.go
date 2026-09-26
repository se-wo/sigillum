package credential

import (
	"strings"
	"testing"
)

// Fuzz targets for the credential parsers that read MailCredential specs and
// SMTP AUTH input. Seeds run with every `go test`; `make fuzz` explores
// further (see CONTRIBUTING.md).

func FuzzParseArgon2id(f *testing.F) {
	for _, s := range []string{
		"$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA==",
		"$argon2i$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA",
		"$argon2id$v=19$m=19456,m=1,t=2,p=1$c2FsdHNhbHQ$aGFzaA",
		"$argon2id$v=19$m=4294967295,t=4294967295,p=255$$",
		"plaintext-password",
		"$$$$$",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, phc string) {
		p, err := ParseArgon2id(phc)
		if err != nil {
			return
		}
		// Whatever parses is what one AUTH attempt will cost the proxy, so
		// the bounds must hold for every accepted string.
		switch {
		case p.MemoryKiB < Argon2MinMemoryKiB || p.MemoryKiB > Argon2MaxMemoryKiB,
			p.Time < 1 || p.Time > Argon2MaxTime,
			uint64(p.MemoryKiB)*uint64(p.Time) < Argon2MinMemoryTimeKiB,
			p.Threads < 1 || p.Threads > Argon2MaxThreads,
			len(p.Salt) < argon2MinSaltLen,
			len(p.Key) < argon2MinKeyLen || len(p.Key) > argon2MaxKeyLen:
			t.Fatalf("ParseArgon2id(%q) accepted out-of-bounds parameters %+v", phc, p)
		}
	})
}

func FuzzParseUsername(f *testing.F) {
	for _, s := range []string{"grafana.monitoring", "argo.cd.notifications.argocd", "", "nodot", ".ns", "name.", "."} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, u string) {
		ns, name, ok := ParseUsername(u)
		if !ok {
			return
		}
		if ns == "" || name == "" || strings.Contains(ns, ".") {
			t.Fatalf("ParseUsername(%q) = %q, %q", u, ns, name)
		}
		if Username(name, ns) != u {
			t.Fatalf("Username(ParseUsername(%q)) = %q", u, Username(name, ns))
		}
	})
}

func FuzzVerifyGenerated(f *testing.F) {
	f.Add(HashGenerated("secret"), "secret")
	f.Add("sha256:", "")
	f.Add("sha256:zz", "x")
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaA", "x")
	f.Fuzz(func(t *testing.T, hash, password string) {
		if VerifyGenerated(hash, password) && hash != HashGenerated(password) &&
			!strings.EqualFold(hash, HashGenerated(password)) {
			t.Fatalf("VerifyGenerated(%q, %q) accepted a different hash", hash, password)
		}
		if !VerifyGenerated(HashGenerated(password), password) {
			t.Fatalf("VerifyGenerated rejects the hash of %q", password)
		}
	})
}
