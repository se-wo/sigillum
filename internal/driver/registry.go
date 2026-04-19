package driver

import (
	"fmt"
	"sync"
)

// Config is the parameter bundle every Factory accepts. Backend-type-specific
// fields live behind the Type discriminator — drivers must ignore fields they
// do not understand so the registry can stay generic.
type Config struct {
	Type       Type
	BackendKey string // namespace/name or /name (for cluster-scoped) — used in metric labels
	SMTP       *SMTPConfig
}

// SMTPConfig is the parsed shape of MailBackend.spec.smtp resolved against
// the referenced credentials secret.
type SMTPConfig struct {
	Endpoints []SMTPEndpoint
	AuthType  string // PLAIN | LOGIN | CRAM-MD5 | NONE
	Username  string
	Password  string
	Timeout   int32
	Helo      string
}

// SMTPEndpoint mirrors the API type but is local to driver to avoid a hard
// dependency on the API package from drivers.
type SMTPEndpoint struct {
	Host               string
	Port               int32
	TLS                string // none | starttls | tls
	InsecureSkipVerify bool
}

// Factory builds a Driver from a Config. Each registered backend type owns one.
type Factory func(cfg Config) (Driver, error)

var (
	registryMu sync.RWMutex
	registry   = map[Type]Factory{}
)

// Register installs a Factory for a backend type. Drivers register themselves
// from package init; the api-server and controller share the same registry.
func Register(t Type, f Factory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[t] = f
}

// New constructs a driver from cfg. Returns an error if the type is unknown,
// which the controller surfaces as Ready=False / UnsupportedBackendType.
func New(cfg Config) (Driver, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	f, ok := registry[cfg.Type]
	if !ok {
		return nil, fmt.Errorf("backend type %q is not implemented in this build", cfg.Type)
	}
	return f(cfg)
}

// Implemented returns the set of registered backend types — used by the
// validating webhook to reject unknown types at admission time.
func Implemented() []Type {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Type, 0, len(registry))
	for t := range registry {
		out = append(out, t)
	}
	return out
}

// IsImplemented reports whether t has a registered factory.
func IsImplemented(t Type) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[t]
	return ok
}
