package smtpproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/cluster"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/apiserver/auth"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/gateway"
	"github.com/se-wo/sigillum/internal/policy/ratelimit"
	"github.com/se-wo/sigillum/internal/telemetry"

	// pull in the SMTP driver so the registry has it at startup
	_ "github.com/se-wo/sigillum/internal/driver/smtp"
)

// Auth mode names accepted by --auth-modes.
const (
	ModeOAuthBearer = "oauthbearer"
	ModePodIP       = "podip"
)

// Options is the parsed command line of --mode=smtp.
type Options struct {
	Listen            string
	MetricsListen     string
	Domain            string
	AuthModes         []string
	AllowInsecureAuth bool
	MaxMessageBytes   int64
	MaxRecipients     int
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	AuthTimeout       time.Duration
	ShutdownTimeout   time.Duration
	TokenAudience     string
	TokenCacheSize    int
	TokenCacheTTL     time.Duration
	AuditLog          string
	RateLimit         ratelimit.Config
}

// ParseFlags parses args into Options.
func ParseFlags(args []string) (*Options, error) {
	o := &Options{}
	var modes string
	fs := flag.NewFlagSet("smtp", flag.ContinueOnError)
	_ = fs.String("mode", "", "operating mode (handled by entrypoint)")
	fs.StringVar(&o.Listen, "listen", ":2587", "SMTP submission listen address (unprivileged; map port 587 in the Service)")
	fs.StringVar(&o.MetricsListen, "metrics-listen", ":9090", "listen address for /metrics, /healthz and /readyz")
	fs.StringVar(&o.Domain, "domain", "sigillum", "host name announced in the SMTP greeting")
	fs.StringVar(&modes, "auth-modes", ModeOAuthBearer, "comma-separated caller identification modes: oauthbearer, podip (legacy, still requires legacyAuth.podIPFallback per policy)")
	fs.BoolVar(&o.AllowInsecureAuth, "allow-insecure-auth", true, "allow AUTH without STARTTLS (cluster-internal traffic, ideally mesh-encrypted)")
	fs.Int64Var(&o.MaxMessageBytes, "max-message-bytes", 32*1024*1024, "hard ceiling per message (policies enforce lower limits)")
	fs.IntVar(&o.MaxRecipients, "max-recipients", 100, "hard ceiling of RCPT TO per message")
	fs.DurationVar(&o.ReadTimeout, "read-timeout", 60*time.Second, "per-command read timeout")
	fs.DurationVar(&o.WriteTimeout, "write-timeout", 60*time.Second, "per-reply write timeout")
	fs.DurationVar(&o.AuthTimeout, "auth-timeout", 10*time.Second, "timeout for TokenReview and pod lookups")
	fs.DurationVar(&o.ShutdownTimeout, "shutdown-timeout", 25*time.Second, "graceful shutdown deadline")
	fs.StringVar(&o.TokenAudience, "token-audience", "sigillum", "expected audience in projected ServiceAccount tokens")
	fs.IntVar(&o.TokenCacheSize, "token-cache-size", 4096, "LRU cache capacity for TokenReview results")
	fs.DurationVar(&o.TokenCacheTTL, "token-cache-ttl", 5*time.Minute, "cache TTL for TokenReview results")
	fs.StringVar(&o.AuditLog, "audit-log", "stdout", "audit stream sink: stdout, stderr, none, or a file path")
	o.RateLimit.BindFlags(fs)
	if err := fs.Parse(args); err != nil && err != flag.ErrHelp {
		return nil, err
	}
	for _, m := range strings.Split(modes, ",") {
		m = strings.TrimSpace(strings.ToLower(m))
		switch m {
		case "":
		case ModeOAuthBearer, ModePodIP:
			o.AuthModes = append(o.AuthModes, m)
		default:
			return nil, fmt.Errorf("unknown auth mode %q (want %s or %s)", m, ModeOAuthBearer, ModePodIP)
		}
	}
	if len(o.AuthModes) == 0 {
		return nil, errors.New("--auth-modes must enable at least one mode")
	}
	return o, nil
}

func (o *Options) has(mode string) bool {
	for _, m := range o.AuthModes {
		if m == mode {
			return true
		}
	}
	return false
}

// NewServer builds the go-smtp server around backend. STARTTLS is offered
// when tlsCfg is non-nil.
func NewServer(o *Options, backend smtp.Backend, tlsCfg *tls.Config) *smtp.Server {
	s := smtp.NewServer(backend)
	s.Addr = o.Listen
	s.Domain = o.Domain
	s.MaxMessageBytes = o.MaxMessageBytes
	s.MaxRecipients = o.MaxRecipients
	s.ReadTimeout = o.ReadTimeout
	s.WriteTimeout = o.WriteTimeout
	s.AllowInsecureAuth = o.AllowInsecureAuth
	s.TLSConfig = tlsCfg
	return s
}

// Run starts the SMTP proxy and blocks until SIGTERM.
func Run(logger *slog.Logger) error {
	o, err := ParseFlags(os.Args[1:])
	if err != nil {
		return err
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(sigv1.AddToScheme(scheme))

	cfg, err := ctrl.GetConfig()
	if err != nil {
		return err
	}
	cl, err := cluster.New(cfg, func(co *cluster.Options) {
		co.Scheme = scheme
		// The pod informer (pod-IP mode) spans the cluster; drop managed
		// fields to keep its memory footprint down.
		co.Cache.DefaultTransform = cache.TransformStripManagedFields()
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	shutdownTracing, tracingOn, err := telemetry.InitTracing(ctx, "sigillum-smtp")
	if err != nil {
		return err
	}
	defer func() {
		flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = shutdownTracing(flushCtx)
	}()

	backend := &Backend{Logger: logger, AuthTimeout: o.AuthTimeout}
	if o.has(ModeOAuthBearer) {
		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}
		authn, err := auth.New(clientset, []string{o.TokenAudience}, o.TokenCacheSize, o.TokenCacheTTL)
		if err != nil {
			return err
		}
		backend.Tokens = authn
	}
	if o.has(ModePodIP) {
		if err := cl.GetFieldIndexer().IndexField(ctx, &corev1.Pod{}, PodIPIndex, IndexPodIP); err != nil {
			return fmt.Errorf("index pods by IP: %w", err)
		}
		backend.Pods = CachedPodResolver{C: cl.GetClient()}
		logger.Warn("pod-IP legacy authentication enabled; only policies with legacyAuth.podIPFallback accept it")
	}

	auditLogger, err := audit.FromFlag(o.AuditLog)
	if err != nil {
		return err
	}
	limiter, err := o.RateLimit.Build(logger)
	if err != nil {
		return err
	}
	backend.Sender = &gateway.Gateway{
		Logger:   logger,
		Audit:    auditLogger,
		Policies: gateway.CachedPolicyStore{C: cl.GetClient()},
		Reader:   cl.GetClient(),
		Limiter:  limiter,
	}

	go func() {
		if err := cl.Start(ctx); err != nil {
			logger.Error("informer cache stopped with error", "err", err)
		}
	}()
	var synced, draining atomic.Bool
	go func() {
		if cl.GetCache().WaitForCacheSync(ctx) {
			synced.Store(true)
			logger.Info("informer cache synced")
		}
	}()

	var tlsCfg *tls.Config
	if cert, key := os.Getenv("SIGILLUM_TLS_CERT"), os.Getenv("SIGILLUM_TLS_KEY"); cert != "" && key != "" {
		pair, err := tls.LoadX509KeyPair(cert, key)
		if err != nil {
			return fmt.Errorf("load STARTTLS certificate: %w", err)
		}
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
	}
	srv := NewServer(o, backend, tlsCfg)

	opsSrv := &http.Server{
		Addr:              o.MetricsListen,
		Handler:           opsHandler(&synced, &draining),
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 2)
	go func() {
		logger.Info("smtp proxy listening", "addr", o.Listen, "auth_modes", strings.Join(o.AuthModes, ","),
			"starttls", tlsCfg != nil, "tracing", tracingOn)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, smtp.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		if err := opsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining")
	case err := <-errCh:
		return err
	}
	draining.Store(true)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), o.ShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		// Idle clients still holding a session; they are cut off when the
		// process exits.
		logger.Warn("smtp shutdown deadline reached with open sessions", "err", err)
	}
	_ = opsSrv.Shutdown(shutdownCtx)
	return nil
}

func opsHandler(synced, draining *atomic.Bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(telemetry.Registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		switch {
		case draining.Load():
			http.Error(w, "draining", http.StatusServiceUnavailable)
		case !synced.Load():
			http.Error(w, "informer cache not synced", http.StatusServiceUnavailable)
		default:
			_, _ = w.Write([]byte("ready"))
		}
	})
	return mux
}
