// Package apiserver implements the REST send path. The same binary serves
// both api and controller modes; this package owns the api side.
package apiserver

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/codes"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cluster"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/apiserver/auth"
	"github.com/se-wo/sigillum/internal/apiserver/problem"
	"github.com/se-wo/sigillum/internal/audit"
	"github.com/se-wo/sigillum/internal/crdcheck"
	"github.com/se-wo/sigillum/internal/gateway"
	"github.com/se-wo/sigillum/internal/kubecache"
	"github.com/se-wo/sigillum/internal/policy/ratelimit"
	"github.com/se-wo/sigillum/internal/telemetry"
	"github.com/se-wo/sigillum/internal/tlsreload"

	// pull in the SMTP driver so the registry has it at startup
	_ "github.com/se-wo/sigillum/internal/driver/graph"
	_ "github.com/se-wo/sigillum/internal/driver/smtp"
)

// writeTimeout is the main server's WriteTimeout: once it expires the
// connection is closed without a response. requestBudget bounds the work of
// one request, so the handler always answers before that: a send still
// running at the deadline gets a visible 502 instead of an empty reply
// while the message may already be on its way (#61).
const (
	writeTimeout  = 60 * time.Second
	requestBudget = writeTimeout - 10*time.Second
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(sigv1.AddToScheme(scheme))
}

// run is the implementation hook so the entrypoint can dispatch by mode.
var run = func(_ *slog.Logger) error { return nil }

// Server holds the live api-server state.
type Server struct {
	logger *slog.Logger
	gw     *gateway.Gateway
	authn  *auth.Authenticator
	router http.Handler

	cacheSynced atomic.Bool
	// draining fails readiness while requests are still served normally,
	// so endpoints are removed before the listener closes (G-3).
	draining atomic.Bool
	shutting atomic.Bool
}

// Run starts the api-server (blocking, returns when SIGTERM is observed).
func Run(logger *slog.Logger) error {
	return run(logger)
}

func init() {
	run = func(logger *slog.Logger) error {
		var (
			addr            string
			metricsAddr     string
			tokenCacheSize  int
			tokenCacheTTL   time.Duration
			audience        string
			shutdownTimeout time.Duration
			shutdownDelay   time.Duration
			auditLog        string
			clusterName     string
			secretNs        string
			skipCRDCheck    bool
			rlCfg           ratelimit.Config
		)
		fs := flag.NewFlagSet("api", flag.ContinueOnError)
		// --mode is consumed by the entrypoint; accept it here so Parse does
		// not error out on it.
		_ = fs.String("mode", "", "operating mode (handled by entrypoint)")
		fs.StringVar(&addr, "listen", ":8443", "HTTPS listen address (TLS via SIGILLUM_TLS_CERT/KEY) or HTTP if no cert configured")
		fs.StringVar(&metricsAddr, "metrics-listen", ":9090", "Prometheus metrics listen address")
		fs.IntVar(&tokenCacheSize, "token-cache-size", 4096, "LRU cache capacity for TokenReview results")
		fs.DurationVar(&tokenCacheTTL, "token-cache-ttl", 5*time.Minute, "cache TTL for TokenReview results")
		fs.StringVar(&audience, "token-audience", "sigillum", "expected audience in projected ServiceAccount tokens")
		fs.DurationVar(&shutdownTimeout, "shutdown-timeout", 25*time.Second, "graceful shutdown deadline")
		fs.DurationVar(&shutdownDelay, "shutdown-delay", 5*time.Second, "after SIGTERM, keep serving with readiness failing for this long before draining, so the pod leaves the Service endpoints first (a preStop delay)")
		fs.StringVar(&clusterName, "cluster-name", "", "cluster name added to audit records and log lines (US-4.5)")
		fs.StringVar(&secretNs, "secret-namespaces", "", "comma-separated namespaces whose Secrets may be read (backend credentials); default: the pod's namespace")
		fs.BoolVar(&skipCRDCheck, "skip-crd-check", false, crdcheck.SkipFlagUsage)
		rlCfg.BindFlags(fs)
		fs.StringVar(&auditLog, "audit-log", "stdout", "audit stream sink: stdout, stderr, none, or a file path")
		if err := fs.Parse(os.Args[1:]); err != nil && err != flag.ErrHelp {
			return err
		}

		cfg, err := ctrl.GetConfig()
		if err != nil {
			return err
		}
		if !skipCRDCheck {
			if err := crdcheck.Wait(context.Background(), cfg, crdcheck.Required, crdcheck.Timeout); err != nil {
				return err
			}
		}
		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}
		if clusterName != "" {
			logger = logger.With("cluster", clusterName)
		}
		cl, err := cluster.New(cfg, func(o *cluster.Options) {
			o.Scheme = scheme
			kubecache.RestrictSecretCache(&o.Cache, kubecache.SecretNamespaces(secretNs))
		})
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		shutdownTracing, tracingOn, err := telemetry.InitTracing(ctx, "sigillum-api")
		if err != nil {
			return err
		}
		defer func() {
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = shutdownTracing(flushCtx)
		}()
		logger.Info("tracing", "enabled", tracingOn)

		// The cache outlives SIGTERM: requests are still served during the
		// shutdown delay and drain, and must see policy changes.
		cacheCtx, stopCache := context.WithCancel(context.Background())
		defer stopCache()
		go func() {
			if startErr := cl.Start(cacheCtx); startErr != nil {
				logger.Error("informer cache stopped with error", "err", startErr)
			}
		}()

		authn, err := auth.New(clientset, []string{audience}, tokenCacheSize, tokenCacheTTL)
		if err != nil {
			return err
		}

		auditLogger, err := audit.FromFlag(auditLog)
		if err != nil {
			return err
		}
		auditLogger = audit.WithCluster(auditLogger, clusterName)
		limiter, err := rlCfg.Build(logger)
		if err != nil {
			return err
		}

		s := &Server{
			logger: logger,
			gw: &gateway.Gateway{
				Logger:   logger,
				Audit:    auditLogger,
				Policies: gateway.CachedPolicyStore{C: cl.GetClient()},
				Reader:   cl.GetClient(),
				Limiter:  limiter,
			},
			authn: authn,
		}
		s.router = s.buildRouter()

		go func() {
			if cl.GetCache().WaitForCacheSync(cacheCtx) {
				s.cacheSynced.Store(true)
				logger.Info("informer cache synced")
			}
		}()

		mainSrv := &http.Server{
			Addr:              addr,
			Handler:           s.router,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       120 * time.Second,
		}
		// The certificate is re-read when its files change, so a renewed
		// Secret takes effect without a restart (#75).
		tlsCfg, err := tlsreload.FromEnv(ctx, logger)
		if err != nil {
			return err
		}
		mainSrv.TLSConfig = tlsCfg
		metricsSrv := &http.Server{
			Addr:              metricsAddr,
			Handler:           metricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
		}

		errCh := make(chan error, 2)
		go func() {
			logger.Info("api-server listening", "addr", addr, "tls", tlsCfg != nil)
			err := serve(mainSrv)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()
		go func() {
			logger.Info("metrics endpoint listening", "addr", metricsAddr)
			err := metricsSrv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
			}
		}()

		select {
		case <-ctx.Done():
			logger.Info("shutdown signal received, draining")
		case err := <-errCh:
			logger.Error("server failed", "err", err)
			return err
		}

		s.draining.Store(true)
		if shutdownDelay > 0 {
			logger.Info("failing readiness before draining", "delay", shutdownDelay.String())
			time.Sleep(shutdownDelay)
		}
		s.shutting.Store(true)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = mainSrv.Shutdown(shutdownCtx)
		_ = metricsSrv.Shutdown(shutdownCtx)
		return nil
	}
}

func metricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(telemetry.Registry, promhttp.HandlerOpts{}))
	return mux
}

func (s *Server) buildRouter() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(s.requestLogger)

	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)
	r.Handle("/metrics", promhttp.HandlerFor(telemetry.Registry, promhttp.HandlerOpts{}))

	r.Route("/v1", func(r chi.Router) {
		// Trace the mail API only: probes and scrapes would otherwise emit
		// a root span each. Ahead of auth so auth.tokenreview nests under
		// http.request.
		r.Use(telemetry.HTTPMiddleware)
		r.Use(s.authMiddleware)
		r.Post("/messages", s.handleSendMessage)
	})
	return r
}

func (s *Server) requestLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)
		s.logger.Debug("http request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.Status(),
			"bytes", ww.BytesWritten(),
			"dur_ms", time.Since(start).Milliseconds(),
		)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r.Header.Get("Authorization"))
		if token == "" {
			s.gw.Reject(audit.Event{
				MessageID: uuid.NewString(),
				Transport: gateway.TransportREST,
			}, "missing_token")
			problem.Write(w, problem.New(problem.TypeInvalidToken, http.StatusUnauthorized,
				"Missing Bearer token", "set Authorization: Bearer <token>"))
			return
		}
		authCtx, span := telemetry.Tracer().Start(r.Context(), "auth.tokenreview")
		subj, err := s.authn.Authenticate(authCtx, token)
		if err != nil {
			span.SetStatus(codes.Error, "token rejected")
		}
		span.End()
		if errors.Is(err, auth.ErrUnavailable) {
			// Not a rejected token: the kube-apiserver could not be asked.
			s.logger.Warn("token review failed", "err", err)
			telemetry.AuthFailuresTotal.WithLabelValues(gateway.TransportREST, gateway.AuthOAuthBearer, "auth_unavailable").Inc()
			s.gw.Reject(audit.Event{
				MessageID: uuid.NewString(),
				Transport: gateway.TransportREST,
			}, "auth_unavailable")
			w.Header().Set("Retry-After", "5")
			problem.Write(w, problem.New(problem.TypeUnavailable, http.StatusServiceUnavailable,
				"Service temporarily unavailable", "the token could not be reviewed, try again later"))
			return
		}
		if err != nil {
			telemetry.AuthFailuresTotal.WithLabelValues(gateway.TransportREST, gateway.AuthOAuthBearer, "invalid_token").Inc()
			s.gw.Reject(audit.Event{
				MessageID: uuid.NewString(),
				Transport: gateway.TransportREST,
			}, "invalid_token")
			problem.Write(w, problem.New(problem.TypeInvalidToken, http.StatusUnauthorized,
				"Invalid token", err.Error()))
			return
		}
		ctx := withSubject(r.Context(), subject{Namespace: subj.Namespace, ServiceAccount: subj.ServiceAccount})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerToken(h string) string {
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// serve dispatches between TLS and plaintext based on env config.
func serve(s *http.Server) error {
	if s.TLSConfig != nil {
		return s.ListenAndServeTLS("", "")
	}
	return s.ListenAndServe()
}
