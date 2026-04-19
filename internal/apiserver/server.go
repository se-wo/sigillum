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
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/cluster"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/apiserver/auth"
	"github.com/se-wo/sigillum/internal/apiserver/problem"
	"github.com/se-wo/sigillum/internal/policy/ratelimit"
	"github.com/se-wo/sigillum/internal/telemetry"

	// pull in the SMTP driver so the registry has it at startup
	_ "github.com/se-wo/sigillum/internal/driver/smtp"
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
	logger      *slog.Logger
	policyStore PolicyStore
	k8sReader   client.Client
	limiter     ratelimit.Limiter
	authn       *auth.Authenticator
	router      http.Handler

	cacheSynced atomic.Bool
	shutting    atomic.Bool
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
		if err := fs.Parse(os.Args[1:]); err != nil && err != flag.ErrHelp {
			return err
		}

		cfg, err := ctrl.GetConfig()
		if err != nil {
			return err
		}
		clientset, err := kubernetes.NewForConfig(cfg)
		if err != nil {
			return err
		}
		cl, err := cluster.New(cfg, func(o *cluster.Options) {
			o.Scheme = scheme
		})
		if err != nil {
			return err
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		go func() {
			if startErr := cl.Start(ctx); startErr != nil {
				logger.Error("informer cache stopped with error", "err", startErr)
			}
		}()

		authn, err := auth.New(clientset, []string{audience}, tokenCacheSize, tokenCacheTTL)
		if err != nil {
			return err
		}

		s := &Server{
			logger:      logger,
			policyStore: newCachedPolicyStore(cl.GetClient()),
			k8sReader:   cl.GetClient(),
			limiter:     ratelimit.NewMemoryLimiter(),
			authn:       authn,
		}
		s.router = s.buildRouter()

		go func() {
			if cl.GetCache().WaitForCacheSync(ctx) {
				s.cacheSynced.Store(true)
				logger.Info("informer cache synced")
			}
		}()

		mainSrv := &http.Server{
			Addr:              addr,
			Handler:           s.router,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       60 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		metricsSrv := &http.Server{
			Addr:              metricsAddr,
			Handler:           metricsHandler(),
			ReadHeaderTimeout: 5 * time.Second,
		}

		errCh := make(chan error, 2)
		go func() {
			logger.Info("api-server listening", "addr", addr)
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
			problem.Write(w, problem.New(problem.TypeInvalidToken, http.StatusUnauthorized,
				"Missing Bearer token", "set Authorization: Bearer <token>"))
			return
		}
		subj, err := s.authn.Authenticate(r.Context(), token)
		if err != nil {
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
	cert := os.Getenv("SIGILLUM_TLS_CERT")
	key := os.Getenv("SIGILLUM_TLS_KEY")
	if cert != "" && key != "" {
		return s.ListenAndServeTLS(cert, key)
	}
	return s.ListenAndServe()
}
