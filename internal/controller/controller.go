// Package controller hosts the controller-runtime manager that reconciles
// MailBackend, ClusterMailBackend, MailPolicy and MailCredential and serves the validating
// admission webhooks.
package controller

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/crdcheck"
	"github.com/se-wo/sigillum/internal/credential"
	"github.com/se-wo/sigillum/internal/kubecache"
	whv1 "github.com/se-wo/sigillum/internal/webhook"

	// pull in the SMTP driver so the registry has it at startup
	_ "github.com/se-wo/sigillum/internal/driver/graph"
	_ "github.com/se-wo/sigillum/internal/driver/smtp"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(sigv1.AddToScheme(scheme))
}

// run is the implementation hook so the entrypoint can dispatch by mode.
var run = func(_ *slog.Logger) error {
	return nil
}

// Run starts the controller manager. Flags below are evaluated by the
// already-parsed flag.CommandLine in the entrypoint, so re-parse here to pick
// up controller-specific flags appended after the program-wide ones.
func Run(logger *slog.Logger) error {
	return run(logger)
}

func init() {
	run = func(_ *slog.Logger) error {
		var (
			metricsAddr          string
			probeAddr            string
			webhookPort          int
			enableLeaderElection bool
			leaderElectionID     string
			webhookCertDir       string
			disableWebhook       bool
			clusterName          string
			secretNamespaces     string
			credentialsGenerated bool
			credentialExclude    string
			credentialGuardName  string
			credentialGuardCheck time.Duration
			serviceAccountName   string
			credentialSMTPHost   string
			credentialSMTPPort   int
			skipCRDCheck         bool
			shutdownDelay        time.Duration
		)
		fs := flag.NewFlagSet("controller", flag.ContinueOnError)
		// --mode is consumed by the entrypoint; accept it here so Parse does
		// not error out on it.
		_ = fs.String("mode", "", "operating mode (handled by entrypoint)")
		fs.StringVar(&metricsAddr, "metrics-bind-address", ":8080", "address the metric endpoint binds to")
		fs.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "address health/readiness probes bind to")
		fs.IntVar(&webhookPort, "webhook-port", 9443, "port the validating webhook server listens on")
		fs.BoolVar(&enableLeaderElection, "leader-elect", true, "enable leader election")
		fs.StringVar(&leaderElectionID, "leader-elect-id", "sigillum-controller.sigillum.dev", "leader election lock name")
		fs.StringVar(&webhookCertDir, "webhook-cert-dir", "/etc/sigillum/webhook-tls", "directory holding webhook tls.crt and tls.key")
		fs.BoolVar(&disableWebhook, "disable-webhook", false, "disable the validating webhook server")
		fs.DurationVar(&shutdownDelay, "shutdown-delay", 5*time.Second, "on SIGTERM, fail readiness and keep the webhook server running for this long before shutting down, so the pod leaves the webhook Service endpoints first")
		fs.StringVar(&clusterName, "cluster-name", "", "cluster name added to every log line (US-4.5)")
		fs.StringVar(&secretNamespaces, "secret-namespaces", "", "comma-separated namespaces whose Secrets may be read (backend credentials); default: the pod's namespace")
		fs.BoolVar(&credentialsGenerated, "credentials-generated", false, "issue generated MailCredential passwords into Secrets; needs the credential Secret guard, POD_NAMESPACE and the ServiceAccount name (the chart sets all of them)")
		fs.StringVar(&credentialExclude, "credential-exclude-namespaces", "kube-*", "comma-separated namespaces (exact, or prefixes ending in *) that may not hold MailCredentials; the pod's namespace is always excluded")
		fs.StringVar(&credentialGuardName, "credential-guard-name", "sigillum-credential-guard", "name of the credential Secret guard ValidatingAdmissionPolicy and binding")
		fs.DurationVar(&credentialGuardCheck, "credential-guard-check-interval", 5*time.Minute, "how often the credential Secret guard is re-verified")
		fs.StringVar(&serviceAccountName, "service-account-name", os.Getenv("POD_SERVICE_ACCOUNT"), "the controller's own ServiceAccount (the guard only applies to it)")
		fs.StringVar(&credentialSMTPHost, "credential-smtp-host", "", "SMTP proxy host written into generated credential Secrets")
		fs.IntVar(&credentialSMTPPort, "credential-smtp-port", 587, "SMTP proxy port written into generated credential Secrets")
		fs.BoolVar(&skipCRDCheck, "skip-crd-check", false, crdcheck.SkipFlagUsage)

		// Allow flags to be passed after --mode=controller.
		if err := fs.Parse(os.Args[1:]); err != nil && err != flag.ErrHelp {
			return err
		}

		if credentialGuardCheck <= 0 {
			return fmt.Errorf("--credential-guard-check-interval must be positive, got %s", credentialGuardCheck)
		}

		zlog := zap.New(zap.UseDevMode(false))
		if clusterName != "" {
			zlog = zlog.WithValues("cluster", clusterName)
		}
		ctrl.SetLogger(zlog)
		setupLog := log.Log.WithName("setup")

		releaseNs := os.Getenv("POD_NAMESPACE")
		exclusions := credential.ParseExclusions(credentialExclude, releaseNs)
		if err := exclusions.Validate(); err != nil {
			return fmt.Errorf("--credential-exclude-namespaces: %w", err)
		}
		if credentialSMTPPort < 1 || credentialSMTPPort > 65535 {
			return fmt.Errorf("--credential-smtp-port must be between 1 and 65535, got %d", credentialSMTPPort)
		}

		opts := ctrl.Options{
			Scheme:                  scheme,
			Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
			HealthProbeBindAddress:  probeAddr,
			LeaderElection:          enableLeaderElection,
			LeaderElectionID:        leaderElectionID,
			LeaderElectionNamespace: releaseNs,
		}
		kubecache.RestrictSecretCache(&opts.Cache, kubecache.SecretNamespaces(secretNamespaces))
		if !disableWebhook {
			opts.WebhookServer = webhook.NewServer(webhook.Options{
				Port:    webhookPort,
				CertDir: webhookCertDir,
			})
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
		mgr, err := ctrl.NewManager(cfg, opts)
		if err != nil {
			return err
		}

		if err := (&MailBackendReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
			return err
		}
		if err := (&ClusterMailBackendReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
			return err
		}
		if err := (&MailPolicyReconciler{Client: mgr.GetClient(), Scheme: mgr.GetScheme()}).SetupWithManager(mgr); err != nil {
			return err
		}

		credReconciler := &MailCredentialReconciler{
			Client:           mgr.GetClient(),
			APIReader:        mgr.GetAPIReader(),
			Exclusions:       exclusions,
			GeneratedEnabled: credentialsGenerated,
			SMTPHost:         credentialSMTPHost,
			SMTPPort:         int32(credentialSMTPPort),
		}
		if credentialsGenerated {
			if releaseNs == "" || serviceAccountName == "" {
				return fmt.Errorf("--credentials-generated needs POD_NAMESPACE and --service-account-name to verify the credential Secret guard")
			}
			guard := credential.Guard{
				Name:               credentialGuardName,
				ControllerUsername: "system:serviceaccount:" + releaseNs + ":" + serviceAccountName,
				Exclusions:         exclusions,
			}
			checker := NewGuardChecker(guard, mgr.GetAPIReader(), mgr.GetClient(), credentialGuardCheck,
				log.Log.WithName("credential-guard"))
			// Verify before any reconciler runs, so none acts on an
			// unknown verdict.
			checkCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			checker.Check(checkCtx)
			cancel()
			if err := mgr.Add(checker); err != nil {
				return err
			}
			if err := mgr.Add(checker.Requeuer()); err != nil {
				return err
			}
			credReconciler.Guard = checker
		}
		if err := credReconciler.SetupWithManager(mgr); err != nil {
			return err
		}

		if !disableWebhook {
			if err := whv1.SetupMailBackendWebhook(mgr); err != nil {
				return err
			}
			if err := whv1.SetupClusterMailBackendWebhook(mgr); err != nil {
				return err
			}
			if err := whv1.SetupMailPolicyWebhook(mgr); err != nil {
				return err
			}
			if err := whv1.SetupMailCredentialWebhook(mgr, &whv1.MailCredentialValidator{
				Exclusions:       exclusions,
				GeneratedEnabled: credentialsGenerated,
			}); err != nil {
				return err
			}
		}

		if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
			return err
		}
		// On SIGTERM the webhook server must keep answering while the pod is
		// removed from the Service endpoints; otherwise, with one replica and
		// failurePolicy Fail, every admission request in that window fails
		// (#74). Readiness fails as soon as draining starts, and the manager
		// (which stops the webhook server) is not shut down until a drain
		// delay has passed.
		var draining atomic.Bool
		if err := mgr.AddReadyzCheck("drain", func(*http.Request) error {
			if draining.Load() {
				return errors.New("draining")
			}
			return nil
		}); err != nil {
			return err
		}
		if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
			return err
		}
		setupLog.Info("starting controller manager", "credentials_generated", credentialsGenerated,
			"credential_exclude_namespaces", credentialExclude)
		return mgr.Start(drainContext(shutdownDelay, func() {
			draining.Store(true)
			setupLog.Info("draining: failing readiness, keeping the webhook up", "delay", shutdownDelay.String())
		}))
	}
}

// drainContext returns a context cancelled a drain delay after the first
// SIGINT/SIGTERM. onSignal runs immediately on that signal (to fail
// readiness) while the manager, and with it the webhook server, keeps
// running until the delay passes, so the pod leaves the Service endpoints
// before the webhook stops answering. A second signal cancels at once; a
// third forces exit, matching controller-runtime's own handler.
func drainContext(delay time.Duration, onSignal func()) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 3)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		drainOnSignal(ch, delay, onSignal, cancel)
		<-ch
		os.Exit(1)
	}()
	return ctx
}

// drainOnSignal waits for the first signal, runs onSignal, then cancels
// after delay (or at once on a second signal). Split out for testing.
func drainOnSignal(ch <-chan os.Signal, delay time.Duration, onSignal, cancel func()) {
	<-ch
	onSignal()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ch:
		}
	}
	cancel()
}
