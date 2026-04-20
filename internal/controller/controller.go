// Package controller hosts the controller-runtime manager that reconciles
// MailBackend, ClusterMailBackend and MailPolicy and serves the validating
// admission webhooks.
package controller

import (
	"flag"
	"log/slog"
	"os"

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
	whv1 "github.com/se-wo/sigillum/internal/webhook"

	// pull in the SMTP driver so the registry has it at startup
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
			metricsAddr           string
			probeAddr             string
			webhookPort           int
			enableLeaderElection  bool
			leaderElectionID      string
			webhookCertDir        string
			disableWebhook        bool
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

		// Allow flags to be passed after --mode=controller.
		if err := fs.Parse(os.Args[1:]); err != nil && err != flag.ErrHelp {
			return err
		}

		ctrl.SetLogger(zap.New(zap.UseDevMode(false)))
		setupLog := log.Log.WithName("setup")

		opts := ctrl.Options{
			Scheme:                  scheme,
			Metrics:                 metricsserver.Options{BindAddress: metricsAddr},
			HealthProbeBindAddress:  probeAddr,
			LeaderElection:          enableLeaderElection,
			LeaderElectionID:        leaderElectionID,
			LeaderElectionNamespace: os.Getenv("POD_NAMESPACE"),
		}
		if !disableWebhook {
			opts.WebhookServer = webhook.NewServer(webhook.Options{
				Port:    webhookPort,
				CertDir: webhookCertDir,
			})
		}

		mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), opts)
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
		}

		if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
			return err
		}
		if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
			return err
		}
		setupLog.Info("starting controller manager")
		return mgr.Start(ctrl.SetupSignalHandler())
	}
}
