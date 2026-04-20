//go:build envtest

// Envtest-backed integration tests for reconcilers and webhooks. Runs
// against a real apiserver/etcd pair provisioned by `setup-envtest` — the
// harness is wired up by the `envtest` make target which sets
// KUBEBUILDER_ASSETS. The build tag keeps the suite out of `go test ./...`
// for contributors without envtest installed.
package controller

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	whv1 "github.com/se-wo/sigillum/internal/webhook"
)

var (
	testEnv    *envtest.Environment
	testCfg    *rest.Config
	testClient client.Client
	testScheme = runtime.NewScheme()
	testCancel context.CancelFunc
)

func TestMain(m *testing.M) {
	utilruntime.Must(clientgoscheme.AddToScheme(testScheme))
	utilruntime.Must(sigv1.AddToScheme(testScheme))

	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	log.SetLogger(zap.New(zap.UseDevMode(true)))

	// Repo-root relative paths, resolved from this file's location.
	root, _ := filepath.Abs(filepath.Join("..", ".."))
	testEnv = &envtest.Environment{
		CRDDirectoryPaths:     []string{filepath.Join(root, "config", "crd", "bases")},
		ErrorIfCRDPathMissing: true,
		WebhookInstallOptions: envtest.WebhookInstallOptions{
			Paths: []string{filepath.Join(root, "config", "webhook")},
		},
	}
	cfg, err := testEnv.Start()
	if err != nil {
		panic(err)
	}
	testCfg = cfg

	cl, err := client.New(cfg, client.Options{Scheme: testScheme})
	if err != nil {
		_ = testEnv.Stop()
		panic(err)
	}
	testClient = cl

	whOpts := testEnv.WebhookInstallOptions
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:  testScheme,
		Metrics: metricsserver.Options{BindAddress: "0"},
		WebhookServer: webhook.NewServer(webhook.Options{
			Host:    whOpts.LocalServingHost,
			Port:    whOpts.LocalServingPort,
			CertDir: whOpts.LocalServingCertDir,
		}),
	})
	if err != nil {
		_ = testEnv.Stop()
		panic(err)
	}

	if err := whv1.SetupMailBackendWebhook(mgr); err != nil {
		panic(err)
	}
	if err := whv1.SetupClusterMailBackendWebhook(mgr); err != nil {
		panic(err)
	}
	if err := whv1.SetupMailPolicyWebhook(mgr); err != nil {
		panic(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	testCancel = cancel
	go func() {
		if err := mgr.Start(ctx); err != nil {
			panic(err)
		}
	}()

	// Wait for webhook server to come up before running tests.
	if err := waitForWebhookServer(whOpts.LocalServingHost, whOpts.LocalServingPort); err != nil {
		cancel()
		_ = testEnv.Stop()
		panic(err)
	}

	code := m.Run()

	cancel()
	_ = testEnv.Stop()
	os.Exit(code)
}

// waitForWebhookServer polls the webhook TLS port until it accepts
// connections, or times out. envtest installs the ValidatingWebhookConfig
// pointing at LocalServingHost:LocalServingPort so API writes will hang
// until the server is reachable.
func waitForWebhookServer(host string, port int) error {
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		d := net.Dialer{Timeout: 500 * time.Millisecond}
		conn, err := d.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return errWebhookTimeout
}

var errWebhookTimeout = errors.New("webhook server did not become ready within timeout")
