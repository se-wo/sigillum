package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"

	"github.com/se-wo/sigillum/internal/oauth"
)

// clientSecretEnv passes a client secret without putting it on the
// command line.
const clientSecretEnv = "SIGILLUM_OAUTH_CLIENT_SECRET"

const oauthUsage = `usage: sigillum oauth login --provider microsoft|google --client-id ID [flags]

Signs in once in a browser on this machine (authorization code with PKCE and
a loopback redirect) and prints the refresh token, or stores it in the
credentials Secret of a backend with your own kubeconfig (--secret).
`

// runOAuth implements `sigillum oauth login` (SPEC US-6.3).
func runOAuth(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "login" {
		fmt.Fprint(stderr, oauthUsage)
		return 2
	}
	fs := flag.NewFlagSet("oauth login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	provider := fs.String("provider", "", "microsoft or google")
	clientID := fs.String("client-id", "", "client ID of your own app registration / OAuth client")
	tenant := fs.String("tenant", "consumers", "Microsoft tenant: consumers, organizations, a tenant ID or domain")
	scopes := fs.String("scopes", "", "space-separated scopes (default: sending over SMTP for microsoft, gmail.send for google)")
	secretFile := fs.String("client-secret-file", "", "file holding the client secret (Google desktop clients); or set "+clientSecretEnv)
	secret := fs.String("secret", "", "store the result in this Secret, as namespace/name, instead of printing it")
	timeout := fs.Duration("timeout", 5*time.Minute, "how long to wait for the sign-in")
	fs.Usage = func() { fmt.Fprint(stderr, oauthUsage); fs.PrintDefaults() }
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	clientSecret := os.Getenv(clientSecretEnv)
	if *secretFile != "" {
		b, err := os.ReadFile(*secretFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		clientSecret = strings.TrimSpace(string(b))
	}
	login, err := authCodeFor(*provider, *clientID, *tenant, clientSecret, strings.Fields(*scopes))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var ns, name string
	if *secret != "" {
		var ok bool
		if ns, name, ok = strings.Cut(*secret, "/"); !ok || ns == "" || name == "" {
			fmt.Fprintln(stderr, "--secret must be namespace/name")
			return 2
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()
	res, err := login.Login(ctx, func(authURL string) {
		fmt.Fprintf(stderr, "Open this URL in a browser on this machine and sign in:\n\n  %s\n\n", authURL)
	})
	if err != nil {
		fmt.Fprintln(stderr, "sign-in failed:", err)
		return 1
	}
	if *secret == "" {
		fmt.Fprintln(stdout, res.RefreshToken)
		return 0
	}
	cfg, err := ctrl.GetConfig()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	kube, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	data := map[string]string{"refresh_token": res.RefreshToken}
	if clientSecret != "" {
		data["client_secret"] = clientSecret
	}
	if err := storeSecret(ctx, kube, ns, name, data); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	fmt.Fprintf(stderr, "Stored the refresh token in Secret %s/%s; the controller picks it up on its next reconcile.\n", ns, name)
	return 0
}

// authCodeFor configures the sign-in for a provider.
func authCodeFor(provider, clientID, tenant, clientSecret string, scopes []string) (*oauth.AuthCode, error) {
	if clientID == "" {
		return nil, errors.New("--client-id is required")
	}
	a := &oauth.AuthCode{ClientID: clientID, ClientSecret: clientSecret, Scopes: scopes}
	switch provider {
	case "microsoft":
		var err error
		if a.AuthURL, err = oauth.MicrosoftAuthURL(tenant); err != nil {
			return nil, err
		}
		if a.TokenURL, err = oauth.MicrosoftTokenURL(tenant); err != nil {
			return nil, err
		}
		if len(a.Scopes) == 0 {
			a.Scopes = []string{"https://outlook.office.com/SMTP.Send", "offline_access"}
		}
	case "google":
		if clientSecret == "" {
			return nil, errors.New("google desktop clients need their client secret: --client-secret-file or " + clientSecretEnv)
		}
		a.AuthURL, a.TokenURL = oauth.GoogleAuthURL, oauth.GoogleTokenURL
		// A refresh token, every time: Google sends one only on consent.
		a.Params = url.Values{"access_type": {"offline"}, "prompt": {"consent"}}
		if len(a.Scopes) == 0 {
			a.Scopes = []string{"https://www.googleapis.com/auth/gmail.send"}
		}
	default:
		return nil, fmt.Errorf("--provider must be microsoft or google, got %q", provider)
	}
	return a, nil
}

// storeSecret writes data into the Secret, creating it if needed; other
// keys stay as they are.
func storeSecret(ctx context.Context, kube kubernetes.Interface, ns, name string, data map[string]string) error {
	secrets := kube.CoreV1().Secrets(ns)
	_, err := secrets.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Type: corev1.SecretTypeOpaque, StringData: data}, metav1.CreateOptions{})
	if !apierrors.IsAlreadyExists(err) {
		return err
	}
	patch, err := json.Marshal(map[string]any{"stringData": data})
	if err != nil {
		return err
	}
	_, err = secrets.Patch(ctx, name, types.StrategicMergePatchType, patch, metav1.PatchOptions{})
	return err
}
