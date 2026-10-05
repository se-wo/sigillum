package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestAuthCodeFor(t *testing.T) {
	a, err := authCodeFor("microsoft", "id", "consumers", "", nil)
	if err != nil || a.AuthURL != "https://login.microsoftonline.com/consumers/oauth2/v2.0/authorize" ||
		a.TokenURL != "https://login.microsoftonline.com/consumers/oauth2/v2.0/token" ||
		strings.Join(a.Scopes, " ") != "https://outlook.office.com/SMTP.Send offline_access" {
		t.Fatalf("microsoft: %+v, %v", a, err)
	}
	a, err = authCodeFor("google", "id", "", "s3cret", nil)
	if err != nil || a.Params.Get("access_type") != "offline" || a.Params.Get("prompt") != "consent" ||
		a.Scopes[0] != "https://www.googleapis.com/auth/gmail.send" {
		t.Fatalf("google: %+v, %v", a, err)
	}
	for name, call := range map[string]func() error{
		"no client ID":          func() error { _, err := authCodeFor("microsoft", "", "consumers", "", nil); return err },
		"unknown provider":      func() error { _, err := authCodeFor("yahoo", "id", "", "", nil); return err },
		"google without secret": func() error { _, err := authCodeFor("google", "id", "", "", nil); return err },
		"tenant with a path":    func() error { _, err := authCodeFor("microsoft", "id", "x/../y", "", nil); return err },
	} {
		if call() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRunOAuthUsage(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{"logout"},
		{"login", "--provider", "yahoo", "--client-id", "id"},
		{"login", "--provider", "microsoft", "--client-id", "id", "--secret", "no-namespace"},
	} {
		var out, errOut bytes.Buffer
		if code := runOAuth(args, &out, &errOut); code != 2 || out.Len() != 0 {
			t.Errorf("%v: exit %d, stdout %q", args, code, out.String())
		}
	}
	var out, errOut bytes.Buffer
	if code := runOAuth([]string{"login", "--help"}, &out, &errOut); code != 0 || !strings.Contains(errOut.String(), "--provider") {
		t.Fatalf("--help: exit %d, %q", code, errOut.String())
	}
}

func TestStoreSecret(t *testing.T) {
	ctx := context.Background()
	kube := fake.NewSimpleClientset()
	if err := storeSecret(ctx, kube, "sigillum-system", "outlook-signin", map[string]string{"refresh_token": "rt-1"}); err != nil {
		t.Fatal(err)
	}
	sec, err := kube.CoreV1().Secrets("sigillum-system").Get(ctx, "outlook-signin", metav1.GetOptions{})
	if err != nil || sec.StringData["refresh_token"] != "rt-1" || sec.Type != corev1.SecretTypeOpaque {
		t.Fatalf("created: %+v, %v", sec, err)
	}

	// An existing Secret keeps its other keys.
	kube = fake.NewSimpleClientset(&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "gmail", Namespace: "home"},
		Data: map[string][]byte{"other": []byte("kept")}})
	if err := storeSecret(ctx, kube, "home", "gmail", map[string]string{"refresh_token": "rt-2", "client_secret": "cs"}); err != nil {
		t.Fatal(err)
	}
	sec, err = kube.CoreV1().Secrets("home").Get(ctx, "gmail", metav1.GetOptions{})
	if err != nil || string(sec.Data["other"]) != "kept" || sec.StringData["refresh_token"] != "rt-2" || sec.StringData["client_secret"] != "cs" {
		t.Fatalf("patched: %+v, %v", sec, err)
	}
}
