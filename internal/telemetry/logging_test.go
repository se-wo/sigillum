package telemetry

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"k8s.io/klog/v2"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

func TestSnakeCase(t *testing.T) {
	for in, want := range map[string]string{
		"msg":             "msg",
		"message_id":      "message_id",
		"authMethod":      "auth_method",
		"reconcileID":     "reconcile_id",
		"controllerGroup": "controller_group",
		"MailBackend":     "mail_backend",
		"HTTPServer":      "http_server",
		"worker count":    "worker count",
		"x509Cert":        "x509_cert",
	} {
		if got := snakeCase(in); got != want {
			t.Errorf("snakeCase(%q) = %q, want %q", in, got, want)
		}
	}
}

func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug, ReplaceAttr: replaceAttr}))
}

func lines(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		out = append(out, m)
	}
	return out
}

// Every logger in the process writes the same JSON schema (#51).
func TestSetGlobalLogger(t *testing.T) {
	var buf bytes.Buffer
	SetGlobalLogger(newTestLogger(&buf).With("cluster", "prod"))
	t.Cleanup(func() {
		slog.SetDefault(slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
		klog.ClearLogger()
	})

	ctrllog.Log.WithName("setup").Info("from controller-runtime", "reconcileID", "abc")
	ctrllog.Log.V(1).Info("verbose")
	klog.InfoS("from klog", "podName", "p")
	log.Print("from std log")
	otel.Handle(errors.New("export failed"))

	got := lines(t, &buf)
	if len(got) != 5 {
		t.Fatalf("want 5 lines, got %d: %s", len(got), buf.String())
	}
	for _, l := range got {
		for _, k := range []string{"time", "level", "msg"} {
			if _, ok := l[k]; !ok {
				t.Errorf("no %q in %v", k, l)
			}
		}
		if l["cluster"] != "prod" {
			t.Errorf("no cluster in %v", l)
		}
	}
	if got[0]["reconcile_id"] != "abc" || got[0]["level"] != "INFO" || got[0]["logger"] != "setup" {
		t.Errorf("controller-runtime line: %v", got[0])
	}
	if got[1]["level"] != "DEBUG" {
		t.Errorf("V(1) line: %v", got[1])
	}
	if got[2]["pod_name"] != "p" {
		t.Errorf("klog line: %v", got[2])
	}
	if got[3]["msg"] != "from std log" {
		t.Errorf("std log line: %v", got[3])
	}
	if got[4]["level"] != "WARN" || got[4]["msg"] != "telemetry export failed" || got[4]["err"] != "export failed" {
		t.Errorf("otel line: %v", got[4])
	}
}

func TestOTelErrorHandlerRateLimit(t *testing.T) {
	var buf bytes.Buffer
	h := &otelErrorHandler{logger: newTestLogger(&buf), every: time.Hour}
	for i := 0; i < 5; i++ {
		h.Handle(errors.New("collector unreachable"))
	}
	if got := lines(t, &buf); len(got) != 1 {
		t.Fatalf("want one line per interval, got %d", len(got))
	}
	h.last = time.Now().Add(-2 * time.Hour)
	h.Handle(errors.New("collector unreachable"))
	got := lines(t, &buf)
	if len(got) != 2 || got[1]["suppressed_errors"] != float64(4) {
		t.Fatalf("want the suppressed count on the next line, got %v", got)
	}
}
