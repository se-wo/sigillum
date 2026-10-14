package telemetry

import (
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/go-logr/logr"
	"go.opentelemetry.io/otel"
	"k8s.io/klog/v2"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"
)

// NewLogger returns a JSON slog logger whose level is read from SIGILLUM_LOG_LEVEL.
// Defaults to info. Output is stdout — operators aggregate via stdout/stderr per US-4.2.
// Attribute keys are written in snake_case, also those of controller-runtime
// and client-go, so every mode logs one schema (#51).
func NewLogger() *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(os.Getenv("SIGILLUM_LOG_LEVEL")) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level, ReplaceAttr: replaceAttr})
	return slog.New(h)
}

func replaceAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == slog.LevelKey {
		// logr's V(n) becomes slog level -n; name it DEBUG rather than
		// "DEBUG+3".
		if l, ok := a.Value.Any().(slog.Level); ok && l < slog.LevelInfo {
			a.Value = slog.StringValue(slog.LevelDebug.String())
		}
		return a
	}
	a.Key = snakeCase(a.Key)
	return a
}

// snakeCase turns a camelCase or PascalCase key (controller-runtime's
// "reconcileID", "MailBackend") into snake_case ("reconcile_id",
// "mail_backend"). Other keys are returned unchanged.
func snakeCase(s string) string {
	if strings.IndexFunc(s, unicode.IsUpper) < 0 || strings.ContainsAny(s, " _-.") {
		return s
	}
	r := []rune(s)
	var b strings.Builder
	for i, c := range r {
		if unicode.IsUpper(c) {
			lowerBefore := i > 0 && (unicode.IsLower(r[i-1]) || unicode.IsDigit(r[i-1]))
			acronymEnd := i > 0 && unicode.IsUpper(r[i-1]) && i+1 < len(r) && unicode.IsLower(r[i+1])
			if lowerBefore || acronymEnd {
				b.WriteByte('_')
			}
			c = unicode.ToLower(c)
		}
		b.WriteRune(c)
	}
	return b.String()
}

// SetGlobalLogger makes logger the destination of every other logger in
// the process: controller-runtime's, client-go's (klog), Go's standard log
// package and OpenTelemetry's error handler, which would otherwise write
// plain text or another JSON schema to the same stream (#51). Modes call it
// once their logger carries its final attributes (cluster).
func SetGlobalLogger(logger *slog.Logger) {
	slog.SetDefault(logger) // also redirects the standard log package
	lr := logr.FromSlogHandler(logger.Handler())
	ctrllog.SetLogger(lr)
	klog.SetLogger(lr)
	otel.SetErrorHandler(&otelErrorHandler{logger: logger, every: time.Minute})
}

// otelErrorHandler logs OpenTelemetry errors (an unreachable collector
// fails every export) at most once per interval.
type otelErrorHandler struct {
	logger *slog.Logger
	every  time.Duration

	mu         sync.Mutex
	last       time.Time
	suppressed int
}

func (h *otelErrorHandler) Handle(err error) {
	h.mu.Lock()
	now := time.Now()
	if !h.last.IsZero() && now.Sub(h.last) < h.every {
		h.suppressed++
		h.mu.Unlock()
		return
	}
	suppressed := h.suppressed
	h.last, h.suppressed = now, 0
	h.mu.Unlock()
	h.logger.Warn("telemetry export failed", "err", err, "suppressed_errors", suppressed)
}
