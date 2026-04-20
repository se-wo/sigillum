package telemetry

import (
	"log/slog"
	"os"
	"strings"
)

// NewLogger returns a JSON slog logger whose level is read from SIGILLUM_LOG_LEVEL.
// Defaults to info. Output is stdout — operators aggregate via stdout/stderr per US-4.2.
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
	h := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}
