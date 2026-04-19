package apiserver

import (
	"log/slog"
)

// Run starts the api-server. Implemented in phase 5.
func Run(logger *slog.Logger) error {
	logger.Info("api-server start (phase 1 stub)")
	return run(logger)
}
