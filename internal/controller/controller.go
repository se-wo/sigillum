package controller

import "log/slog"

// Run starts the controller. Implemented in phase 4.
func Run(logger *slog.Logger) error {
	logger.Info("controller start (phase 1 stub)")
	return run(logger)
}

var run = func(logger *slog.Logger) error {
	select {}
}
