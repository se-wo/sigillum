package apiserver

import "log/slog"

// run is the implementation hook overridden in phase 5.
var run = func(logger *slog.Logger) error {
	select {}
}
