package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/se-wo/sigillum/internal/apiserver"
	"github.com/se-wo/sigillum/internal/controller"
	"github.com/se-wo/sigillum/internal/telemetry"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	mode, showVersion := parseEntrypointArgs(os.Args[1:])

	if showVersion {
		fmt.Printf("sigillum %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	logger := telemetry.NewLogger()

	switch mode {
	case "api":
		if err := apiserver.Run(logger); err != nil {
			logger.Error("api-server exited with error", "err", err)
			os.Exit(1)
		}
	case "controller":
		if err := controller.Run(logger); err != nil {
			logger.Error("controller exited with error", "err", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintf(os.Stderr, "must pass --mode=api or --mode=controller\n")
		os.Exit(2)
	}
}

// parseEntrypointArgs pulls --mode and --version out of argv without the
// default flag package's ExitOnError-on-unknown-flag behavior: the subcommand
// flag sets own the rest of the args.
func parseEntrypointArgs(args []string) (mode string, showVersion bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-version" || a == "--version":
			showVersion = true
		case a == "-mode" || a == "--mode":
			if i+1 < len(args) {
				mode = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-mode=") || strings.HasPrefix(a, "--mode="):
			mode = a[strings.Index(a, "=")+1:]
		}
	}
	return mode, showVersion
}
