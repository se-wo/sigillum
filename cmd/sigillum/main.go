package main

import (
	"flag"
	"fmt"
	"os"

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
	mode := flag.String("mode", "", "operating mode: api or controller")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("sigillum %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	logger := telemetry.NewLogger()

	switch *mode {
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
