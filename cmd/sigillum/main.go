package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/se-wo/sigillum/internal/apiserver"
	"github.com/se-wo/sigillum/internal/controller"
	"github.com/se-wo/sigillum/internal/smtpproxy"
	"github.com/se-wo/sigillum/internal/telemetry"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// mode is one way to run the binary. Run parses the mode's flags from
// os.Args and returns flag.ErrHelp after printing them on --help.
type mode struct {
	name    string
	summary string
	what    string // names the component in the exit error
	run     func(*slog.Logger) error
}

var modes = []mode{
	{"api", "REST send API (POST /v1/messages)", "api-server", apiserver.Run},
	{"controller", "reconciles backends, policies and credentials; serves the admission webhooks", "controller", controller.Run},
	{"smtp", "SMTP submission proxy", "smtp proxy", smtpproxy.Run},
}

func main() {
	name, showVersion, help := parseEntrypointArgs(os.Args[1:])

	if showVersion {
		fmt.Printf("sigillum %s (commit %s, built %s)\n", version, commit, date)
		return
	}

	var m *mode
	for i := range modes {
		if modes[i].name == name {
			m = &modes[i]
		}
	}
	if m == nil {
		if !help {
			printUsage(os.Stderr)
			os.Exit(2)
		}
		printUsage(os.Stdout)
		// Each mode prints its flags and returns before starting.
		for _, m := range modes {
			os.Args = []string{os.Args[0], "--help"}
			_ = m.run(slog.Default())
		}
		return
	}
	if help {
		printUsage(os.Stdout)
	}

	logger := telemetry.NewLogger()
	if err := m.run(logger); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		logger.Error(m.what+" exited with error", "err", err)
		os.Exit(1)
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: sigillum --mode=MODE [flags]")
	fmt.Fprintln(w, "       sigillum --version")
	fmt.Fprintln(w, "       sigillum [--mode=MODE] --help")
	fmt.Fprintln(w, "\nModes:")
	for _, m := range modes {
		fmt.Fprintf(w, "  %-11s %s\n", m.name, m.summary)
	}
}

// parseEntrypointArgs pulls --mode, --version and --help out of argv
// without the default flag package's ExitOnError-on-unknown-flag behavior:
// the subcommand flag sets own the rest of the args.
func parseEntrypointArgs(args []string) (mode string, showVersion, help bool) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-version" || a == "--version":
			showVersion = true
		case a == "-h" || a == "-help" || a == "--help":
			help = true
		case a == "-mode" || a == "--mode":
			if i+1 < len(args) {
				mode = args[i+1]
				i++
			}
		case strings.HasPrefix(a, "-mode=") || strings.HasPrefix(a, "--mode="):
			mode = a[strings.Index(a, "=")+1:]
		}
	}
	return mode, showVersion, help
}
