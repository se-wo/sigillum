// Package cliflags builds the flag set of each mode, so that every mode
// handles --help the same way.
package cliflags

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

// Stdout receives the flag list on --help; a variable for tests.
var Stdout io.Writer = os.Stdout

// New returns the flag set of mode. --mode is consumed by the entrypoint;
// it is defined here too so Parse does not fail on it.
func New(mode string) *flag.FlagSet {
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	_ = fs.String("mode", "", "operating mode: api, controller or smtp")
	// Parse errors are returned and logged by the entrypoint.
	fs.SetOutput(io.Discard)
	return fs
}

// Parse parses args. On -h or --help it writes the flags of the mode to
// Stdout and returns flag.ErrHelp; the caller then exits without starting.
func Parse(fs *flag.FlagSet, args []string) error {
	err := fs.Parse(args)
	if errors.Is(err, flag.ErrHelp) {
		fmt.Fprintf(Stdout, "\nFlags of --mode=%s:\n", fs.Name())
		fs.SetOutput(Stdout)
		fs.PrintDefaults()
		fs.SetOutput(io.Discard)
	}
	return err
}
