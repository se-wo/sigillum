package cliflags

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestParseHelp(t *testing.T) {
	var out bytes.Buffer
	Stdout = &out
	t.Cleanup(func() { Stdout = nil })
	for _, arg := range []string{"-h", "--help", "-help"} {
		out.Reset()
		fs := New("smtp")
		fs.String("listen", ":2587", "listen address")
		if err := Parse(fs, []string{"--mode=smtp", arg}); !errors.Is(err, flag.ErrHelp) {
			t.Fatalf("%s: want flag.ErrHelp, got %v", arg, err)
		}
		for _, want := range []string{"Flags of --mode=smtp:", "-listen", "listen address"} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s: want %q in %q", arg, want, out.String())
			}
		}
	}
}

func TestParseError(t *testing.T) {
	var out bytes.Buffer
	Stdout = &out
	t.Cleanup(func() { Stdout = nil })
	fs := New("api")
	err := Parse(fs, []string{"--mode=api", "--nope"})
	if err == nil || errors.Is(err, flag.ErrHelp) || !strings.Contains(err.Error(), "nope") {
		t.Fatalf("want an error naming the flag, got %v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("usage written on a parse error: %q", out.String())
	}
}
