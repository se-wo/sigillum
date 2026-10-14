package main

import "testing"

func TestParseEntrypointArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		mode    string
		version bool
		help    bool
	}{
		{"double-dash equals", []string{"--mode=controller"}, "controller", false, false},
		{"single-dash equals", []string{"-mode=api"}, "api", false, false},
		{"double-dash space", []string{"--mode", "controller"}, "controller", false, false},
		{"single-dash space", []string{"-mode", "api"}, "api", false, false},
		{"version short", []string{"-version"}, "", true, false},
		{"version long", []string{"--version"}, "", true, false},
		{"ignores unknown flags", []string{"--mode=controller", "--metrics-bind-address=:8080", "--leader-elect=true"}, "controller", false, false},
		{"empty", nil, "", false, false},
		{"help", []string{"--help"}, "", false, true},
		{"help short", []string{"-h"}, "", false, true},
		{"mode help", []string{"--mode=smtp", "-help"}, "smtp", false, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mode, version, help := parseEntrypointArgs(tc.args)
			if mode != tc.mode || version != tc.version || help != tc.help {
				t.Errorf("got (%q, %v, %v) want (%q, %v, %v)", mode, version, help, tc.mode, tc.version, tc.help)
			}
		})
	}
}
