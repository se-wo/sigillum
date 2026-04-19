package main

import "testing"

func TestParseEntrypointArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    []string
		mode    string
		version bool
	}{
		{"double-dash equals", []string{"--mode=controller"}, "controller", false},
		{"single-dash equals", []string{"-mode=api"}, "api", false},
		{"double-dash space", []string{"--mode", "controller"}, "controller", false},
		{"single-dash space", []string{"-mode", "api"}, "api", false},
		{"version short", []string{"-version"}, "", true},
		{"version long", []string{"--version"}, "", true},
		{"ignores unknown flags", []string{"--mode=controller", "--metrics-bind-address=:8080", "--leader-elect=true"}, "controller", false},
		{"empty", nil, "", false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mode, version := parseEntrypointArgs(tc.args)
			if mode != tc.mode || version != tc.version {
				t.Errorf("got (%q, %v) want (%q, %v)", mode, version, tc.mode, tc.version)
			}
		})
	}
}
