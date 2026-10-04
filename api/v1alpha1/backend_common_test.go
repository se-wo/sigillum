package v1alpha1

import (
	"encoding/json"
	"strings"
	"testing"
)

// An empty allowedSenders denies every sender, an omitted one allows all:
// the difference must survive a JSON round trip through the Go type.
func TestBackendSpec_AllowedSendersRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []string
		want string
	}{
		{"omitted", nil, `"allowedSenders":null`},
		{"empty", []string{}, `"allowedSenders":[]`},
		{"listed", []string{"me@example.com"}, `"allowedSenders":["me@example.com"]`},
	} {
		raw, err := json.Marshal(BackendSpec{Type: BackendSMTP, AllowedSenders: tc.in})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), tc.want) {
			t.Fatalf("%s: %s does not contain %s", tc.name, raw, tc.want)
		}
		var out BackendSpec
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		if (out.AllowedSenders == nil) != (tc.in == nil) || len(out.AllowedSenders) != len(tc.in) {
			t.Fatalf("%s: got %#v, want %#v", tc.name, out.AllowedSenders, tc.in)
		}
		if cp := out.DeepCopy(); (cp.AllowedSenders == nil) != (tc.in == nil) {
			t.Fatalf("%s: DeepCopy lost the difference: %#v", tc.name, cp.AllowedSenders)
		}
	}
}
