package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestJSONLogger_FixedShape(t *testing.T) {
	var buf bytes.Buffer
	l := NewJSONLogger(&buf)
	l.now = func() time.Time { return time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC) }

	l.Record(Event{MessageID: "m1", Namespace: "ns", ServiceAccount: "sa", Transport: "rest",
		From: "a@x.com", To: []string{"b@y.com"}, Policy: "p", Decision: DecisionAccept})
	l.Record(Event{MessageID: "m2", Transport: "rest", Decision: DecisionReject, Reason: "invalid_token"})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("want 2 lines, got %d: %q", len(lines), buf.String())
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{
		"stream": "audit", "timestamp": "2026-09-26T12:00:00Z", "message_id": "m1",
		"namespace": "ns", "service_account": "sa", "from": "a@x.com", "policy": "p", "decision": "accept",
	} {
		if got[k] != want {
			t.Errorf("%s: got %v want %v", k, got[k], want)
		}
	}
	// A reject without recipients still carries an (empty) to[] array.
	if !strings.Contains(lines[1], `"to":[]`) || !strings.Contains(lines[1], `"reason":"invalid_token"`) {
		t.Errorf("unexpected reject record: %s", lines[1])
	}
}

func TestFromFlag(t *testing.T) {
	if l, err := FromFlag("none"); err != nil || l != Discard {
		t.Fatalf("none: got %v, %v", l, err)
	}
	if _, err := FromFlag(t.TempDir() + "/audit.log"); err != nil {
		t.Fatalf("file: %v", err)
	}
}
