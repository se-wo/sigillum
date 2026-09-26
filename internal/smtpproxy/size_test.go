package smtpproxy

import (
	"encoding/base64"
	"net/mail"
	"strings"
	"testing"
)

func size(t *testing.T, raw string) int64 {
	t.Helper()
	msg, err := mail.ReadMessage(strings.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	return contentSize(msg, len(raw))
}

func TestContentSize_SubtractsOnlyEncodingOverhead(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString([]byte("hello world!")) // 16 encoded, 12 decoded
	cases := map[string]struct {
		raw     string
		savings int
	}{
		"plain":            {"Subject: x\r\n\r\nhello", 0},
		"quoted-printable": {"Content-Transfer-Encoding: quoted-printable\r\n\r\nh=C3=A9", len("h=C3=A9") - 3},
		"base64":           {"Content-Transfer-Encoding: base64\r\n\r\n" + b64, 4},
		"nested multipart": {"Content-Type: multipart/mixed; boundary=o\r\n\r\n" +
			"--o\r\nContent-Type: multipart/alternative; boundary=i\r\n\r\n" +
			"--i\r\nContent-Type: text/plain\r\n\r\nab\r\n--i--\r\n" +
			"--o\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64 + "\r\n--o--\r\n", 4},
	}
	for name, tc := range cases {
		if got, want := size(t, tc.raw), int64(len(tc.raw)-tc.savings); got != want {
			t.Errorf("%s: want %d, got %d", name, want, got)
		}
	}
}

func TestContentSize_FramingCannotSmuggleData(t *testing.T) {
	junk := strings.Repeat("x", 100_000)
	for name, raw := range map[string]string{
		"preamble": "Content-Type: multipart/mixed; boundary=b\r\n\r\n" + junk +
			"\r\n--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n",
		"epilogue": "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\nhi\r\n--b--\r\n" + junk,
		"folded part header": "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\nX-Pad: a\r\n " + junk + "\r\n\r\nhi\r\n--b--\r\n",
	} {
		if got := size(t, raw); got < int64(len(junk)) {
			t.Errorf("%s: %d bytes of relayed junk measured as %d", name, len(junk), got)
		}
	}
}

func TestContentSize_MalformedFallsBackToRaw(t *testing.T) {
	for name, raw := range map[string]string{
		"bad base64":       "Content-Transfer-Encoding: base64\r\n\r\n!!!not base64!!!",
		"missing boundary": "Content-Type: multipart/mixed\r\n\r\nbody",
		"unterminated":     "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\npart without end",
	} {
		if got := size(t, raw); got != int64(len(raw)) {
			t.Errorf("%s: malformed MIME must count as raw size %d, got %d", name, len(raw), got)
		}
	}
}
