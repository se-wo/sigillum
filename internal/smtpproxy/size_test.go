package smtpproxy

import (
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

func TestContentSize(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want int64
	}{
		"plain":            {"Subject: x\r\n\r\nhello", 5},
		"quoted-printable": {"Content-Transfer-Encoding: quoted-printable\r\n\r\nh=C3=A9", 3},
		"nested multipart": {"Content-Type: multipart/mixed; boundary=o\r\n\r\n" +
			"--o\r\nContent-Type: multipart/alternative; boundary=i\r\n\r\n" +
			"--i\r\nContent-Type: text/plain\r\n\r\nab\r\n--i\r\nContent-Type: text/html\r\n\r\ncd\r\n--i--\r\n" +
			"--o\r\nContent-Transfer-Encoding: base64\r\n\r\nZWY=\r\n--o--\r\n", 6},
	}
	for name, tc := range cases {
		if got := size(t, tc.raw); got != tc.want {
			t.Errorf("%s: want %d, got %d", name, tc.want, got)
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
