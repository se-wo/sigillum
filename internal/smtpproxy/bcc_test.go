package smtpproxy

import "testing"

func TestStripBcc(t *testing.T) {
	cases := map[string]struct{ in, want string }{
		"crlf with folded Bcc": {
			"From: a@x\r\nBcc: hidden@x,\r\n\tother@x\r\nTo: b@x\r\n\r\nBcc: in body stays\r\n",
			"From: a@x\r\nTo: b@x\r\n\r\nBcc: in body stays\r\n",
		},
		"case and resent": {
			"bcc: h@x\r\nResent-BCC: r@x\r\nSubject: s\r\n\r\nbody",
			"Subject: s\r\n\r\nbody",
		},
		"bare lf": {"From: a@x\nBcc: h@x\n\nbody", "From: a@x\n\nbody"},
		"no bcc":  {"From: a@x\r\n\r\nbody", "From: a@x\r\n\r\nbody"},
		"not bcc": {"Bcc-Like: keep\r\n\r\nx", "Bcc-Like: keep\r\n\r\nx"},
	}
	for name, tc := range cases {
		if got := string(stripBcc([]byte(tc.in))); got != tc.want {
			t.Errorf("%s:\n got %q\nwant %q", name, got, tc.want)
		}
	}
}
