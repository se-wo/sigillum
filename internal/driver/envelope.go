package driver

import (
	"bytes"
	"errors"
	"fmt"
	"net/mail"
	"strings"
)

// BindToEnvelope makes the recipients an API backend delivers to equal the
// envelope the policy checked (SPEC US-6.1). Microsoft Graph and the Gmail
// API take them from the To, Cc and Bcc header fields of the MIME message
// and have no envelope, so:
//
//   - every To and Cc address must be an envelope recipient, otherwise the
//     message is refused with ErrRecipientNotInEnvelope (permanent);
//   - envelope recipients in neither field are blind copies and go into a
//     Bcc field, which the provider removes from the delivered copies.
//
// A message that still carries Bcc is refused: the SMTP proxy strips Bcc
// and REST messages are assembled without, so one here would be a bug that
// could deliver to unchecked addresses. It returns the message to send and
// its From address, the mailbox the provider sends as.
func BindToEnvelope(raw []byte, envelope []string) ([]byte, string, error) {
	m, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, "", permanent("cannot parse the message header: %v", err)
	}
	h := m.Header
	if len(h["Bcc"]) > 0 || len(h["Resent-Bcc"]) > 0 {
		return nil, "", permanent("the message still carries a Bcc field")
	}

	from, err := h.AddressList("From")
	if err != nil || len(from) != 1 {
		return nil, "", permanent("the message needs exactly one From address")
	}

	inEnvelope := make(map[string]bool, len(envelope))
	for _, r := range envelope {
		// The gateway validates recipients already; anything that is not a
		// bare addr-spec would also corrupt the Bcc field written below.
		if a, err := mail.ParseAddress(r); err != nil || a.Name != "" || a.Address != r {
			return nil, "", permanent("invalid envelope recipient %q", r)
		}
		inEnvelope[strings.ToLower(r)] = true
	}
	listed := map[string]bool{}
	for _, field := range []string{"To", "Cc"} {
		addrs, err := h.AddressList(field)
		if errors.Is(err, mail.ErrHeaderNotPresent) {
			continue
		}
		if err != nil {
			return nil, "", permanent("cannot parse the %s field: %v", field, err)
		}
		for _, a := range addrs {
			key := strings.ToLower(a.Address)
			if !inEnvelope[key] {
				return nil, "", fmt.Errorf("%w: %w: %s %s", ErrUpstreamPermanent, ErrRecipientNotInEnvelope, field, a.Address)
			}
			listed[key] = true
		}
	}

	var blind []string
	for _, r := range envelope {
		if key := strings.ToLower(r); !listed[key] {
			listed[key] = true
			blind = append(blind, r)
		}
	}
	if len(blind) == 0 {
		return raw, from[0].Address, nil
	}
	// One address per line keeps every line far below 998 characters.
	field := "Bcc: " + strings.Join(blind, ",\r\n ") + "\r\n"
	return append([]byte(field), raw...), from[0].Address, nil
}

func permanent(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUpstreamPermanent, fmt.Sprintf(format, args...))
}
