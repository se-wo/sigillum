package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	sigv1 "github.com/se-wo/sigillum/api/v1alpha1"
	"github.com/se-wo/sigillum/internal/oauth"
)

// DeviceFlow starts and polls a device code sign-in; *oauth.DeviceCode
// implements it.
type DeviceFlow interface {
	Start(ctx context.Context) (oauth.DeviceAuthorization, error)
	Poll(ctx context.Context, deviceCode string) (oauth.DeviceResult, error)
}

// noteAuthorize turns a new value of the sigillum.dev/authorize annotation
// into a sign-in request. The value a state starts with counts as handled,
// so a controller restart does not ask for another sign-in.
func noteAuthorize(st *brokerState, d DelegatedBackend) {
	if st.authorize == nil {
		v := d.Authorize
		st.authorize = &v
		return
	}
	if *st.authorize != d.Authorize {
		*st.authorize = d.Authorize
		st.wantSignIn, st.device, st.expired = true, nil, ""
	}
}

// signIn advances the device code sign-in (SPEC US-6.3) by one step: start
// it, wait for the person (the condition message holds the URL and the
// code), poll, and store the result. It never blocks for the person; the
// caller is requeued at the poll interval. While a new sign-in is pending,
// a backend that still holds a working token keeps sending with it.
func (b *TokenBroker) signIn(ctx context.Context, d DelegatedBackend, st *brokerState, now time.Time) BrokerResult {
	working := st.stored && st.refreshToken != ""
	if !working {
		backendAuthorized.WithLabelValues(d.Key).Set(0)
	}
	// The refresh token of the sign-in must be stored, or a restart
	// would lose it.
	if ok, msg := b.Guard.OK(); !ok {
		return BrokerResult{Authorized: working, Reason: sigv1.ReasonGuardMissing, Message: msg, RequeueAfter: brokerRetry}
	}
	expired := func(why string) BrokerResult {
		st.device, st.expired = nil, why
		retry := brokerReauthRetry
		if working {
			// Refresh the old sign-in when it is due.
			retry = max(min(st.refreshAt.Sub(now), retry), time.Second)
		}
		return BrokerResult{Authorized: working, Reason: sigv1.ReasonAuthorizationExpired, RequeueAfter: retry,
			Message: expiredMessage(why)}
	}
	if st.expired != "" {
		return expired(st.expired)
	}
	if st.device != nil && !now.Before(st.device.ExpiresAt) {
		return expired("the sign-in code expired before anyone signed in")
	}
	if st.device == nil {
		auth, err := d.Device.Start(ctx)
		if err != nil {
			retry := brokerRetry
			if oauth.IsPermanent(err) {
				retry = brokerReauthRetry
			}
			return BrokerResult{Authorized: working, Reason: sigv1.ReasonAuthorizationRequired, RequeueAfter: retry,
				Message: "could not start a sign-in: " + err.Error()}
		}
		st.device, st.nextPoll = &auth, now.Add(auth.Interval)
		return pending(d, st, working, now)
	}
	if now.Before(st.nextPoll) {
		return pending(d, st, working, now)
	}
	res, err := d.Device.Poll(ctx, st.device.DeviceCode)
	switch {
	case errors.Is(err, oauth.ErrSlowDown):
		st.device.Interval += 5 * time.Second
		st.nextPoll = now.Add(st.device.Interval)
		return pending(d, st, working, now)
	case errors.Is(err, oauth.ErrAuthorizationPending), err != nil && !oauth.IsPermanent(err):
		st.nextPoll = now.Add(st.device.Interval)
		return pending(d, st, working, now)
	case err != nil:
		return expired("the sign-in failed: " + err.Error())
	case d.Account != "" && !strings.EqualFold(res.Account, d.Account):
		// Anyone who can read the backend sees the code; only the
		// mailbox's own sign-in may be used.
		return expired(fmt.Sprintf("signed in as %q, but the backend's mailbox is %q", res.Account, d.Account))
	}
	st.device, st.wantSignIn = nil, false
	st.refreshToken, st.token, st.stored = res.RefreshToken, res.Token, false
	st.refreshAt = now.Add(res.Token.Expiry.Sub(now) / 2)
	return b.store(ctx, d, st, now)
}

func expiredMessage(why string) string {
	return why + "; set a new value on the annotation " + sigv1.AuthorizeAnnotation + " to sign in again"
}

func pending(d DelegatedBackend, st *brokerState, working bool, now time.Time) BrokerResult {
	who := ""
	if d.Account != "" {
		who = " as " + d.Account
	}
	return BrokerResult{Authorized: working, Reason: sigv1.ReasonAuthorizationPending,
		RequeueAfter: max(st.nextPoll.Sub(now), time.Second),
		Message: fmt.Sprintf("to sign in%s, open %s and enter the code %s (valid until %s)", who,
			st.device.VerificationURI, st.device.UserCode, st.device.ExpiresAt.UTC().Format(time.RFC3339))}
}
