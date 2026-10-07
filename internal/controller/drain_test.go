package controller

import (
	"os"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// On a signal, onSignal runs at once (fail readiness) and cancel only
// after the drain delay, so the webhook keeps serving while the pod leaves
// the endpoints (#74).
func TestDrainOnSignalDelaysCancel(t *testing.T) {
	ch := make(chan os.Signal, 3)
	var drained, cancelled atomic.Bool
	done := make(chan struct{})
	go func() {
		drainOnSignal(ch, 120*time.Millisecond, func() { drained.Store(true) }, func() { cancelled.Store(true) })
		close(done)
	}()
	ch <- syscall.SIGTERM
	time.Sleep(40 * time.Millisecond)
	if !drained.Load() {
		t.Fatal("onSignal must run immediately")
	}
	if cancelled.Load() {
		t.Fatal("cancel must wait for the drain delay")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not happen after the delay")
	}
	if !cancelled.Load() {
		t.Fatal("cancel must run after the delay")
	}
}

// A second signal cancels at once, without waiting the full delay.
func TestDrainOnSignalSecondSignalCancelsNow(t *testing.T) {
	ch := make(chan os.Signal, 3)
	done := make(chan struct{})
	go func() {
		drainOnSignal(ch, time.Hour, func() {}, func() {})
		close(done)
	}()
	ch <- syscall.SIGTERM
	ch <- syscall.SIGTERM
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("a second signal must cancel immediately")
	}
}
