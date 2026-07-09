package vpnmgr

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A transient failure (e.g. the control API hiccuping right at reconnect time)
// must be retried instead of dropping the whole VPN to logged_in: the proxy
// listener dying on a single failed HTTP round-trip is a total outage.
func TestRetryReconnectRecoversFromTransientFailure(t *testing.T) {
	calls := 0
	err := retryReconnect(context.Background(), 5, time.Millisecond, func() error {
		calls++
		if calls < 3 {
			return errors.New("transient: EOF")
		}
		return nil
	}, func(error) bool { return false })
	if err != nil {
		t.Fatalf("expected recovery, got: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected 3 attempts, got %d", calls)
	}
}

// When every attempt fails the last error must surface after the full budget.
func TestRetryReconnectExhaustsBudget(t *testing.T) {
	calls := 0
	failure := errors.New("gateway down")
	err := retryReconnect(context.Background(), 4, time.Millisecond, func() error {
		calls++
		return failure
	}, func(error) bool { return false })
	if !errors.Is(err, failure) {
		t.Fatalf("expected the failure error, got: %v", err)
	}
	if calls != 4 {
		t.Fatalf("expected 4 attempts, got %d", calls)
	}
}

// A fatal error (session revoked / logged out) must stop retrying immediately:
// hammering the login-required API cannot succeed and delays surfacing the
// real state to the user.
func TestRetryReconnectStopsOnFatal(t *testing.T) {
	calls := 0
	fatal := errors.New("logged out")
	err := retryReconnect(context.Background(), 5, time.Millisecond, func() error {
		calls++
		return fatal
	}, func(e error) bool { return errors.Is(e, fatal) })
	if !errors.Is(err, fatal) {
		t.Fatalf("expected fatal error, got: %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 attempt, got %d", calls)
	}
}
