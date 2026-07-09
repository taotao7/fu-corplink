package corplink

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// dialerFunc adapts a func to the Dialer interface for tests.
type dialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return f(ctx, network, addr)
}

// pipeDialer returns a Dialer that always succeeds with one end of a pipe.
func pipeDialer(calls *atomic.Int32) Dialer {
	return dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		c1, c2 := net.Pipe()
		go func() { _ = c2.Close() }()
		return c1, nil
	})
}

// hangDialer returns a Dialer that blocks until the dial context expires,
// simulating a tunnel whose data path is dead (SYNs go unanswered).
func hangDialer(calls *atomic.Int32) Dialer {
	return dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		<-ctx.Done()
		return nil, ctx.Err()
	})
}

func setDialTimeouts(t *testing.T, overall, attempt time.Duration) {
	t.Helper()
	prevOverall, prevAttempt, prevDelay := proxyDialTimeout, proxyDialAttemptTimeout, dialRetryDelay
	proxyDialTimeout, proxyDialAttemptTimeout = overall, attempt
	dialRetryDelay = 10 * time.Millisecond
	t.Cleanup(func() {
		proxyDialTimeout, proxyDialAttemptTimeout, dialRetryDelay = prevOverall, prevAttempt, prevDelay
	})
}

// A dial that hangs on a dead tunnel must retry and succeed once the refresher
// swaps the proxy onto a live tunnel mid-request (make-before-break).
func TestDialRetriesOnSwappedTunnel(t *testing.T) {
	setDialTimeouts(t, time.Second, 50*time.Millisecond)

	var deadCalls, liveCalls atomic.Int32
	p := NewMixedProxy(hangDialer(&deadCalls), nil)
	live := pipeDialer(&liveCalls)

	// Simulate the background refresher swapping tunnels while the first
	// attempt is still hanging on the dead tunnel.
	go func() {
		time.Sleep(10 * time.Millisecond)
		p.SetTunnel(live, nil)
	}()

	conn, err := p.dialContext(context.Background(), "tcp", "10.0.0.1", "80")
	if err != nil {
		t.Fatalf("dial should succeed on swapped tunnel, got: %v", err)
	}
	conn.Close()
	if deadCalls.Load() < 1 {
		t.Fatalf("expected at least one attempt on the dead tunnel")
	}
	if liveCalls.Load() != 1 {
		t.Fatalf("expected exactly one dial on the live tunnel, got %d", liveCalls.Load())
	}
}

// A timed-out attempt must be retried even when no swap happened yet: the same
// tunnel may recover, and repeated attempts keep the watchdog's dial-demand
// signal alive until the refresher rotates.
func TestDialRetriesTimeoutOnSameTunnel(t *testing.T) {
	setDialTimeouts(t, time.Second, 50*time.Millisecond)

	var calls atomic.Int32
	// hangs on the first call, succeeds on the second — same dialer identity
	flaky := dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		if calls.Add(1) == 1 {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		c1, c2 := net.Pipe()
		go func() { _ = c2.Close() }()
		return c1, nil
	})
	p := NewMixedProxy(flaky, nil)

	conn, err := p.dialContext(context.Background(), "tcp", "10.0.0.1", "80")
	if err != nil {
		t.Fatalf("dial should succeed on retry, got: %v", err)
	}
	conn.Close()
	if got := calls.Load(); got != 2 {
		t.Fatalf("expected 2 attempts, got %d", got)
	}
}

// A quick, definitive error (e.g. connection refused) from a live tunnel that
// was not swapped must fail fast without retrying — it is a real answer.
func TestDialNoRetryOnGenuineError(t *testing.T) {
	setDialTimeouts(t, time.Second, 50*time.Millisecond)

	refused := errors.New("connect tcp 10.0.0.1:80: connection was refused")
	var calls atomic.Int32
	p := NewMixedProxy(dialerFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		calls.Add(1)
		return nil, refused
	}), nil)

	start := time.Now()
	_, err := p.dialContext(context.Background(), "tcp", "10.0.0.1", "80")
	if !errors.Is(err, refused) {
		t.Fatalf("expected the refusal error, got: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 attempt, got %d", got)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("genuine error should fail fast, took %s", elapsed)
	}
}

// Conns dialed through the device must be tracked while open so the refresher
// can drain an old tunnel until its transfers finish instead of cutting them
// off mid-download. Close must decrement exactly once even if called twice.
func TestNetstackActiveConnsRefcount(t *testing.T) {
	dev := &NetstackDevice{}
	c1, c2 := net.Pipe()
	defer c2.Close()
	cc := &countingConn{Conn: c1, dev: dev}
	dev.trackConn()
	if got := dev.ActiveConns(); got != 1 {
		t.Fatalf("expected 1 active conn, got %d", got)
	}
	cc.Close()
	if got := dev.ActiveConns(); got != 0 {
		t.Fatalf("expected 0 after close, got %d", got)
	}
	cc.Close() // double close must not go negative
	if got := dev.ActiveConns(); got != 0 {
		t.Fatalf("expected 0 after double close, got %d", got)
	}
}

// When every attempt times out and no live tunnel ever appears, the dial must
// give up once the overall budget is exhausted.
func TestDialGivesUpAfterOverallBudget(t *testing.T) {
	setDialTimeouts(t, 200*time.Millisecond, 50*time.Millisecond)

	var calls atomic.Int32
	p := NewMixedProxy(hangDialer(&calls), nil)

	start := time.Now()
	_, err := p.dialContext(context.Background(), "tcp", "10.0.0.1", "80")
	if err == nil {
		t.Fatalf("dial should fail when tunnel never recovers")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("should give up near the overall budget, took %s", elapsed)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("expected multiple attempts within the budget, got %d", got)
	}
}
