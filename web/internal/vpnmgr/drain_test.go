package vpnmgr

import (
	"sync/atomic"
	"testing"
	"time"
)

type fakeConnCounter struct{ n atomic.Int64 }

func (f *fakeConnCounter) ActiveConns() int64 { return f.n.Load() }

// A retiring tunnel with no open connections must be released after the
// minimum drain, well before the max cap.
func TestWaitDrainedIdleReleasesAtMin(t *testing.T) {
	f := &fakeConnCounter{}
	start := time.Now()
	waitDrained(f, 30*time.Millisecond, 5*time.Second, 10*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 30*time.Millisecond || elapsed > time.Second {
		t.Fatalf("idle tunnel should release near min drain, took %s", elapsed)
	}
}

// A tunnel with an in-flight transfer must be held until the transfer closes.
func TestWaitDrainedHoldsWhileConnsOpen(t *testing.T) {
	f := &fakeConnCounter{}
	f.n.Store(1)
	released := make(chan time.Duration, 1)
	start := time.Now()
	go func() {
		waitDrained(f, 10*time.Millisecond, 5*time.Second, 10*time.Millisecond)
		released <- time.Since(start)
	}()
	time.Sleep(150 * time.Millisecond)
	select {
	case d := <-released:
		t.Fatalf("released after %s while a conn was still open", d)
	default:
	}
	f.n.Store(0)
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatalf("not released after conns drained")
	}
}

// A wedged connection must not hold the old tunnel forever: the max cap wins.
func TestWaitDrainedMaxCap(t *testing.T) {
	f := &fakeConnCounter{}
	f.n.Store(1)
	start := time.Now()
	waitDrained(f, 10*time.Millisecond, 200*time.Millisecond, 10*time.Millisecond)
	elapsed := time.Since(start)
	if elapsed < 200*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("expected release at max cap, took %s", elapsed)
	}
}
