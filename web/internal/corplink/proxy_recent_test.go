package corplink

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// Successful dials must be recorded as recent destinations, most-recent-first
// and deduplicated, so the refresher can probe routes users actually depend on.
func TestRecentDialAddrsRecordsSuccessfulDials(t *testing.T) {
	var calls atomic.Int32
	p := NewMixedProxy(pipeDialer(&calls), nil)

	for _, hp := range [][2]string{{"172.16.4.18", "80"}, {"172.16.3.229", "31509"}, {"172.16.4.18", "80"}} {
		conn, err := p.dialContext(context.Background(), "tcp", hp[0], hp[1])
		if err != nil {
			t.Fatalf("dial %s:%s: %v", hp[0], hp[1], err)
		}
		conn.Close()
	}

	got := p.RecentDialAddrs(4)
	want := []string{"172.16.4.18:80", "172.16.3.229:31509"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

// Failed dials must not be recorded — probing an unreachable destination would
// make every refresh fail.
func TestRecentDialAddrsSkipsFailedDials(t *testing.T) {
	setDialTimeouts(t, 100*time.Millisecond, 30*time.Millisecond)
	var calls atomic.Int32
	p := NewMixedProxy(hangDialer(&calls), nil)

	if _, err := p.dialContext(context.Background(), "tcp", "172.16.9.9", "80"); err == nil {
		t.Fatalf("dial should fail")
	}
	if got := p.RecentDialAddrs(4); len(got) != 0 {
		t.Fatalf("failed dial must not be recorded, got %v", got)
	}
}

// Recorded destinations must age out so a service that went down stops gating
// tunnel refreshes after the TTL.
func TestRecentDialAddrsExpire(t *testing.T) {
	prev := recentDialTTL
	recentDialTTL = 20 * time.Millisecond
	t.Cleanup(func() { recentDialTTL = prev })

	var calls atomic.Int32
	p := NewMixedProxy(pipeDialer(&calls), nil)
	conn, err := p.dialContext(context.Background(), "tcp", "172.16.4.18", "80")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	conn.Close()

	if got := p.RecentDialAddrs(4); len(got) != 1 {
		t.Fatalf("expected 1 recent addr, got %v", got)
	}
	time.Sleep(30 * time.Millisecond)
	if got := p.RecentDialAddrs(4); len(got) != 0 {
		t.Fatalf("expected expired list, got %v", got)
	}
}

// The returned list must respect the max and the internal cap.
func TestRecentDialAddrsCap(t *testing.T) {
	var calls atomic.Int32
	p := NewMixedProxy(pipeDialer(&calls), nil)
	for i := 0; i < recentDialCap+3; i++ {
		conn, err := p.dialContext(context.Background(), "tcp", "10.0.0.1", string(rune('0'+i%10))+"1")
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		conn.Close()
	}
	if got := p.RecentDialAddrs(100); len(got) > recentDialCap {
		t.Fatalf("cap exceeded: %d entries", len(got))
	}
	if got := p.RecentDialAddrs(2); len(got) != 2 {
		t.Fatalf("max not respected, got %v", got)
	}
}
