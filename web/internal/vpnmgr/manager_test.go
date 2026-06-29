package vpnmgr

import (
	"testing"
	"time"
)

func TestHandshakeStalenessFromAge(t *testing.T) {
	cases := []struct {
		age  int64
		want float64
	}{
		{-1, 100},  // never handshaked
		{0, 0},     // just handshaked
		{15, 0},    // keepalive boundary
		{45, 0},    // older handshakes are normal on idle tunnels
		{89, 0},    // old 90s threshold should no longer kill idle tunnels
		{90, 0},    // still within WireGuard's normal rekey/retry window
		{120, 0},   // initiator rekey boundary
		{209, 0},   // no gradual degradation before the reconnect threshold
		{210, 100}, // reconnect threshold => stale
		{240, 100}, // stays pinned at 100
	}
	for _, c := range cases {
		got := handshakeStalenessFromAge(c.age)
		if got != c.want {
			t.Errorf("age=%d: want %g, got %g", c.age, c.want, got)
		}
	}
}

func TestReconnectReason(t *testing.T) {
	now := time.Date(2026, 6, 29, 12, 0, 0, 0, time.UTC)
	started := now.Add(-5 * time.Minute)

	// helper to build the common case of a fresh handshake.
	fresh := func(mod func(*reconnectInputs)) reconnectInputs {
		in := reconnectInputs{
			lastHandshake: now.Add(-15 * time.Second).Unix(),
			startedAt:     started,
			now:           now,
		}
		mod(&in)
		return in
	}

	cases := []struct {
		name       string
		in         reconnectInputs
		wantReason bool // expect a non-empty reason (i.e. should reconnect)
	}{
		{
			name: "healthy fresh handshake, idle",
			in:   fresh(func(in *reconnectInputs) {}),
		},
		{
			name: "healthy but rx flat - idle tunnel (no tx demand) must NOT reconnect",
			in: fresh(func(in *reconnectInputs) {
				in.txGrowing = false
				in.rxChangedAt = now.Add(-5 * time.Minute)
			}),
		},
		{
			name:       "fake-alive: tx growing but rx stalled past threshold",
			wantReason: true,
			in: fresh(func(in *reconnectInputs) {
				in.txGrowing = true
				in.rxChangedAt = now.Add(-(rxStallAfter + time.Second))
			}),
		},
		{
			name: "tx growing but rx only just stalled - within grace, keep going",
			in: fresh(func(in *reconnectInputs) {
				in.txGrowing = true
				in.rxChangedAt = now.Add(-(rxStallAfter - 10 * time.Second))
			}),
		},
		{
			name:       "handshake never completed past grace window",
			wantReason: true,
			in: fresh(func(in *reconnectInputs) {
				in.lastHandshake = 0
				in.startedAt = now.Add(-(handshakeStaleAfter + time.Second))
			}),
		},
		{
			name: "handshake never completed but still within grace",
			in: fresh(func(in *reconnectInputs) {
				in.lastHandshake = 0
				in.startedAt = now.Add(-30 * time.Second)
			}),
		},
		{
			name:       "handshake stale past threshold",
			wantReason: true,
			in: fresh(func(in *reconnectInputs) {
				in.lastHandshake = now.Add(-(handshakeStaleAfter + 10 * time.Second)).Unix()
			}),
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := reconnectReason(c.in)
			if c.wantReason && got == "" {
				t.Errorf("expected a reconnect reason, got empty")
			}
			if !c.wantReason && got != "" {
				t.Errorf("expected no reconnect, got reason: %s", got)
			}
		})
	}
}
