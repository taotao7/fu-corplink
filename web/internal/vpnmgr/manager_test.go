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
			name: "healthy fresh handshake, never used",
			in:   fresh(func(in *reconnectInputs) {}),
		},
		{
			name: "idle tunnel: keepalive keeps wire-tx growing but no real app demand - must NOT reconnect",
			in: fresh(func(in *reconnectInputs) {
				// The old wire-level watchdog saw keepalive as "tx growing" here and
				// tore the tunnel down every 60s. App-level counters show no recent
				// outbound demand, so it must stay up.
				in.appTxAt = now.Add(-5 * time.Minute)
				in.appRxAt = now.Add(-5 * time.Minute)
			}),
		},
		{
			name: "download finished, tunnel idle - stale rx but no recent tx demand must NOT reconnect",
			in: fresh(func(in *reconnectInputs) {
				in.appTxAt = now.Add(-2 * time.Minute)
				in.appRxAt = now.Add(-2 * time.Minute)
				in.dialAt = now.Add(-2 * time.Minute)
			}),
		},
		{
			name:       "fake-alive: recent app tx demand but app rx stalled past threshold",
			wantReason: true,
			in: fresh(func(in *reconnectInputs) {
				in.appTxAt = now.Add(-5 * time.Second)
				in.appRxAt = now.Add(-(rxStallAfter + time.Second))
			}),
		},
		{
			name:       "dead under load: dials being attempted but no inbound ever - reconnect without waiting handshake grace",
			wantReason: true,
			in: fresh(func(in *reconnectInputs) {
				// Tunnel so dead every dial times out: no countingConn bytes at all,
				// only dial attempts. Started long enough ago that inbound silence
				// exceeds the threshold.
				in.startedAt = now.Add(-(rxStallAfter + 30*time.Second))
				in.dialAt = now.Add(-2 * time.Second)
				// appTxAt / appRxAt zero: failing dials never transferred anything.
			}),
		},
		{
			name: "fresh connect, first request in flight - dial demand but within grace, keep going",
			in: fresh(func(in *reconnectInputs) {
				in.startedAt = now.Add(-5 * time.Second)
				in.dialAt = now.Add(-2 * time.Second)
				// no inbound yet, but the tunnel only just came up.
			}),
		},
		{
			name: "recent app tx but app rx only just stalled - within grace, keep going",
			in: fresh(func(in *reconnectInputs) {
				in.appTxAt = now.Add(-5 * time.Second)
				in.appRxAt = now.Add(-(rxStallAfter - 10*time.Second))
			}),
		},
		{
			name:       "long-lived tunnel actively sending but never once received - dead under load",
			wantReason: true,
			in: fresh(func(in *reconnectInputs) {
				// Up for 5 minutes (fresh handshake), still sending, yet not a single
				// inbound app byte ever arrived: fake-alive, must reconnect.
				in.appTxAt = now.Add(-5 * time.Second)
				// appRxAt zero: never received real app bytes.
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
				in.lastHandshake = now.Add(-(handshakeStaleAfter + 10*time.Second)).Unix()
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
