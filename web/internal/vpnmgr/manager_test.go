package vpnmgr

import "testing"

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
