package vpnmgr

import "testing"

func TestHandshakeStalenessFromAge(t *testing.T) {
	cases := []struct {
		age  int64
		want float64
	}{
		{-1, 100},            // never handshaked
		{0, 0},               // just handshaked
		{15, 0},              // still healthy at the keepalive boundary
		{16, 50.0 / 45.0},    // entering degraded: (16-15)/45*50
		{60, 50},             // end of first ramp
		{61, 50 + 50.0/30.0}, // second ramp begins
		{90, 100},            // reconnect threshold => dead
		{120, 100},           // stays pinned at 100
	}
	for _, c := range cases {
		got := handshakeStalenessFromAge(c.age)
		if got != c.want {
			t.Errorf("age=%d: want %g, got %g", c.age, c.want, got)
		}
	}
}
