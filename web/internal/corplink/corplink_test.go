package corplink

import (
	"encoding/base64"
	"sort"
	"testing"
)

func TestFeilianV1EncryptPassword(t *testing.T) {
	// Deterministic: fixed key/iv derived from constants. The same input must
	// always produce the same ciphertext (stable server-side password hash).
	got, err := feilianV1EncryptPassword("hunter2")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	again, _ := feilianV1EncryptPassword("hunter2")
	if got != again {
		t.Fatalf("non-deterministic output: %q != %q", got, again)
	}
	// AES block size is 16 bytes; "hunter2" (7 bytes) pads to one block => 32 hex chars.
	if len(got) != 32 {
		t.Fatalf("expected 32 hex chars, got %d (%q)", len(got), got)
	}
}

func TestGenerateKeypairRoundTrip(t *testing.T) {
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := base64.StdEncoding.DecodeString(pub); err != nil {
		t.Fatalf("public key not base64: %v", err)
	}
	derived, err := PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if derived != pub {
		t.Fatalf("derived public key %q != generated %q", derived, pub)
	}
}

func TestHOTPKnownVectors(t *testing.T) {
	// RFC 4226 Appendix D test vectors for secret "12345678901234567890".
	key := []byte("12345678901234567890")
	want := []uint32{755224, 287082, 359152, 969429, 338314}
	for i, w := range want {
		if got := hotp(key, uint64(i), 6); got != w {
			t.Errorf("hotp(%d) = %06d, want %06d", i, got, w)
		}
	}
}

func TestSubtractCIDR(t *testing.T) {
	tests := []struct {
		outer, inner string
		want         []string
	}{
		{"10.0.0.0/24", "192.168.0.0/16", []string{"10.0.0.0/24"}}, // disjoint
		{"10.0.0.0/24", "10.0.0.0/24", nil},                        // equal
		{"10.0.5.0/24", "10.0.0.0/16", nil},                        // inner covers outer
	}
	for _, tc := range tests {
		got := subtractCIDR(tc.outer, tc.inner)
		if !equalStrs(got, tc.want) {
			t.Errorf("subtractCIDR(%q,%q) = %v, want %v", tc.outer, tc.inner, got, tc.want)
		}
	}

	// 0.0.0.0/0 minus a /32 should yield 32 complement CIDRs, none covering the host.
	host := subtractCIDR("0.0.0.0/0", "1.2.3.4/32")
	if len(host) != 32 {
		t.Errorf("default-route minus /32: got %d CIDRs, want 32", len(host))
	}
}

func equalStrs(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := append([]string(nil), a...)
	bs := append([]string(nil), b...)
	sort.Strings(as)
	sort.Strings(bs)
	for i := range as {
		if as[i] != bs[i] {
			return false
		}
	}
	return true
}
