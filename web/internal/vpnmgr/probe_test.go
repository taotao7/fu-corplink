package vpnmgr

import (
	"context"
	"errors"
	"testing"
)

// fakeProber probes succeed for addrs in ok, fail otherwise.
type fakeProber struct {
	ok     map[string]bool
	probed []string
}

func (f *fakeProber) Probe(ctx context.Context, addr string) error {
	f.probed = append(f.probed, addr)
	if f.ok[addr] {
		return nil
	}
	return errors.New("probe timeout")
}

func TestProbeTunnelDNSFailureAlwaysFails(t *testing.T) {
	p := &fakeProber{ok: map[string]bool{"172.16.4.18:80": true}}
	err := probeTunnel(context.Background(), p, "223.5.5.5:53", []string{"172.16.4.18:80"}, false)
	if err == nil {
		t.Fatalf("DNS probe failure must fail the tunnel check")
	}
}

func TestProbeTunnelNoRecentAddrsIsDNSOnly(t *testing.T) {
	p := &fakeProber{ok: map[string]bool{"223.5.5.5:53": true}}
	if err := probeTunnel(context.Background(), p, "223.5.5.5:53", nil, true); err != nil {
		t.Fatalf("no recent addrs: DNS-only probe should pass, got %v", err)
	}
}

func TestProbeTunnelRecentAddrReachablePasses(t *testing.T) {
	p := &fakeProber{ok: map[string]bool{
		"223.5.5.5:53":       true,
		"172.16.3.229:31509": true,
	}}
	err := probeTunnel(context.Background(), p, "223.5.5.5:53",
		[]string{"172.16.4.18:80", "172.16.3.229:31509"}, true)
	if err != nil {
		t.Fatalf("one reachable recent addr should suffice, got %v", err)
	}
}

func TestProbeTunnelRecentAddrsUnreachableStrictFails(t *testing.T) {
	p := &fakeProber{ok: map[string]bool{"223.5.5.5:53": true}}
	err := probeTunnel(context.Background(), p, "223.5.5.5:53",
		[]string{"172.16.4.18:80"}, true)
	if err == nil {
		t.Fatalf("strict mode: unreachable recent addrs must fail the check")
	}
}

func TestProbeTunnelRecentAddrsUnreachableRelaxedPasses(t *testing.T) {
	p := &fakeProber{ok: map[string]bool{"223.5.5.5:53": true}}
	err := probeTunnel(context.Background(), p, "223.5.5.5:53",
		[]string{"172.16.4.18:80"}, false)
	if err != nil {
		t.Fatalf("relaxed mode must accept DNS-only success, got %v", err)
	}
}
