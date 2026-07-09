package vpnmgr

import (
	"context"
	"fmt"
	"log"
	"time"
)

// probeEachTimeout caps a single destination probe so one black-holed route
// can't consume the whole probe window before the others are tried.
const probeEachTimeout = 2 * time.Second

// tunnelProber is the slice of NetstackDevice the probe logic needs; it opens a
// short TCP connection through the tunnel to addr and reports whether the peer
// answered.
type tunnelProber interface {
	Probe(ctx context.Context, addr string) error
}

// probeTunnel validates a candidate tunnel's data path. The DNS probe is the
// baseline: if the tunnel can't reach its own DNS server the data plane is dead
// and the check fails outright. But a passing DNS probe alone is not proof the
// gateway's internal routes have converged — a fresh CorpLink session sometimes
// reaches 223.5.5.5 while 172.16.x destinations stay black-holed for several
// seconds. So when recent user destinations are known, at least one of them
// must also answer; strict controls whether their collective failure fails the
// check (early refresh attempts) or is tolerated (final attempt, so a genuinely
// down internal service can't wedge tunnel rotation forever).
func probeTunnel(ctx context.Context, dev tunnelProber, dnsAddr string, recentAddrs []string, strict bool) error {
	if err := probeOne(ctx, dev, dnsAddr); err != nil {
		return fmt.Errorf("dns probe %s: %w", dnsAddr, err)
	}
	if len(recentAddrs) == 0 {
		return nil
	}
	var lastErr error
	for _, addr := range recentAddrs {
		if err := probeOne(ctx, dev, addr); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	if strict {
		return fmt.Errorf("no recent destination reachable (tried %d, last: %w)", len(recentAddrs), lastErr)
	}
	log.Printf("tunnel probe: recent destinations unreachable (%v); accepting on DNS probe alone", lastErr)
	return nil
}

func probeOne(ctx context.Context, dev tunnelProber, addr string) error {
	pctx, cancel := context.WithTimeout(ctx, probeEachTimeout)
	defer cancel()
	return dev.Probe(pctx, addr)
}
