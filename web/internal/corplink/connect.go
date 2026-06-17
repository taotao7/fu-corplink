package corplink

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
)

// BuildWgConf assembles a WgConf from a chosen node and its peer-info response,
// applying route-mode selection and carving the peer endpoint (and any
// configured disallowed routes) out of the AllowedIPs to avoid routing loops.
func (c *Client) BuildWgConf(node VPNInfo, info *respWgInfo) (*WgConf, error) {
	ipMask, err := strconv.Atoi(info.IPMask)
	if err != nil {
		return nil, fmt.Errorf("invalid ip mask %q: %w", info.IPMask, err)
	}
	address := fmt.Sprintf("%s/%d", info.IP, ipMask)
	address6 := ""
	if info.IPv6 != "" {
		address6 = fmt.Sprintf("%s/128", info.IPv6)
	}

	var allowed []string
	switch c.conf.RouteModeOrDefault() {
	case RouteModeSplit:
		allowed = append(allowed, info.Setting.VPNRouteSplit...)
		allowed = append(allowed, info.Setting.V6RouteSplit...)
	default: // full
		allowed = append(allowed, info.Setting.VPNRouteFull...)
		allowed = append(allowed, info.Setting.V6RouteFull...)
		if len(allowed) == 0 {
			return nil, fmt.Errorf("route_mode=full but server returned no routes; " +
				"refusing to fall back to 0.0.0.0/0 to avoid a peer-IP routing loop")
		}
	}

	// Auto-carve the peer endpoint IP out of allowed_ips so the outer transport
	// packets to the node aren't captured by the tunnel.
	if peerCIDR, ok := hostCIDR(node.IP); ok {
		var carved []string
		for _, a := range allowed {
			carved = append(carved, subtractCIDR(a, peerCIDR)...)
		}
		allowed = carved
	}
	// validate / normalize remaining entries
	allowed = normalizeCIDRs(allowed)

	protocol := 0 // udp
	switch {
	case eqFold(c.conf.ForceProtocol, "udp"):
		protocol = 0
	case eqFold(c.conf.ForceProtocol, "tcp"):
		protocol = 1
	case node.ProtocolMode == 1:
		protocol = 1
	}

	return &WgConf{
		Address:     address,
		Address6:    address6,
		PeerAddress: fmt.Sprintf("%s:%d", node.IP, node.VPNPort),
		MTU:         info.Setting.VPNMTU,
		PublicKey:   c.conf.PublicKey,
		PrivateKey:  c.conf.PrivateKey,
		PeerKey:     info.PublicKey,
		AllowedIPs:  allowed,
		Routes:      append([]string(nil), allowed...),
		DNS:         info.Setting.VPNDNS,
		Protocol:    protocol,
	}, nil
}

// SelectVPN chooses a node from the list given the configured strategy. When a
// node is pinned (vpn_server_id != 0) it is returned directly if present.
func (c *Client) SelectVPN(ctx context.Context, vpns []VPNInfo) (*VPNInfo, error) {
	if len(vpns) == 0 {
		return nil, fmt.Errorf("no vpn available")
	}
	if c.conf.VPNServerID != 0 {
		for i := range vpns {
			if vpns[i].ID == c.conf.VPNServerID {
				if err := c.activateNode(vpns[i]); err != nil {
					return nil, err
				}
				return &vpns[i], nil
			}
		}
	}
	switch c.conf.VPNSelectStrategy {
	case StrategyLatency:
		var best *VPNInfo
		var min int64 = 1<<63 - 1
		for i := range vpns {
			latency, err := c.pingNodeLocked(ctx, vpns[i].IP, vpns[i].APIPort)
			if err != nil {
				continue
			}
			if latency < min {
				min = latency
				best = &vpns[i]
			}
		}
		if best == nil {
			return nil, fmt.Errorf("no reachable vpn node")
		}
		if err := c.activateNode(*best); err != nil {
			return nil, err
		}
		return best, nil
	default: // default: first reachable
		for i := range vpns {
			if _, err := c.pingNodeLocked(ctx, vpns[i].IP, vpns[i].APIPort); err == nil {
				if err := c.activateNode(vpns[i]); err != nil {
					return nil, err
				}
				return &vpns[i], nil
			}
		}
		return nil, fmt.Errorf("no reachable vpn node")
	}
}

func normalizeCIDRs(in []string) []string {
	out := in[:0]
	seen := map[string]struct{}{}
	for _, s := range in {
		if _, err := netip.ParsePrefix(s); err != nil {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func eqFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
