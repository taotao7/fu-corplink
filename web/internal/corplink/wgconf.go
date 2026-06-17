package corplink

import (
	"fmt"
	"net/netip"
)

// WgConf is the assembled WireGuard configuration handed to the data plane.
type WgConf struct {
	Address     string   // local tunnel IPv4 with prefix, e.g. 10.1.2.3/24
	Address6    string   // local tunnel IPv6 with prefix, or "" if none
	PeerAddress string   // peer endpoint host:port
	MTU         uint32   //
	PublicKey   string   // our public key (base64)
	PrivateKey  string   // our private key (base64)
	PeerKey     string   // peer public key (base64)
	AllowedIPs  []string // CIDRs routed into the tunnel
	Routes      []string // system routes (same as AllowedIPs unless disabled)
	DNS         string   // in-tunnel DNS server
	Protocol    int      // 0 udp, 1 tcp
}

// subtractCIDR returns a list of CIDR strings covering all addresses in outer
// except those in inner. Mirrors the route-carving used to punch the VPN peer
// endpoint (and any user-disallowed ranges) out of a full-tunnel AllowedIPs so
// the outer transport packets don't get captured by the tunnel.
//
//   - disjoint            -> [outer] unchanged
//   - inner covers outer  -> [] (everything removed)
//   - outer covers inner  -> minimal complement CIDRs (one per prefix bit)
//   - family mismatch / unparseable -> [outer] unchanged (never silently drop)
func subtractCIDR(outer, inner string) []string {
	op, err1 := netip.ParsePrefix(outer)
	ip, err2 := netip.ParsePrefix(inner)
	if err1 != nil || err2 != nil {
		return []string{outer}
	}
	op = op.Masked()
	ip = ip.Masked()
	if op.Addr().Is4() != ip.Addr().Is4() {
		return []string{outer}
	}
	if ip.Bits() <= op.Bits() && ip.Contains(op.Addr()) {
		return nil
	}
	if !op.Contains(ip.Addr()) {
		return []string{outer}
	}
	return carve(op, ip)
}

func carve(outer, inner netip.Prefix) []string {
	if outer.Bits() == inner.Bits() {
		return nil
	}
	newBits := outer.Bits() + 1
	lower := netip.PrefixFrom(outer.Addr(), newBits).Masked()
	upper := netip.PrefixFrom(setBit(outer.Addr(), outer.Bits()), newBits).Masked()

	containing, sibling := upper, lower
	if lower.Contains(inner.Addr()) {
		containing, sibling = lower, upper
	}
	out := []string{sibling.String()}
	return append(out, carve(containing, inner)...)
}

// setBit returns addr with the bit at position `pos` (from the MSB) set to 1.
func setBit(addr netip.Addr, pos int) netip.Addr {
	if addr.Is4() {
		b := addr.As4()
		b[pos/8] |= 1 << (7 - uint(pos%8))
		return netip.AddrFrom4(b)
	}
	b := addr.As16()
	b[pos/8] |= 1 << (7 - uint(pos%8))
	return netip.AddrFrom16(b)
}

// hostCIDR returns ip as a host CIDR (/32 or /128).
func hostCIDR(ip string) (string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", false
	}
	if addr.Is4() {
		return fmt.Sprintf("%s/32", addr), true
	}
	return fmt.Sprintf("%s/128", addr), true
}
