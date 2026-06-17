package corplink

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// NetstackDevice runs WireGuard entirely in userspace via gVisor netstack. It
// creates no kernel TUN device and installs no system routes or DNS, so it
// needs no elevated privileges. It exposes a Dialer/Resolver scoped to the
// tunnel for the proxy to use, and tracks transferred byte counts.
type NetstackDevice struct {
	tun    *netstack.Net
	dev    *device.Device
	dns    []netip.Addr
	has6   bool
	closed atomic.Bool

	rxBytes atomic.Int64
	txBytes atomic.Int64

	mu sync.Mutex
}

// StartNetstack brings up a userspace WireGuard interface from the given config
// and returns a running device. The tunnel addresses, MTU and DNS come from the
// WgConf; peers/keys/routes are programmed via the wg-go UAPI.
func StartNetstack(conf *WgConf) (*NetstackDevice, error) {
	localAddrs, err := parseAddrs(conf)
	if err != nil {
		return nil, err
	}
	dnsAddrs := parseDNS(conf.DNS)

	mtu := int(conf.MTU)
	if mtu == 0 {
		mtu = 1280
	}

	tunDev, tnet, err := netstack.CreateNetTUN(localAddrs, dnsAddrs, mtu)
	if err != nil {
		return nil, fmt.Errorf("create netstack tun: %w", err)
	}

	bind, err := newWireGuardBind(conf.Protocol)
	if err != nil {
		_ = tunDev.Close()
		return nil, err
	}
	dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelError, "wg-corplink "))
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("bring up wireguard: %w", err)
	}

	uapi, err := buildUAPI(conf)
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure wireguard: %w", err)
	}

	return &NetstackDevice{tun: tnet, dev: dev, dns: dnsAddrs, has6: hasIPv6(localAddrs)}, nil
}

func newWireGuardBind(protocol int) (conn.Bind, error) {
	switch protocol {
	case 0:
		return conn.NewDefaultBind(), nil
	case 1:
		return conn.NewTCPBind(), nil
	default:
		return nil, fmt.Errorf("unsupported wireguard protocol %d", protocol)
	}
}

// buildUAPI renders the wg-go IPC configuration string from a WgConf, following
// the cross-platform configuration protocol.
func buildUAPI(conf *WgConf) (string, error) {
	priv, err := b64DecodeToHex(conf.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("decode private key: %w", err)
	}
	peer, err := b64DecodeToHex(conf.PeerKey)
	if err != nil {
		return "", fmt.Errorf("decode peer key: %w", err)
	}
	endpoint, err := resolveEndpoint(conf.PeerAddress)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	b.WriteString("replace_peers=true\n")
	fmt.Fprintf(&b, "public_key=%s\n", peer)
	b.WriteString("replace_allowed_ips=true\n")
	fmt.Fprintf(&b, "endpoint=%s\n", endpoint)
	b.WriteString("persistent_keepalive_interval=10\n")
	for _, ip := range conf.AllowedIPs {
		if strings.Contains(ip, "/") {
			fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
		} else {
			fmt.Fprintf(&b, "allowed_ip=%s/32\n", ip)
		}
	}
	return b.String(), nil
}

// resolveEndpoint resolves a host:port endpoint to an ip:port, since the wg-go
// bind expects a numeric address.
func resolveEndpoint(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid peer address %q: %w", addr, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		return addr, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("resolve peer host %q: %w", host, err)
	}
	return net.JoinHostPort(ips[0].String(), port), nil
}

func parseAddrs(conf *WgConf) ([]netip.Addr, error) {
	var out []netip.Addr
	for _, cidr := range []string{conf.Address, conf.Address6} {
		if cidr == "" {
			continue
		}
		// addresses may carry a prefix; netstack wants the bare address
		host := cidr
		if i := strings.IndexByte(cidr, '/'); i >= 0 {
			host = cidr[:i]
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			return nil, fmt.Errorf("invalid tunnel address %q: %w", cidr, err)
		}
		out = append(out, addr)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no tunnel address configured")
	}
	return out, nil
}

func parseDNS(dns string) []netip.Addr {
	var out []netip.Addr
	for _, s := range strings.FieldsFunc(dns, func(r rune) bool { return r == ',' || r == ' ' }) {
		if addr, err := netip.ParseAddr(strings.TrimSpace(s)); err == nil {
			out = append(out, addr)
		}
	}
	if len(out) == 0 {
		// fall back to a sane public resolver inside the tunnel
		out = append(out, netip.MustParseAddr("8.8.8.8"))
	}
	return out
}

func hasIPv6(addrs []netip.Addr) bool {
	for _, addr := range addrs {
		if addr.Is6() {
			return true
		}
	}
	return false
}

// DialContext dials a TCP connection through the tunnel.
func (n *NetstackDevice) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := n.tun.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: conn, dev: n}, nil
}

// LookupHost resolves a hostname using the tunnel's DNS configuration.
func (n *NetstackDevice) LookupHost(ctx context.Context, host string) ([]string, error) {
	addrs, err := n.tun.LookupContextHost(ctx, host)
	if err != nil || n.has6 {
		return addrs, err
	}
	out := addrs[:0]
	for _, addr := range addrs {
		ip, err := netip.ParseAddr(addr)
		if err != nil || !ip.Is6() {
			out = append(out, addr)
		}
	}
	return out, nil
}

// Transfer returns the cumulative rx/tx byte counts observed on proxied conns.
func (n *NetstackDevice) Transfer() (rx, tx int64) {
	return n.rxBytes.Load(), n.txBytes.Load()
}

// Close tears down the WireGuard device.
func (n *NetstackDevice) Close() {
	if n.closed.Swap(true) {
		return
	}
	if n.dev != nil {
		n.dev.Close()
	}
}

// LastHandshake returns the most recent handshake unix time across peers, or 0.
func (n *NetstackDevice) LastHandshake() int64 {
	out, err := n.dev.IpcGet()
	if err != nil {
		return 0
	}
	var last int64
	for _, line := range strings.Split(out, "\n") {
		if v, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			if ts, err := parseInt64(v); err == nil && ts > last {
				last = ts
			}
		}
	}
	return last
}

func parseInt64(s string) (int64, error) {
	var v int64
	_, err := fmt.Sscan(strings.TrimSpace(s), &v)
	return v, err
}

// countingConn tallies bytes read/written through the tunnel.
type countingConn struct {
	net.Conn
	dev *NetstackDevice
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.dev.rxBytes.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.dev.txBytes.Add(int64(n))
	return n, err
}
