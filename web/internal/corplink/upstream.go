package corplink

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// This file implements upstream-proxy routing for fu-corplink's own egress.
//
// Background: when a host-layer TUN VPN (Stash / Clash in TUN mode) is running
// it installs 0.0.0.0/1 + 128.0.0.0/1 routes that capture every packet leaving
// the host — including fu-corplink's WireGuard transport and corplink API
// calls. Those captured packets then depend on the TUN VPN's rule set and
// frequently break the tunnel (or the TUN VPN's own traffic, depending on order
// of operations). Routing fu-corplink's egress through the TUN VPN's own
// HTTP/SOCKS5 mixed-port instead sidesteps the fight: from the TUN VPN's point
// of view fu-corplink is just a normal proxied client, which it routes over its
// real interface per its rules. The two then coexist.
//
// Point UpstreamProxy at the TUN VPN's mixed-port, e.g.
// "http://host.docker.internal:7890" for Stash on a Docker host.

// UpstreamProxyConfig is a parsed, ready-to-use upstream proxy. A nil config
// means "no upstream proxy / dial direct" (the default behavior).
type UpstreamProxyConfig struct {
	raw    string
	scheme string // "http" or "socks5"
	host   string // proxy host:port
	user   string
	pass   string
}

// ParseUpstreamProxy parses a proxy URL. An empty string returns nil. Supported
// schemes: http, https, socks5 (socks5h). A bare "host:port" is treated as http.
func ParseUpstreamProxy(raw string) (*UpstreamProxyConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	// Tolerate bare "host:port" (no scheme). url.Parse misreads that as a scheme,
	// so prepend a scheme when none is present.
	if !containsScheme(raw) {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse upstream proxy %q: %w", raw, err)
	}
	switch u.Scheme {
	case "http", "https":
		u.Scheme = "http"
	case "socks5", "socks5h":
		u.Scheme = "socks5"
	default:
		return nil, fmt.Errorf("unsupported upstream proxy scheme %q (use http/https/socks5)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("upstream proxy %q has no host", raw)
	}
	cfg := &UpstreamProxyConfig{
		raw:    raw,
		scheme: u.Scheme,
		host:   u.Host,
		user:   u.User.Username(),
	}
	cfg.pass, _ = u.User.Password()
	return cfg, nil
}

// containsScheme reports whether s has a scheme prefix like "http://" or
// "socks5://". Used to detect bare host:port inputs that url.Parse would
// misinterpret.
func containsScheme(s string) bool {
	i := strings.Index(s, "://")
	if i <= 0 {
		return false
	}
	scheme := s[:i]
	for _, c := range scheme {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// Enabled reports whether an upstream proxy is configured.
func (p *UpstreamProxyConfig) Enabled() bool { return p != nil && p.host != "" }

// IsSOCKS5 reports whether the proxy speaks SOCKS5 (and can therefore carry UDP
// via UDP ASSOCIATE). HTTP CONNECT proxies can only carry TCP.
func (p *UpstreamProxyConfig) IsSOCKS5() bool { return p.Enabled() && p.scheme == "socks5" }

// IsHTTP reports whether the proxy is an HTTP CONNECT proxy.
func (p *UpstreamProxyConfig) IsHTTP() bool { return p.Enabled() && p.scheme == "http" }

// ProxyURL returns the configured proxy URL for use with http.Transport.Proxy,
// or nil when no proxy is configured.
func (p *UpstreamProxyConfig) ProxyURL() *url.URL {
	if !p.Enabled() {
		return nil
	}
	u := &url.URL{Scheme: p.scheme, Host: p.host}
	if p.user != "" {
		if p.pass != "" {
			u.User = url.UserPassword(p.user, p.pass)
		} else {
			u.User = url.User(p.user)
		}
	}
	return u
}

// String returns the configured proxy URL.
func (p *UpstreamProxyConfig) String() string {
	if !p.Enabled() {
		return ""
	}
	return p.raw
}

// DialContext dials a TCP connection to addr through the upstream proxy. With
// no proxy configured it dials directly. Used for the WireGuard TCP transport
// (force_protocol=tcp).
func (p *UpstreamProxyConfig) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if !p.Enabled() {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}
	if p.IsSOCKS5() {
		return socks5Connect(ctx, p.host, p.user, p.pass, addr)
	}
	return httpConnect(ctx, p.host, p.user, p.pass, addr)
}

// --- HTTP CONNECT -------------------------------------------------------

func httpConnect(ctx context.Context, proxyHost, user, pass, addr string) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("connect to http proxy %s: %w", proxyHost, err)
	}
	applyKeepAlive(conn)
	applyDeadline(conn, ctx, 15*time.Second)

	var req strings.Builder
	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)
	if user != "" {
		req.WriteString("Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass)) + "\r\n")
	}
	req.WriteString("\r\n")

	if _, err := conn.Write([]byte(req.String())); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}
	br := newLineReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if !strings.Contains(statusLine, " 200 ") {
		_ = conn.Close()
		return nil, fmt.Errorf("http proxy refused CONNECT: %s", strings.TrimSpace(statusLine))
	}
	// consume headers up to blank line
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("read CONNECT headers: %w", err)
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	_ = conn.SetDeadline(time.Time{})
	return &leftoverConn{Conn: conn, buf: br.leftover()}, nil
}

// --- SOCKS5 (RFC 1928 / 1929) TCP CONNECT -------------------------------

const socks5Version = 0x05

func socks5Connect(ctx context.Context, proxyHost, user, pass, addr string) (net.Conn, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", proxyHost)
	if err != nil {
		return nil, fmt.Errorf("connect to socks5 proxy %s: %w", proxyHost, err)
	}
	applyKeepAlive(conn)
	applyDeadline(conn, ctx, 15*time.Second)
	if err := socks5Greet(conn, user); err != nil {
		_ = conn.Close()
		return nil, err
	}
	req, err := socks5Request(0x01, addr) // CMD CONNECT
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		_ = conn.Close()
		return nil, err
	}
	rep := make([]byte, 4)
	if _, err := io.ReadFull(conn, rep); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 read reply: %w", err)
	}
	if rep[1] != 0x00 {
		_ = conn.Close()
		return nil, fmt.Errorf("socks5 connect failed (rep 0x%02x)", rep[1])
	}
	if _, _, err := socks5ReadAddr(conn, rep[3]); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func socks5Greet(conn net.Conn, user string) error {
	if user == "" {
		if _, err := conn.Write([]byte{socks5Version, 0x01, 0x00}); err != nil {
			return err
		}
	} else {
		if _, err := conn.Write([]byte{socks5Version, 0x01, 0x02}); err != nil {
			return err
		}
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != socks5Version {
		return fmt.Errorf("socks5: bad version %d", resp[0])
	}
	switch resp[1] {
	case 0x00:
	case 0x02:
		return fmt.Errorf("socks5: server requires auth (not sent)")
	default:
		return fmt.Errorf("socks5: no acceptable auth method (0x%02x)", resp[1])
	}
	return nil
}

func socks5Request(cmd byte, addr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q", portStr)
	}
	buf := []byte{socks5Version, cmd, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			buf = append(buf, 0x01)
			buf = append(buf, v4...)
		} else {
			buf = append(buf, 0x04)
			buf = append(buf, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("socks5 domain too long")
		}
		buf = append(buf, 0x03, byte(len(host)))
		buf = append(buf, host...)
	}
	var pb [2]byte
	binary.BigEndian.PutUint16(pb[:], uint16(port))
	buf = append(buf, pb[:]...)
	return buf, nil
}

func socks5ReadAddr(r io.Reader, atyp byte) (string, uint16, error) {
	var host string
	switch atyp {
	case 0x01:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(r, l); err != nil {
			return "", 0, err
		}
		buf := make([]byte, l[0])
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = string(buf)
	case 0x04:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", 0, err
		}
		host = net.IP(buf).String()
	default:
		return "", 0, fmt.Errorf("socks5: unknown atyp %d", atyp)
	}
	var pb [2]byte
	if _, err := io.ReadFull(r, pb[:]); err != nil {
		return "", 0, err
	}
	return host, binary.BigEndian.Uint16(pb[:]), nil
}

// --- helpers ------------------------------------------------------------

func applyDeadline(conn net.Conn, ctx context.Context, fallback time.Duration) {
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(fallback))
	}
}

// lineReader reads CRLF-terminated lines from a conn while preserving any bytes
// overread past the blank-line terminator (those belong to the tunnel payload).
type lineReader struct {
	conn net.Conn
	buf  []byte
}

func newLineReader(c net.Conn) *lineReader { return &lineReader{conn: c} }

func (l *lineReader) leftover() []byte { return l.buf }

func (l *lineReader) ReadString(delim byte) (string, error) {
	var out strings.Builder
	for len(l.buf) > 0 {
		b := l.buf[0]
		l.buf = l.buf[1:]
		out.WriteByte(b)
		if b == delim {
			return out.String(), nil
		}
	}
	one := make([]byte, 1)
	for {
		n, err := l.conn.Read(one)
		if n > 0 {
			out.WriteByte(one[0])
			if one[0] == delim {
				return out.String(), nil
			}
		}
		if err != nil {
			return out.String(), err
		}
	}
}

// applyKeepAlive enables aggressive TCP keepalive on the real socket underlying
// an upstream-proxy connection. This is essential because the WireGuard TCP
// transport dials through the host TUN VPN (Stash/Clash mixed-port); when that
// proxy silently drops a node (e.g. on a node switch / rule reload) the TCP
// connection is left half-open — no FIN, no RST, no error — yet data stops
// flowing. The default kernel probe schedule (~11min on Linux) declares the
// socket dead far past WireGuard's session lifetime, so the tunnel goes dark
// for minutes and only recovers via the 210s handshake-stale fallback.
//
// Idle 10s + 5s*3 probes reclaims the dead connection in ~25s: the read loop in
// TcpBind then fails, drops the conn, and the next Send redials a fresh one. We
// set it on the raw *net.TCPConn here (before it gets wrapped in a leftoverConn)
// because the bind's own tuner only matches *net.TCPConn and would otherwise
// skip proxied connections.
func applyKeepAlive(conn net.Conn) {
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		return
	}
	_ = tc.SetKeepAliveConfig(net.KeepAliveConfig{
		Enable:   true,
		Idle:     10 * time.Second,
		Interval: 5 * time.Second,
		Count:    3,
	})
}

// leftoverConn forwards any bytes already consumed during the handshake before
// delegating to the underlying conn.
type leftoverConn struct {
	net.Conn
	buf []byte
}

func (c *leftoverConn) Read(p []byte) (int, error) {
	if len(c.buf) > 0 {
		n := copy(p, c.buf)
		c.buf = c.buf[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}
