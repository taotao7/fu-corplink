package corplink

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	dnsCacheTTL      = 5 * time.Minute
	dnsLookupRetries = 4
	proxyDialTimeout = 15 * time.Second
	proxyCopyBufSize = 256 << 10
)

var proxyCopyBufferPool = sync.Pool{
	New: func() any {
		return make([]byte, proxyCopyBufSize)
	},
}

// Dialer dials TCP connections to a host:port, typically through the tunnel.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Resolver resolves hostnames through the tunnel.
type Resolver interface {
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// dialActivityMarker lets a dialer record that a proxied request was attempted,
// even when the subsequent in-tunnel DNS or dial hangs on a dead tunnel. The
// handshake watchdog treats this as outbound demand.
type dialActivityMarker interface{ MarkDialActivity() }

// ProxyAuth optionally gates the proxy with username/password credentials
// (applied to SOCKS5 via RFC 1929 and to HTTP via Proxy-Authorization Basic).
type ProxyAuth struct {
	Username string
	Password string
}

func (a *ProxyAuth) required() bool { return a != nil && a.Username != "" }

// MixedProxy serves HTTP CONNECT, plain HTTP forward, and SOCKS5 on a single
// listener, auto-detecting the protocol from the first byte (like mihomo's
// mixed-port). All upstream connections are dialed via the provided Dialer so
// traffic egresses through the VPN tunnel; DNS is resolved in-tunnel.
type MixedProxy struct {
	// tunMu guards dialer/resolver so a background refresh can swap the proxy
	// onto a freshly-established tunnel (make-before-break) without dropping the
	// listener or connections already bound to the previous tunnel.
	tunMu    sync.RWMutex
	dialer   Dialer
	resolver Resolver

	auth *ProxyAuth

	dnsMu    sync.Mutex
	dnsCache map[string]dnsCacheEntry
	dnsCalls map[string]*dnsLookupCall

	ln     net.Listener
	closed chan struct{}
	once   sync.Once
}

type dnsCacheEntry struct {
	addrs   []string
	expires time.Time
}

type dnsLookupCall struct {
	done  chan struct{}
	addrs []string
	err   error
}

// NewMixedProxy creates a proxy that dials via dialer. auth may be nil.
func NewMixedProxy(dialer Dialer, auth *ProxyAuth) *MixedProxy {
	resolver, _ := dialer.(Resolver)
	return &MixedProxy{
		dialer:   dialer,
		resolver: resolver,
		auth:     auth,
		dnsCache: make(map[string]dnsCacheEntry),
		dnsCalls: make(map[string]*dnsLookupCall),
		closed:   make(chan struct{}),
	}
}

// SetTunnel atomically swaps the dialer/resolver the proxy dials through, so a
// background refresh can move new connections onto a freshly-established tunnel
// (make-before-break) without dropping the listener. Connections already relaying
// keep using whatever tunnel they were dialed on until they close.
func (p *MixedProxy) SetTunnel(dialer Dialer, resolver Resolver) {
	p.tunMu.Lock()
	p.dialer = dialer
	p.resolver = resolver
	p.tunMu.Unlock()
}

// tunnel returns the currently active dialer/resolver under the read lock.
func (p *MixedProxy) tunnel() (Dialer, Resolver) {
	p.tunMu.RLock()
	defer p.tunMu.RUnlock()
	return p.dialer, p.resolver
}

// ListenAndServe binds listenAddr and serves until Close is called.
func (p *MixedProxy) ListenAndServe(listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("listen proxy %s: %w", listenAddr, err)
	}
	p.ln = ln
	go p.acceptLoop()
	return nil
}

// Addr returns the actual listen address (useful when binding :0).
func (p *MixedProxy) Addr() string {
	if p.ln == nil {
		return ""
	}
	return p.ln.Addr().String()
}

// Close stops the proxy.
func (p *MixedProxy) Close() {
	p.once.Do(func() {
		close(p.closed)
		if p.ln != nil {
			_ = p.ln.Close()
		}
	})
}

func (p *MixedProxy) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			select {
			case <-p.closed:
				return
			default:
				continue
			}
		}
		go p.handle(conn)
	}
}

func (p *MixedProxy) handle(client net.Conn) {
	defer client.Close()
	tuneProxyConn(client)
	_ = client.SetDeadline(time.Now().Add(30 * time.Second))

	br := bufio.NewReader(client)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	// SOCKS5 begins with version byte 0x05; anything else is treated as HTTP.
	if first[0] == 0x05 {
		p.handleSocks5(client, br)
		return
	}
	p.handleHTTP(client, br)
}

// --- SOCKS5 (RFC 1928 / 1929) -------------------------------------------

func (p *MixedProxy) handleSocks5(client net.Conn, br *bufio.Reader) {
	// greeting: VER NMETHODS METHODS...
	ver, _ := br.ReadByte()
	if ver != 0x05 {
		return
	}
	nmethods, err := br.ReadByte()
	if err != nil {
		return
	}
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	if p.auth.required() {
		if !containsByte(methods, 0x02) {
			_, _ = client.Write([]byte{0x05, 0xff}) // no acceptable methods
			return
		}
		_, _ = client.Write([]byte{0x05, 0x02}) // username/password
		if !p.socks5Auth(client, br) {
			return
		}
	} else {
		_, _ = client.Write([]byte{0x05, 0x00}) // no auth
	}

	// request: VER CMD RSV ATYP DST.ADDR DST.PORT
	header := make([]byte, 4)
	if _, err := io.ReadFull(br, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return
	}
	if header[1] != 0x01 { // only CONNECT
		socks5Reply(client, 0x07) // command not supported
		return
	}

	host, err := readSocksAddr(br, header[3])
	if err != nil {
		socks5Reply(client, 0x08) // address type not supported
		return
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(br, portBuf[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf[:])

	upstream, err := p.dialContext(context.Background(), "tcp", host, strconv.Itoa(int(port)))
	if err != nil {
		log.Printf("socks5 dial %s:%d failed: %v", host, port, err)
		socks5Reply(client, 0x05) // connection refused
		return
	}
	tuneProxyConn(upstream)
	defer upstream.Close()
	socks5Reply(client, 0x00) // succeeded

	_ = client.SetDeadline(time.Time{})
	relay(client, upstream, br)
}

func (p *MixedProxy) dialContext(ctx context.Context, network, host, port string) (net.Conn, error) {
	// Snapshot the active tunnel once so a mid-dial refresh swap stays consistent
	// for this connection.
	dialer, resolver := p.tunnel()

	// Record outbound demand at the entry point — before in-tunnel DNS and the
	// dial — so a tunnel dead enough to hang even DNS resolution still registers
	// as "in use" for the handshake watchdog. Without this, a request that stalls
	// in lookupHost never reaches DialContext and the watchdog can't see demand.
	if m, ok := dialer.(dialActivityMarker); ok {
		m.MarkDialActivity()
	}

	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, proxyDialTimeout)
		defer cancel()
	}

	if net.ParseIP(host) != nil || resolver == nil {
		return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
	}

	addrs, err := p.lookupHost(ctx, resolver, host)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, addr := range addrs {
		upstream, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr, port))
		if err == nil {
			return upstream, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, &net.DNSError{Err: "no addresses found", Name: host}
}

func (p *MixedProxy) lookupHost(ctx context.Context, resolver Resolver, host string) ([]string, error) {
	now := time.Now()
	p.dnsMu.Lock()
	if entry, ok := p.dnsCache[host]; ok && now.Before(entry.expires) {
		addrs := append([]string(nil), entry.addrs...)
		p.dnsMu.Unlock()
		return addrs, nil
	}
	if call, ok := p.dnsCalls[host]; ok {
		p.dnsMu.Unlock()
		select {
		case <-call.done:
			if call.err != nil {
				return nil, call.err
			}
			return append([]string(nil), call.addrs...), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &dnsLookupCall{done: make(chan struct{})}
	p.dnsCalls[host] = call
	p.dnsMu.Unlock()

	addrs, err := p.resolveHost(ctx, resolver, host)

	p.dnsMu.Lock()
	if err == nil {
		p.dnsCache[host] = dnsCacheEntry{
			addrs:   append([]string(nil), addrs...),
			expires: now.Add(dnsCacheTTL),
		}
	}
	call.addrs = append([]string(nil), addrs...)
	call.err = err
	delete(p.dnsCalls, host)
	close(call.done)
	p.dnsMu.Unlock()

	return addrs, err
}

func (p *MixedProxy) resolveHost(ctx context.Context, resolver Resolver, host string) ([]string, error) {
	var lastErr error
	for attempt := 0; attempt < dnsLookupRetries; attempt++ {
		addrs, err := resolver.LookupHost(ctx, host)
		if err != nil {
			lastErr = err
			continue
		}
		ips := make([]string, 0, len(addrs))
		for _, addr := range addrs {
			if ip := net.ParseIP(addr); ip != nil && !isBenchmarkFakeIP(ip) {
				ips = append(ips, ip.String())
			}
		}
		if len(ips) > 0 {
			return ips, nil
		}
		lastErr = &net.DNSError{Err: "no addresses found", Name: host}
	}
	return nil, lastErr
}

func isBenchmarkFakeIP(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

func tuneProxyConn(conn net.Conn) {
	type noDelayer interface {
		SetNoDelay(bool) error
	}
	if c, ok := conn.(noDelayer); ok {
		_ = c.SetNoDelay(true)
	}
	type readBufferSetter interface {
		SetReadBuffer(int) error
	}
	if c, ok := conn.(readBufferSetter); ok {
		_ = c.SetReadBuffer(proxyCopyBufSize)
	}
	type writeBufferSetter interface {
		SetWriteBuffer(int) error
	}
	if c, ok := conn.(writeBufferSetter); ok {
		_ = c.SetWriteBuffer(proxyCopyBufSize)
	}
}

func (p *MixedProxy) socks5Auth(client net.Conn, br *bufio.Reader) bool {
	// VER ULEN UNAME PLEN PASSWD
	ver, _ := br.ReadByte()
	if ver != 0x01 {
		return false
	}
	ulen, err := br.ReadByte()
	if err != nil {
		return false
	}
	uname := make([]byte, ulen)
	if _, err := io.ReadFull(br, uname); err != nil {
		return false
	}
	plen, err := br.ReadByte()
	if err != nil {
		return false
	}
	passwd := make([]byte, plen)
	if _, err := io.ReadFull(br, passwd); err != nil {
		return false
	}
	ok := string(uname) == p.auth.Username && string(passwd) == p.auth.Password
	if ok {
		_, _ = client.Write([]byte{0x01, 0x00})
	} else {
		_, _ = client.Write([]byte{0x01, 0x01})
	}
	return ok
}

func readSocksAddr(br *bufio.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03: // domain
		l, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		buf := make([]byte, l)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(br, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	default:
		return "", errors.New("unsupported address type")
	}
}

func socks5Reply(w io.Writer, code byte) {
	// VER REP RSV ATYP BND.ADDR(0.0.0.0) BND.PORT(0)
	_, _ = w.Write([]byte{0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

func containsByte(b []byte, target byte) bool {
	for _, x := range b {
		if x == target {
			return true
		}
	}
	return false
}

// relay pipes data bidirectionally between client and upstream. The client's
// buffered reader is used so any bytes already buffered are not lost.
func relay(client net.Conn, upstream net.Conn, clientBuf *bufio.Reader) {
	done := make(chan struct{}, 2)
	go func() {
		copyAndCloseWrite(upstream, clientBuf)
		done <- struct{}{}
	}()
	go func() {
		copyAndCloseWrite(client, upstream)
		done <- struct{}{}
	}()
	<-done
}

func copyAndCloseWrite(dst net.Conn, src io.Reader) {
	buf := proxyCopyBufferPool.Get().([]byte)
	_, _ = io.CopyBuffer(dst, src, buf)
	proxyCopyBufferPool.Put(buf)
	type closeWriter interface {
		CloseWrite() error
	}
	if c, ok := dst.(closeWriter); ok {
		_ = c.CloseWrite()
	}
}
